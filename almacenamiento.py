"""
almacenamiento.py — Panel de almacenamiento (Neon + Cloudflare R2 + Cloudinary)

Se conecta por API a cada servicio y junta todo en un solo resumen.
Las llaves viven SOLO en variables de entorno (Render); nunca llegan al navegador.

Uso en app.py (antes de `if __name__ == '__main__':`):

    import almacenamiento
    app.register_blueprint(almacenamiento.crear_blueprint(db, registrar))
"""
import base64
import heapq
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib import error as _uerr, parse as _uparse, request as _ureq

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user

CACHE_SEGUNDOS = 300      # el resumen se guarda 5 min (cuida los límites de las APIs)
R2_MAX_PAGINAS = 30       # 30 x 1000 objetos por bucket; si hay más, se marca como estimado
CLD_MAX_PAGINAS = 4       # 4 x 500 archivos por tipo al buscar los más pesados
UMBRAL_ALERTA = 80        # % de uso a partir del cual se avisa


# --- utilidades -------------------------------------------------------------
def _env(nombre, defecto=""):
    return (os.environ.get(nombre) or defecto).strip()


def _gb(nombre, defecto=""):
    """Lee una variable en GB y la devuelve en bytes (None si no está o no es número)."""
    try:
        return float(_env(nombre, defecto)) * 1024 ** 3
    except ValueError:
        return None


def _pct(usado, limite):
    return round(usado * 100 / limite, 1) if limite else None


def _http(url, metodo="GET", headers=None, timeout=20):
    req = _ureq.Request(url, method=metodo, headers=headers or {})
    try:
        with _ureq.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except _uerr.HTTPError as e:
        cuerpo = e.read().decode("utf-8", "ignore")[:200]
        raise RuntimeError(f"HTTP {e.code}: {cuerpo}") from None
    except _uerr.URLError as e:
        raise RuntimeError(f"Sin conexión: {e.reason}") from None


# --- NEON -------------------------------------------------------------------
def _neon(ruta):
    return _http("https://console.neon.tech/api/v2" + ruta,
                 headers={"Authorization": "Bearer " + _env("NEON_API_KEY"), "Accept": "application/json"})


def _neon_proyecto(p):
    pid = p["id"]
    info = {"id": pid, "nombre": p.get("name"), "region": p.get("region_id"),
            "bytes": p.get("synthetic_storage_size") or 0, "ramas": [], "bases": []}
    try:
        for r in _neon(f"/projects/{pid}/branches").get("branches", []):
            info["ramas"].append({"id": r["id"], "nombre": r.get("name"),
                                  "principal": bool(r.get("default") or r.get("primary")),
                                  "bytes": r.get("logical_size") or 0, "estado": r.get("current_state")})
        info["ramas"].sort(key=lambda r: r["bytes"], reverse=True)
        prin = next((r for r in info["ramas"] if r["principal"]), info["ramas"][0] if info["ramas"] else None)
        if prin:
            dbs = _neon(f"/projects/{pid}/branches/{prin['id']}/databases").get("databases", [])
            info["bases"] = [d.get("name") for d in dbs]
    except RuntimeError as e:
        info["aviso"] = str(e)
    return info


def datos_neon():
    if not _env("NEON_API_KEY"):
        return {"configurado": False}
    ruta = "/projects?limit=100"
    if _env("NEON_ORG_ID"):
        ruta += "&org_id=" + _uparse.quote(_env("NEON_ORG_ID"))
    proyectos = _neon(ruta).get("projects", [])
    with ThreadPoolExecutor(max_workers=4) as ex:
        filas = list(ex.map(_neon_proyecto, proyectos))
    limite = _gb("NEON_LIMITE_GB")            # límite POR PROYECTO (según tu plan), opcional
    for f in filas:
        f["limite"] = limite
        f["pct"] = _pct(f["bytes"], limite)
    filas.sort(key=lambda f: f["bytes"], reverse=True)
    return {"configurado": True, "proyectos": filas, "total": sum(f["bytes"] for f in filas)}


def tablas_locales(db):
    """Tablas más pesadas de la base a la que está conectada esta app (solo PostgreSQL)."""
    if db.engine.dialect.name != "postgresql":
        return None
    from sqlalchemy import text
    filas = db.session.execute(text(
        "SELECT c.relname, pg_total_relation_size(c.oid) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind = 'r' AND n.nspname = 'public' ORDER BY 2 DESC LIMIT 10")).all()
    total = db.session.execute(text("SELECT pg_database_size(current_database())")).scalar()
    return {"base": int(total or 0), "tablas": [{"nombre": r[0], "bytes": int(r[1])} for r in filas]}


# --- CLOUDFLARE R2 (API compatible con S3) -----------------------------------
def _r2():
    import boto3
    from botocore.config import Config
    return boto3.client(
        "s3", endpoint_url=f"https://{_env('R2_ACCOUNT_ID')}.r2.cloudflarestorage.com",
        aws_access_key_id=_env("R2_ACCESS_KEY_ID"), aws_secret_access_key=_env("R2_SECRET_ACCESS_KEY"),
        region_name="auto",
        config=Config(signature_version="s3v4", retries={"max_attempts": 3}, connect_timeout=8, read_timeout=20))


def _r2_configurado():
    return all(_env(k) for k in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"))


def _buckets_r2(cli):
    fijos = [b.strip() for b in _env("R2_BUCKETS").split(",") if b.strip()]
    return fijos or [b["Name"] for b in cli.list_buckets().get("Buckets", [])]


def _bucket_r2(args):
    cli, nombre = args
    total = cuenta = paginas = 0
    top, truncado, token = [], False, None
    try:
        while True:
            kw = {"Bucket": nombre, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            r = cli.list_objects_v2(**kw)
            for o in r.get("Contents", []):
                total += o["Size"]
                cuenta += 1
                item = (o["Size"], o["Key"], o["LastModified"].isoformat())
                if len(top) < 15:
                    heapq.heappush(top, item)
                elif item > top[0]:
                    heapq.heapreplace(top, item)
            paginas += 1
            if not r.get("IsTruncated"):
                break
            token = r.get("NextContinuationToken")
            if paginas >= R2_MAX_PAGINAS:
                truncado = True
                break
    except Exception as e:                      # un bucket con error no tumba a los demás
        return {"nombre": nombre, "error": str(e)[:200]}
    grandes = [{"key": k, "bytes": s, "fecha": f} for s, k, f in sorted(top, reverse=True)]
    return {"nombre": nombre, "bytes": total, "objetos": cuenta, "estimado": truncado, "grandes": grandes}


def datos_r2():
    if not _r2_configurado():
        return {"configurado": False}
    cli = _r2()
    nombres = _buckets_r2(cli)
    with ThreadPoolExecutor(max_workers=4) as ex:
        buckets = list(ex.map(_bucket_r2, [(cli, n) for n in nombres]))
    total = sum(b.get("bytes", 0) for b in buckets)
    limite = _gb("R2_LIMITE_GB", "10")          # plan gratuito de R2: 10 GB; cámbialo si tu plan es otro
    return {"configurado": True, "buckets": buckets, "total": total, "limite": limite, "pct": _pct(total, limite)}


# --- CLOUDINARY -------------------------------------------------------------
def _cld_cred():
    url = _env("CLOUDINARY_URL")
    if url.startswith("cloudinary://"):
        p = _uparse.urlparse(url)
        return p.netloc.split("@")[-1], _uparse.unquote(p.username or ""), _uparse.unquote(p.password or "")
    return _env("CLOUDINARY_CLOUD_NAME"), _env("CLOUDINARY_API_KEY"), _env("CLOUDINARY_API_SECRET")


def _cld_configurado():
    return all(_cld_cred())


def _cld(ruta, metodo="GET", params=None):
    nube, k, s = _cld_cred()
    cab = {"Authorization": "Basic " + base64.b64encode(f"{k}:{s}".encode()).decode()}
    url = f"https://api.cloudinary.com/v1_1/{nube}{ruta}"
    if params:
        url += "?" + _uparse.urlencode(params, doseq=True)
    return _http(url, metodo, cab)


def datos_cloudinary():
    if not _cld_configurado():
        return {"configurado": False}
    uso = _cld("/usage")
    almacen = uso.get("storage") or {}
    cred = uso.get("credits") or {}
    usados = almacen.get("usage") or 0
    grandes, muestra = [], False
    for tipo in ("image", "video", "raw"):
        cursor = None
        for _ in range(CLD_MAX_PAGINAS):
            params = {"type": "upload", "max_results": 500}
            if cursor:
                params["next_cursor"] = cursor
            try:
                r = _cld(f"/resources/{tipo}", params=params)
            except RuntimeError:
                break
            for x in r.get("resources", []):
                grandes.append({"public_id": x["public_id"], "tipo": tipo, "formato": x.get("format"),
                                "bytes": x.get("bytes") or 0, "url": x.get("secure_url")})
            cursor = r.get("next_cursor")
            if not cursor:
                break
        else:
            muestra = True
        if cursor:
            muestra = True
    grandes.sort(key=lambda x: x["bytes"], reverse=True)
    limite = _gb("CLOUDINARY_LIMITE_GB")        # opcional; si no, se usa el % de créditos que reporta Cloudinary
    pct = _pct(usados, limite) if limite else cred.get("used_percent")
    return {"configurado": True, "plan": uso.get("plan"), "total": usados, "limite": limite, "pct": pct,
            "creditos": {"usado": cred.get("usage"), "limite": cred.get("limit"), "pct": cred.get("used_percent")},
            "recursos": uso.get("resources"), "derivados": uso.get("derived_resources"),
            "ancho_banda": (uso.get("bandwidth") or {}).get("usage"),
            "transformaciones": (uso.get("transformations") or {}).get("usage"),
            "grandes": grandes[:15], "muestra": muestra}


# --- resumen general ----------------------------------------------------------
_cache = {"t": 0.0, "datos": None}
_lock = threading.Lock()


def _seguro(fn):
    try:
        return fn()
    except ImportError as e:
        return {"configurado": True, "error": f"Falta instalar una librería: {e}"}
    except Exception as e:
        return {"configurado": True, "error": str(e)[:300]}


def _alertas(d):
    avisos = []
    for nombre, s in (("Neon", d["neon"]), ("Cloudflare R2", d["r2"]), ("Cloudinary", d["cloudinary"])):
        if s.get("error"):
            avisos.append({"nivel": "error", "texto": f"{nombre}: no se pudo leer ({s['error']})"})
            continue
        pcts = [s.get("pct")] if s.get("pct") is not None else []
        pcts += [p.get("pct") for p in s.get("proyectos", []) if p.get("pct") is not None]
        peor = max(pcts) if pcts else None
        if peor is not None and peor >= UMBRAL_ALERTA:
            avisos.append({"nivel": "alerta", "texto": f"{nombre} está al {peor}% de su límite."})
    return avisos


def _armar():
    with ThreadPoolExecutor(max_workers=3) as ex:
        f1, f2, f3 = (ex.submit(_seguro, fn) for fn in (datos_neon, datos_r2, datos_cloudinary))
        d = {"neon": f1.result(), "r2": f2.result(), "cloudinary": f3.result()}
    d["alertas"] = _alertas(d)
    d["generado"] = datetime.utcnow().isoformat() + "Z"
    return d


def _invalidar():
    _cache["t"] = 0.0


# --- Blueprint ----------------------------------------------------------------
def crear_blueprint(db, registrar):
    bp = Blueprint("almacen", __name__)

    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "") == "admin"

    def negado():
        return jsonify(ok=False, error="Solo administradores."), 403

    def cuerpo_confirmado():
        """Las acciones de borrado exigen JSON (un formulario ajeno no puede enviarlo) y confirmación explícita."""
        if not es_admin():
            return None, negado()
        d = request.get_json(silent=True)
        if not isinstance(d, dict) or d.get("confirmar") is not True:
            return None, (jsonify(ok=False, error="Falta la confirmación."), 400)
        return d, None

    @bp.route("/almacenamiento")
    def pagina():
        if not es_admin():
            return "Solo administradores.", 403
        return render_template("almacenamiento.html")

    @bp.route("/api/almacenamiento/resumen")
    def resumen():
        if not es_admin():
            return negado()
        forzar = request.args.get("forzar") == "1"
        with _lock:
            if forzar or not _cache["datos"] or time.time() - _cache["t"] > CACHE_SEGUNDOS:
                datos = _armar()
                try:
                    datos["tablas"] = tablas_locales(db)
                except Exception as e:
                    db.session.rollback()
                    datos["tablas"] = {"error": str(e)[:200]}
                _cache["datos"], _cache["t"] = datos, time.time()
            return jsonify(ok=True, **_cache["datos"])

    @bp.route("/api/almacenamiento/r2/eliminar", methods=["POST"])
    def r2_eliminar():
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        bucket, key = d.get("bucket"), d.get("key")
        if not isinstance(bucket, str) or not isinstance(key, str) or not key:
            return jsonify(ok=False, error="Datos incompletos."), 400
        try:
            cli = _r2()
            if bucket not in _buckets_r2(cli):          # solo buckets de tu cuenta
                return jsonify(ok=False, error="Bucket no permitido."), 400
            cli.delete_object(Bucket=bucket, Key=key)
        except Exception as e:
            return jsonify(ok=False, error=str(e)[:200]), 502
        registrar("eliminar", "R2", None, f"{bucket}/{key}"[:300])
        db.session.commit()
        _invalidar()
        return jsonify(ok=True)

    @bp.route("/api/almacenamiento/cloudinary/eliminar", methods=["POST"])
    def cld_eliminar():
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        pid, tipo = d.get("public_id"), d.get("resource_type")
        if not isinstance(pid, str) or not pid or tipo not in ("image", "video", "raw"):
            return jsonify(ok=False, error="Datos incompletos."), 400
        try:
            r = _cld(f"/resources/{tipo}/upload", "DELETE", {"public_ids[]": [pid], "invalidate": "true"})
        except Exception as e:
            return jsonify(ok=False, error=str(e)[:200]), 502
        if (r.get("deleted") or {}).get(pid) != "deleted":
            return jsonify(ok=False, error="Cloudinary no confirmó el borrado."), 502
        registrar("eliminar", "Cloudinary", None, f"{tipo}/{pid}"[:300])
        db.session.commit()
        _invalidar()
        return jsonify(ok=True)

    return bp
