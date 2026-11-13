"""
almacenamiento.py — Panel de almacenamiento (Neon + Cloudflare R2 + Cloudinary)

Se conecta por API a cada servicio y junta todo en un solo resumen.
Las llaves se pegan desde el propio panel (sección "Conexiones"): se guardan CIFRADAS en la base
de datos y nunca vuelven al navegador. Si prefieres, también siguen funcionando como variables
de entorno (Render); lo guardado en el panel tiene prioridad.

Uso en app.py (antes de `if __name__ == '__main__':`):

    import almacenamiento
    app.register_blueprint(almacenamiento.crear_blueprint(db, registrar))
"""
import base64
import hashlib
import heapq
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib import error as _uerr, parse as _uparse, request as _ureq

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user

CACHE_SEGUNDOS = 300      # el resumen se guarda 5 min (cuida los límites de las APIs)
R2_MAX_PAGINAS = 30       # 30 x 1000 objetos por bucket; si hay más, se marca como estimado
CLD_MAX_PAGINAS = 4       # 4 x 500 archivos por tipo al buscar los más pesados
UMBRAL_ALERTA = 80        # % de uso a partir del cual se avisa


# --- utilidades -------------------------------------------------------------
# Campos que se pueden guardar desde el panel: nombre -> (servicio, es_secreto)
CAMPOS = {
    "NEON_API_KEY": ("neon", True), "NEON_ORG_ID": ("neon", False), "NEON_LIMITE_GB": ("neon", False),
    "R2_ACCOUNT_ID": ("r2", False), "R2_ACCESS_KEY_ID": ("r2", True), "R2_SECRET_ACCESS_KEY": ("r2", True),
    "R2_BUCKETS": ("r2", False), "R2_LIMITE_GB": ("r2", False),
    "CLOUDINARY_CLOUD_NAME": ("cloudinary", False), "CLOUDINARY_API_KEY": ("cloudinary", True),
    "CLOUDINARY_API_SECRET": ("cloudinary", True), "CLOUDINARY_LIMITE_GB": ("cloudinary", False),
}
SERVICIOS = ("neon", "r2", "cloudinary")
_guardadas = {}           # valores guardados desde el panel (ya descifrados, solo en memoria)
_estado = {"tabla": False, "ilegibles": 0}


def _env(nombre, defecto=""):
    return (_guardadas.get(nombre) or os.environ.get(nombre) or defecto).strip()


def _origen(nombre):
    if _guardadas.get(nombre):
        return "panel"
    return "entorno" if (os.environ.get(nombre) or "").strip() else None


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
    carp = {}                                    # carpeta -> [bytes, objetos] (hasta 2 niveles)
    try:
        while True:
            kw = {"Bucket": nombre, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            r = cli.list_objects_v2(**kw)
            for o in r.get("Contents", []):
                total += o["Size"]
                cuenta += 1
                partes = o["Key"].split("/")[:-1]
                for i in range(1, min(len(partes), 2) + 1):
                    c = carp.setdefault("/".join(partes[:i]), [0, 0])
                    c[0] += o["Size"]
                    c[1] += 1
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
    return {"nombre": nombre, "bytes": total, "objetos": cuenta, "estimado": truncado, "grandes": grandes,
            "carpetas": {k: {"bytes": v[0], "objetos": v[1]} for k, v in carp.items()}}


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
    tres = ("CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET")
    if all(_guardadas.get(k) for k in tres):
        return tuple(_guardadas[k].strip() for k in tres)
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
    carp = {}                                    # carpeta -> [bytes, archivos] (hasta 3 niveles)
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
                partes = x["public_id"].split("/")[:-1]
                for i in range(1, min(len(partes), 3) + 1):
                    c = carp.setdefault("/".join(partes[:i]), [0, 0])
                    c[0] += x.get("bytes") or 0
                    c[1] += 1
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
            "grandes": grandes[:15], "muestra": muestra,
            "carpetas": {k: {"bytes": v[0], "archivos": v[1]} for k, v in carp.items()}}


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


# --- vínculo con los proyectos de la app -------------------------------------------
def _publico(d):
    """Copia del resumen sin los totales por carpeta (solo sirven para calcular por proyecto)."""
    o = dict(d)
    if isinstance(o.get("r2"), dict) and o["r2"].get("buckets"):
        o["r2"] = dict(o["r2"], buckets=[{k: v for k, v in b.items() if k != "carpetas"} for b in o["r2"]["buckets"]])
    if isinstance(o.get("cloudinary"), dict):
        o["cloudinary"] = {k: v for k, v in o["cloudinary"].items() if k != "carpetas"}
    return o


def _filas_proyectos(db):
    """Proyectos que tienen algo vinculado (columnas neon_proyecto, r2_buckets, cloudinary_prefijo)."""
    from sqlalchemy import text
    try:
        filas = db.session.execute(text(
            "SELECT id, nombre, neon_proyecto, r2_buckets, cloudinary_prefijo FROM proyecto")).all()
    except Exception:
        db.session.rollback()
        return []
    out = []
    for r in filas:
        f = {"id": r[0], "nombre": r[1], "neon": (r[2] or "").strip(), "r2": (r[3] or "").strip(),
             "cld": (r[4] or "").strip().strip("/")}
        if f["neon"] or f["r2"] or f["cld"]:
            out.append(f)
    return out


def _entradas_r2(texto):
    """'bucket' o 'bucket/carpeta', separados por coma -> [(bucket, carpeta)]."""
    res = []
    for e in (texto or "").split(","):
        e = e.strip().strip("/")
        if e:
            b, _, c = e.partition("/")
            res.append((b.strip(), c.strip("/")))
    return res


def _vinculos(filas):
    """Para la página global: qué proyecto usa cada proyecto de Neon / bucket de R2."""
    v = {"neon": {}, "r2": {}}
    for f in filas:
        if f["neon"]:
            v["neon"].setdefault(f["neon"].lower(), []).append(f["nombre"])
        for b, _c in _entradas_r2(f["r2"]):
            if f["nombre"] not in v["r2"].setdefault(b.lower(), []):
                v["r2"][b.lower()].append(f["nombre"])
    return v


def _busca(dic, clave):
    if clave in dic:
        return dic[clave]
    bajo = clave.lower()
    return next((v for k, v in dic.items() if k.lower() == bajo), None)


def _por_proyecto(d, f):
    """Lo que ocupa UN proyecto, a partir del resumen completo (con carpetas)."""
    res = {"nombre": f["nombre"], "neon": None, "r2": [], "cloudinary": None}
    if f["neon"]:
        n = d.get("neon") or {}
        if n.get("error"):
            res["neon"] = {"estado": "error", "error": n["error"]}
        elif not n.get("configurado"):
            res["neon"] = {"estado": "sin_conectar"}
        else:
            p = next((x for x in n.get("proyectos", []) if str(x.get("nombre", "")).lower() == f["neon"].lower()), None)
            res["neon"] = ({"estado": "ok", "nombre": p["nombre"], "bytes": p["bytes"], "pct": p.get("pct"),
                            "ramas": len(p["ramas"]), "bases": p["bases"], "aviso": p.get("aviso"),
                            "detalle_ramas": [{"nombre": r["nombre"], "bytes": r["bytes"], "principal": r["principal"]}
                                              for r in p["ramas"]]}
                           if p else {"estado": "no_encontrado", "buscado": f["neon"]})
    entradas = _entradas_r2(f["r2"])
    if entradas:
        r = d.get("r2") or {}
        if r.get("error"):
            res["r2"] = [{"estado": "error", "error": r["error"]}]
        elif not r.get("configurado"):
            res["r2"] = [{"estado": "sin_conectar"}]
        else:
            for bucket, carpeta in entradas:
                etiqueta = bucket + ("/" + carpeta if carpeta else "")
                b = next((x for x in r.get("buckets", []) if str(x.get("nombre", "")).lower() == bucket.lower()), None)
                if not b:
                    res["r2"].append({"estado": "no_encontrado", "entrada": etiqueta})
                elif b.get("error"):
                    res["r2"].append({"estado": "error", "entrada": etiqueta, "error": b["error"]})
                else:
                    c = None if not carpeta else _busca(b.get("carpetas") or {}, carpeta)
                    grandes = [g for g in b.get("grandes", []) if not carpeta or g["key"].startswith(carpeta + "/")]
                    res["r2"].append({"estado": "ok", "entrada": etiqueta, "bucket": b["nombre"],
                                      "bytes": b["bytes"] if not carpeta else (c["bytes"] if c else 0),
                                      "objetos": b["objetos"] if not carpeta else (c["objetos"] if c else 0),
                                      "estimado": b["estimado"], "grandes": grandes[:8]})
    if f["cld"]:
        c = d.get("cloudinary") or {}
        if c.get("error"):
            res["cloudinary"] = {"estado": "error", "error": c["error"]}
        elif not c.get("configurado"):
            res["cloudinary"] = {"estado": "sin_conectar"}
        else:
            x = _busca(c.get("carpetas") or {}, f["cld"])
            res["cloudinary"] = {"estado": "ok", "carpeta": f["cld"], "bytes": x["bytes"] if x else 0,
                                 "archivos": x["archivos"] if x else 0, "muestra": c.get("muestra", False),
                                 "vacia": x is None,
                                 "grandes": [{"public_id": g["public_id"], "tipo": g["tipo"], "bytes": g["bytes"]}
                                             for g in c.get("grandes", [])
                                             if g["public_id"].startswith(f["cld"] + "/")][:8]}
    return res


def _armar():
    with ThreadPoolExecutor(max_workers=3) as ex:
        f1, f2, f3 = (ex.submit(_seguro, fn) for fn in (datos_neon, datos_r2, datos_cloudinary))
        d = {"neon": f1.result(), "r2": f2.result(), "cloudinary": f3.result()}
    d["alertas"] = _alertas(d)
    d["generado"] = datetime.utcnow().isoformat() + "Z"
    return d


def _invalidar():
    _cache["t"] = 0.0


def _probar(servicio):
    """Una llamada mínima a la API para confirmar que las llaves funcionan. Devuelve un texto."""
    if servicio == "neon":
        if not _env("NEON_API_KEY"):
            raise RuntimeError("Falta la API key de Neon.")
        ruta = "/projects?limit=100"
        if _env("NEON_ORG_ID"):
            ruta += "&org_id=" + _uparse.quote(_env("NEON_ORG_ID"))
        n = len(_neon(ruta).get("projects", []))
        return f"Conectado. Se ven {n} proyecto(s)."
    if servicio == "r2":
        if not _r2_configurado():
            raise RuntimeError("Faltan datos de R2 (Account ID, Access Key ID y Secret).")
        cli = _r2()
        fijos = [b.strip() for b in _env("R2_BUCKETS").split(",") if b.strip()]
        if fijos:
            cli.list_objects_v2(Bucket=fijos[0], MaxKeys=1)
            return f"Conectado. Se puede leer el bucket {fijos[0]}."
        n = len(cli.list_buckets().get("Buckets", []))
        return f"Conectado. Se ven {n} bucket(s)."
    if servicio == "cloudinary":
        if not _cld_configurado():
            raise RuntimeError("Faltan datos de Cloudinary.")
        uso = _cld("/usage")
        return f"Conectado. Plan: {uso.get('plan') or 'desconocido'}."
    raise RuntimeError("Servicio desconocido.")


# --- Blueprint ----------------------------------------------------------------
_Modelo = None


def crear_blueprint(db, registrar):
    global _Modelo
    bp = Blueprint("almacen", __name__)

    if _Modelo is None:
        class ConexionAlmacen(db.Model):
            """Llaves de las APIs guardadas desde el panel. El valor va CIFRADO (Fernet)."""
            __tablename__ = "conexiones_almacen"
            nombre = db.Column(db.String(60), primary_key=True)
            valor = db.Column(db.Text, nullable=False)
            actualizado = db.Column(db.DateTime, default=datetime.utcnow)
        _Modelo = ConexionAlmacen
    Conexion = _Modelo

    def fernet():
        from cryptography.fernet import Fernet
        clave = hashlib.sha256(("almacenamiento|" + str(current_app.config["SECRET_KEY"])).encode()).digest()
        return Fernet(base64.urlsafe_b64encode(clave))

    def cargar_guardadas():
        """Lee y descifra lo guardado. Se llama en cada petición: así todos los workers ven lo último."""
        if not _estado["tabla"]:
            Conexion.__table__.create(db.engine, checkfirst=True)
            _estado["tabla"] = True
        nuevas, ilegibles = {}, 0
        filas = Conexion.query.all()
        if filas:
            f = fernet()
            for r in filas:
                if r.nombre not in CAMPOS:
                    continue
                try:
                    nuevas[r.nombre] = f.decrypt(r.valor.encode()).decode()
                except Exception:                 # SECRET_KEY cambió o el dato se dañó
                    ilegibles += 1
        _guardadas.clear()
        _guardadas.update(nuevas)
        _estado["ilegibles"] = ilegibles

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

    def datos_cacheados(forzar=False):
        cargar_guardadas()
        with _lock:
            if forzar or not _cache["datos"] or time.time() - _cache["t"] > CACHE_SEGUNDOS:
                datos = _armar()
                try:
                    datos["tablas"] = tablas_locales(db)
                except Exception as e:
                    db.session.rollback()
                    datos["tablas"] = {"error": str(e)[:200]}
                _cache["datos"], _cache["t"] = datos, time.time()
            return _cache["datos"]

    @bp.route("/api/almacenamiento/resumen")
    def resumen():
        if not es_admin():
            return negado()
        d = _publico(datos_cacheados(request.args.get("forzar") == "1"))
        d["vinculos"] = _vinculos(_filas_proyectos(db))
        return jsonify(ok=True, **d)

    @bp.route("/api/almacenamiento/proyectos")
    def por_proyecto():
        """Espacio que ocupa cada proyecto vinculado (Neon, R2, Cloudinary). Usa el mismo caché de 5 min."""
        if not es_admin():
            return negado()
        d = datos_cacheados(request.args.get("forzar") == "1")
        return jsonify(ok=True, generado=d["generado"],
                       proyectos={str(f["id"]): _por_proyecto(d, f) for f in _filas_proyectos(db)})

    @bp.route("/api/almacenamiento/opciones")
    def opciones():
        """Lo que existe en Neon / R2 / Cloudinary, para elegirlo en 'Editar proyecto' en vez de escribirlo.
        ?pid=ID excluye al propio proyecto de la lista de 'ya usado por'."""
        if not es_admin():
            return negado()
        try:
            pid = int(request.args.get("pid", "0"))
        except ValueError:
            pid = 0
        d = datos_cacheados()
        filas = _filas_proyectos(db)

        def usado(tipo, nombre):
            r = []
            for f in filas:
                if f["id"] == pid:
                    continue
                if tipo == "neon" and f["neon"].lower() == nombre.lower():
                    r.append(f["nombre"])
                elif tipo == "r2" and any(b.lower() == nombre.lower() for b, _c in _entradas_r2(f["r2"])):
                    r.append(f["nombre"])
                elif tipo == "cld" and f["cld"].lower() == nombre.lower():
                    r.append(f["nombre"])
            return r

        n, r2, c = d.get("neon") or {}, d.get("r2") or {}, d.get("cloudinary") or {}
        out = {"neon": {"ok": bool(n.get("configurado")) and not n.get("error"), "items": []},
               "r2": {"ok": bool(r2.get("configurado")) and not r2.get("error"), "items": []},
               "cloudinary": {"ok": bool(c.get("configurado")) and not c.get("error"), "items": []}}
        for p in n.get("proyectos", []):
            out["neon"]["items"].append({"nombre": p["nombre"], "usado_por": usado("neon", p["nombre"])})
        for b in r2.get("buckets", []):
            out["r2"]["items"].append({"nombre": b["nombre"], "usado_por": usado("r2", b["nombre"])})
            for carp in sorted(k for k in (b.get("carpetas") or {}) if "/" not in k):
                out["r2"]["items"].append({"nombre": b["nombre"] + "/" + carp, "usado_por": []})
        for carp in sorted(k for k in (c.get("carpetas") or {}) if "/" not in k):
            out["cloudinary"]["items"].append({"nombre": carp, "usado_por": usado("cld", carp)})
        return jsonify(ok=True, **out)

    def _fila_proyecto(pid):
        return next((f for f in _filas_proyectos(db) if f["id"] == pid), None)

    @bp.route("/api/almacenamiento/proyectos/<int:pid>/r2/eliminar", methods=["POST"])
    def r2_eliminar_proyecto(pid):
        """Borra un archivo de R2 SOLO si está dentro del bucket/carpeta vinculado a ese proyecto."""
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        f = _fila_proyecto(pid)
        bucket, key = d.get("bucket"), d.get("key")
        if not f or not isinstance(bucket, str) or not isinstance(key, str) or not key:
            return jsonify(ok=False, error="Datos incompletos."), 400
        if not any(b.lower() == bucket.lower() and (not c or key.startswith(c + "/")) for b, c in _entradas_r2(f["r2"])):
            return jsonify(ok=False, error="Ese archivo no pertenece a este proyecto."), 403
        cargar_guardadas()
        try:
            _r2().delete_object(Bucket=bucket, Key=key)
        except Exception as e:
            return jsonify(ok=False, error=str(e)[:200]), 502
        registrar("eliminar", "R2", pid, f"{f['nombre']}: {bucket}/{key}"[:300])
        db.session.commit()
        _invalidar()
        return jsonify(ok=True)

    @bp.route("/api/almacenamiento/proyectos/<int:pid>/cloudinary/eliminar", methods=["POST"])
    def cld_eliminar_proyecto(pid):
        """Borra un archivo de Cloudinary SOLO si está dentro de la carpeta vinculada a ese proyecto."""
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        f = _fila_proyecto(pid)
        pub, tipo = d.get("public_id"), d.get("resource_type")
        if not f or not f["cld"] or not isinstance(pub, str) or tipo not in ("image", "video", "raw"):
            return jsonify(ok=False, error="Datos incompletos."), 400
        if not pub.startswith(f["cld"] + "/"):
            return jsonify(ok=False, error="Ese archivo no pertenece a este proyecto."), 403
        cargar_guardadas()
        try:
            r = _cld(f"/resources/{tipo}/upload", "DELETE", {"public_ids[]": [pub], "invalidate": "true"})
        except Exception as e:
            return jsonify(ok=False, error=str(e)[:200]), 502
        if (r.get("deleted") or {}).get(pub) != "deleted":
            return jsonify(ok=False, error="Cloudinary no confirmó el borrado."), 502
        registrar("eliminar", "Cloudinary", pid, f"{f['nombre']}: {tipo}/{pub}"[:300])
        db.session.commit()
        _invalidar()
        return jsonify(ok=True)

    @bp.route("/api/almacenamiento/r2/eliminar", methods=["POST"])
    def r2_eliminar():
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        cargar_guardadas()
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
        cargar_guardadas()
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

    # --- Conexiones: guardar llaves desde el panel --------------------------------
    @bp.route("/api/almacenamiento/conexiones")
    def conexiones():
        if not es_admin():
            return negado()
        cargar_guardadas()
        campos = []
        for nombre, (serv, secreto) in CAMPOS.items():
            origen = _origen(nombre)
            campos.append({"nombre": nombre, "servicio": serv, "secreto": secreto, "origen": origen,
                           "valor": None if (secreto or not origen) else _env(nombre)})
        listo = {"neon": bool(_env("NEON_API_KEY")), "r2": _r2_configurado(), "cloudinary": _cld_configurado()}
        return jsonify(ok=True, campos=campos, conectado=listo, ilegibles=_estado["ilegibles"])

    @bp.route("/api/almacenamiento/conexiones/guardar", methods=["POST"])
    def conexiones_guardar():
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        serv, valores = d.get("servicio"), d.get("valores")
        if serv not in SERVICIOS or not isinstance(valores, dict):
            return jsonify(ok=False, error="Datos incompletos."), 400
        cargar_guardadas()
        cambios = []
        for nombre, v in valores.items():
            if nombre not in CAMPOS or CAMPOS[nombre][0] != serv:
                return jsonify(ok=False, error=f"Campo no permitido: {nombre}"), 400
            if v is None:
                continue
            if not isinstance(v, str) or len(v) > 2000:
                return jsonify(ok=False, error=f"Valor no válido en {nombre}."), 400
            v = v.strip()
            if not v and CAMPOS[nombre][1]:
                continue                                   # secreto vacío = conservar el que ya está
            if v and nombre.endswith("_LIMITE_GB"):
                try:
                    if float(v) <= 0:
                        raise ValueError
                except ValueError:
                    return jsonify(ok=False, error="El límite debe ser un número de GB mayor que 0."), 400
            cambios.append((nombre, v))
        if not cambios:
            return jsonify(ok=False, error="No hay nada nuevo que guardar."), 400
        try:
            f = fernet()
            for nombre, v in cambios:
                fila = db.session.get(Conexion, nombre)
                if not v:
                    if fila:
                        db.session.delete(fila)
                    continue
                cifrado = f.encrypt(v.encode()).decode()
                if fila:
                    fila.valor, fila.actualizado = cifrado, datetime.utcnow()
                else:
                    db.session.add(Conexion(nombre=nombre, valor=cifrado))
            registrar("guardar", "Conexión", None, f"{serv}: {', '.join(n for n, _ in cambios)}"[:300])
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error="No se pudo guardar: " + str(e)[:150]), 500
        _invalidar()
        return jsonify(ok=True)

    @bp.route("/api/almacenamiento/conexiones/desconectar", methods=["POST"])
    def conexiones_desconectar():
        d, fallo = cuerpo_confirmado()
        if fallo:
            return fallo
        serv = d.get("servicio")
        if serv not in SERVICIOS:
            return jsonify(ok=False, error="Datos incompletos."), 400
        cargar_guardadas()
        try:
            for nombre, (s_, _) in CAMPOS.items():
                if s_ == serv:
                    fila = db.session.get(Conexion, nombre)
                    if fila:
                        db.session.delete(fila)
            registrar("eliminar", "Conexión", None, serv)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error=str(e)[:150]), 500
        _invalidar()
        return jsonify(ok=True)

    @bp.route("/api/almacenamiento/conexiones/probar", methods=["POST"])
    def conexiones_probar():
        if not es_admin():
            return negado()
        d = request.get_json(silent=True)
        serv = d.get("servicio") if isinstance(d, dict) else None
        if serv not in SERVICIOS:
            return jsonify(ok=False, error="Datos incompletos."), 400
        cargar_guardadas()
        try:
            return jsonify(ok=True, mensaje=_probar(serv))
        except ImportError as e:
            return jsonify(ok=False, error=f"Falta instalar una librería: {e}")
        except Exception as e:
            return jsonify(ok=False, error=str(e)[:250])

    return bp