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
import math
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
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
    # tarifas del estimador de costos (se editan en la sección "Costos"; vacío = valor de referencia)
    "COSTO_USD_MXN": ("costos", False), "R2_PRECIO_GB": ("costos", False), "R2_GRATIS_GB": ("costos", False),
    "NEON_PRECIO_GB": ("costos", False), "NEON_GRATIS_TOTAL_GB": ("costos", False), "NEON_OTROS_USD": ("costos", False),
}
SERVICIOS = ("neon", "r2", "cloudinary", "costos")
_guardadas = {}           # valores guardados desde el panel (ya descifrados, solo en memoria)
_estado = {"tabla": False, "tabla_h": False, "limpieza": None, "ilegibles": 0}

# --- historial y costos: constantes -------------------------------------------
VENTANA_DIAS = 30         # días que se usan para calcular el ritmo de crecimiento
HISTORIAL_DIAS = 90       # días que se devuelven para dibujar la tendencia
CONSERVAR_DIAS = 400      # lo más viejo se borra
DIAS_AVISO = 30           # alerta si, al ritmo actual, el límite llega en menos de estos días
MAX_DIAS_PROYECCION = 3650
GIB = 1024 ** 3
# Tarifas de referencia (nov 2026). Se pueden cambiar desde el panel sin tocar el código.
TARIFAS_FECHA = "nov 2026"
TARIFAS = {
    "COSTO_USD_MXN": 18.7,          # Banxico (interbancario) 10-nov-2026
    "R2_PRECIO_GB": 0.015,          # R2 Standard: US$0.015 por GB-mes, salida de datos gratis
    "R2_GRATIS_GB": 10.0,           # R2: 10 GB-mes gratis
    "NEON_PRECIO_GB": 0.35,         # Neon Launch/Scale: US$0.35 por GB-mes (sin GB incluidos)
    "NEON_GRATIS_TOTAL_GB": 20.0,   # Neon Free: 1 GB por proyecto (NEON_LIMITE_GB) y 20 GB en total
    "NEON_OTROS_USD": 0.0,          # cómputo u otros cargos mensuales de Neon al pasar a plan de pago
}
# Cloudinary cobra por créditos (1 crédito = 1 GB almacenado = 1 GB de ancho de banda = 1,000 transformaciones)
PLANES_CLD = (("Free", 25, 0.0), ("Plus", 225, 99.0), ("Advanced", 600, 249.0))
FACTORES = (1, 2, 5, 10, 25)


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
    if not limite:
        return None
    p = round(usado * 100 / limite, 1)
    return 0.01 if (usado and p == 0) else p      # algo usado pero minúsculo: se muestra como "<0.1%"


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
            "bytes": p.get("synthetic_storage_size") or 0, "ramas": [], "bases": [],
            "creado": p.get("created_at"), "actualizado": p.get("updated_at"),
            "compute_s": p.get("compute_time_seconds"), "activo_s": p.get("active_time_seconds"),
            "escrito": p.get("written_data_bytes"), "transferencia": p.get("data_transfer_bytes")}
    try:
        for r in _neon(f"/projects/{pid}/branches").get("branches", []):
            info["ramas"].append({"id": r["id"], "nombre": r.get("name"),
                                  "principal": bool(r.get("default") or r.get("primary")),
                                  "bytes": r.get("logical_size") or 0, "estado": r.get("current_state"),
                                  "creada": r.get("created_at")})
        info["ramas"].sort(key=lambda r: r["bytes"], reverse=True)
        # synthetic_storage_size (lo facturable) llega en 0/null en proyectos chicos o recién creados:
        # en ese caso el tamaño real es la suma del tamaño lógico de las ramas.
        if not info["bytes"]:
            info["bytes"] = sum(r["bytes"] for r in info["ramas"])
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
    limite = _gb("NEON_LIMITE_GB", "1")       # límite POR PROYECTO: plan gratuito de Neon = 1 GB; cámbialo en Conexiones
    for f in filas:
        f["limite"] = limite
        f["pct"] = _pct(f["bytes"], limite)
    filas.sort(key=lambda f: f["bytes"], reverse=True)
    return {"configurado": True, "proyectos": filas, "total": sum(f["bytes"] for f in filas), "limite": limite}


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
            "grandes": grandes[:40], "muestra": muestra,
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
        if isinstance(o["cloudinary"].get("grandes"), list):
            o["cloudinary"]["grandes"] = o["cloudinary"]["grandes"][:15]
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


def _restante(usado, limite):
    return max(limite - usado, 0) if limite else None


def _hijos(carpetas, prefijo, cuenta_clave, maximo=25):
    """Subcarpetas (hasta 2 niveles por debajo del prefijo) de un diccionario carpeta -> totales."""
    pre = (prefijo + "/") if prefijo else ""
    filas = []
    for k, v in (carpetas or {}).items():
        if not k.startswith(pre) or k == prefijo:
            continue
        filas.append({"ruta": k, "bytes": v["bytes"], cuenta_clave: v[cuenta_clave]})
    filas.sort(key=lambda x: x["bytes"], reverse=True)
    return filas[:maximo]


def _por_proyecto(d, f):
    """Lo que ocupa UN proyecto, a partir del resumen completo (con carpetas), con límites y lo que sobra."""
    res = {"nombre": f["nombre"], "neon": None, "r2": [], "cloudinary": None, "r2_cuenta": None,
           "cld_cuenta": None, "umbral": UMBRAL_ALERTA}
    if f["neon"]:
        n = d.get("neon") or {}
        if n.get("error"):
            res["neon"] = {"estado": "error", "error": n["error"]}
        elif not n.get("configurado"):
            res["neon"] = {"estado": "sin_conectar"}
        else:
            p = next((x for x in n.get("proyectos", []) if str(x.get("nombre", "")).lower() == f["neon"].lower()), None)
            if p:
                lim = p.get("limite")
                res["neon"] = {"estado": "ok", "nombre": p["nombre"], "bytes": p["bytes"], "pct": p.get("pct"),
                               "limite": lim, "restante": _restante(p["bytes"], lim),
                               "region": p.get("region"), "creado": p.get("creado"), "actualizado": p.get("actualizado"),
                               "compute_s": p.get("compute_s"), "activo_s": p.get("activo_s"),
                               "escrito": p.get("escrito"), "transferencia": p.get("transferencia"),
                               "ramas": len(p["ramas"]), "bases": p["bases"], "aviso": p.get("aviso"),
                               "detalle_ramas": [{"nombre": r["nombre"], "bytes": r["bytes"], "principal": r["principal"],
                                                  "estado": r.get("estado"), "creada": r.get("creada"),
                                                  "pct": _pct(r["bytes"], lim)} for r in p["ramas"]]}
            else:
                res["neon"] = {"estado": "no_encontrado", "buscado": f["neon"]}
    entradas = _entradas_r2(f["r2"])
    if entradas:
        r = d.get("r2") or {}
        if r.get("error"):
            res["r2"] = [{"estado": "error", "error": r["error"]}]
        elif not r.get("configurado"):
            res["r2"] = [{"estado": "sin_conectar"}]
        else:
            lim = r.get("limite")
            res["r2_cuenta"] = {"total": r.get("total", 0), "limite": lim, "pct": r.get("pct"),
                                "restante": _restante(r.get("total", 0), lim), "buckets": len(r.get("buckets", []))}
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
                    usado = b["bytes"] if not carpeta else (c["bytes"] if c else 0)
                    res["r2"].append({"estado": "ok", "entrada": etiqueta, "bucket": b["nombre"], "bytes": usado,
                                      "objetos": b["objetos"] if not carpeta else (c["objetos"] if c else 0),
                                      "pct_cuenta": _pct(usado, lim), "bytes_bucket": b["bytes"],
                                      "estimado": b["estimado"], "grandes": grandes[:15],
                                      "carpetas": _hijos(b.get("carpetas"), carpeta, "objetos")})
    if f["cld"]:
        c = d.get("cloudinary") or {}
        if c.get("error"):
            res["cloudinary"] = {"estado": "error", "error": c["error"]}
        elif not c.get("configurado"):
            res["cloudinary"] = {"estado": "sin_conectar"}
        else:
            lim = c.get("limite")
            cred = c.get("creditos") or {}
            res["cld_cuenta"] = {"plan": c.get("plan"), "total": c.get("total", 0), "limite": lim, "pct": c.get("pct"),
                                 "restante": _restante(c.get("total", 0), lim), "creditos": cred,
                                 "recursos": c.get("recursos"), "derivados": c.get("derivados"),
                                 "ancho_banda": c.get("ancho_banda"), "transformaciones": c.get("transformaciones")}
            x = _busca(c.get("carpetas") or {}, f["cld"])
            usado = x["bytes"] if x else 0
            res["cloudinary"] = {"estado": "ok", "carpeta": f["cld"], "bytes": usado,
                                 "archivos": x["archivos"] if x else 0, "muestra": c.get("muestra", False),
                                 "vacia": x is None, "pct_cuenta": _pct(usado, lim),
                                 "carpetas": _hijos(c.get("carpetas"), f["cld"], "archivos"),
                                 "grandes": [{"public_id": g["public_id"], "tipo": g["tipo"], "bytes": g["bytes"],
                                              "formato": g.get("formato"), "url": g.get("url")}
                                             for g in c.get("grandes", [])
                                             if g["public_id"].startswith(f["cld"] + "/")][:15]}
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


# --- historial diario y proyección ---------------------------------------------
def _hoy():
    """Fecha en México (UTC-6, sin horario de verano): el 'día' del historial coincide con el del usuario."""
    return (datetime.utcnow() - timedelta(hours=6)).date()


def _etiqueta(clave):
    if clave == "r2":
        return "Cloudflare R2"
    if clave == "cloudinary":
        return "Cloudinary · almacenamiento"
    if clave == "cloudinary:creditos":
        return "Cloudinary · créditos"
    if clave.startswith("neon:"):
        return "Neon · " + clave[5:]
    return clave


def _lecturas(d):
    """Lo que se guarda cada día: [(clave, valor, limite, unidad)]. Solo de servicios que respondieron bien."""
    out = []
    n = d.get("neon") or {}
    if n.get("configurado") and not n.get("error"):
        for p in n.get("proyectos", []):
            out.append(("neon:" + str(p["nombre"]), p["bytes"], p.get("limite"), "bytes"))
    r = d.get("r2") or {}
    # si algún bucket falló, el total estaría incompleto y parecería que el espacio bajó: no se guarda
    if r.get("configurado") and not r.get("error") and not any(b.get("error") for b in r.get("buckets", [])):
        out.append(("r2", r.get("total", 0), r.get("limite"), "bytes"))
    c = d.get("cloudinary") or {}
    if c.get("configurado") and not c.get("error"):
        out.append(("cloudinary", c.get("total") or 0, c.get("limite"), "bytes"))
        cred = c.get("creditos") or {}
        if cred.get("usado") is not None:
            out.append(("cloudinary:creditos", float(cred["usado"]), cred.get("limite"), "creditos"))
    return out


def proyectar(serie, limite, hoy):
    """serie = [(fecha, valor)] ordenada. El ritmo es una recta de mínimos cuadrados sobre los últimos
    VENTANA_DIAS días (más estable que comparar solo dos puntos). Estados: sin_datos, pocos_datos, sin_limite,
    superado, estable, crece, lejano."""
    r = {"actual": None, "por_dia": None, "dias": None, "fecha": None, "estado": "sin_datos",
         "dias_datos": 0, "cambio": None}
    if not serie:
        return r
    actual = serie[-1][1]
    r["actual"] = actual
    pts = [(f, v) for f, v in serie if (hoy - f).days <= VENTANA_DIAS]
    if pts:
        r["dias_datos"] = (pts[-1][0] - pts[0][0]).days + 1
    pendiente = None
    if len(pts) >= 2 and pts[-1][0] > pts[0][0]:
        xs = [(f - pts[0][0]).days for f, _ in pts]
        ys = [v for _, v in pts]
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        var = sum((x - mx) ** 2 for x in xs)
        pendiente = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var
        r["por_dia"] = pendiente
        r["cambio"] = ys[-1] - ys[0]
    if not limite or limite <= 0:
        r["estado"] = "sin_limite" if pendiente is not None else "pocos_datos"
    elif actual >= limite:
        r["estado"], r["dias"] = "superado", 0
    elif pendiente is None:
        r["estado"] = "pocos_datos"
    elif pendiente <= 0:
        r["estado"] = "estable"
    else:
        dias = (limite - actual) / pendiente
        if dias > MAX_DIAS_PROYECCION:
            r["estado"] = "lejano"
        else:
            r["estado"], r["dias"] = "crece", dias
            r["fecha"] = (hoy + timedelta(days=dias)).isoformat()
    return r


def _ordenar_items(items):
    items.sort(key=lambda i: (i["dias"] is None, i["dias"] if i["dias"] is not None else 0, i["nombre"]))
    return items


def _alertas_historial(items):
    return [{"nivel": "alerta",
             "texto": f"{i['nombre']}: al ritmo actual llega a su límite en ~{max(1, round(i['dias']))} días ({i['fecha']})."}
            for i in items if i["estado"] == "crece" and i["dias"] is not None and i["dias"] <= DIAS_AVISO]


# --- costos --------------------------------------------------------------------
def _tarifa(nombre):
    try:
        v = float(_env(nombre, str(TARIFAS[nombre])))
    except ValueError:
        return TARIFAS[nombre]
    if not math.isfinite(v) or v < 0 or (nombre == "COSTO_USD_MXN" and v == 0):
        return TARIFAS[nombre]
    return v


def _tarifas():
    return {k: _tarifa(k) for k in TARIFAS}


def _gratis_neon_proyecto():
    """GB gratis por proyecto de Neon: es el mismo 'límite por proyecto' de la tarjeta de conexión."""
    b = _gb("NEON_LIMITE_GB", "1")
    return (b if b and math.isfinite(b) else GIB) / GIB


def costo_neon(gbs, t, gratis_proyecto):
    """Neon: gratis mientras ningún proyecto pase de su GB y el total de la cuenta de 20 GB.
    Al pasar a plan de pago, TODO el almacenamiento se cobra (el plan de pago no incluye GB)."""
    total = sum(gbs)
    paga = any(g > gratis_proyecto for g in gbs) or total > t["NEON_GRATIS_TOTAL_GB"]
    usd = total * t["NEON_PRECIO_GB"] + t["NEON_OTROS_USD"] if paga else 0.0
    return {"gb": total, "paga": paga, "usd": usd}


def costo_r2(gb, t):
    extra = max(gb - t["R2_GRATIS_GB"], 0.0)
    return {"gb": gb, "paga": extra > 0, "extra_gb": extra, "usd": extra * t["R2_PRECIO_GB"]}


def costo_cld(creditos):
    for nombre, cred, usd in PLANES_CLD:
        if creditos <= cred:
            return {"creditos": creditos, "plan": nombre, "paga": usd > 0, "usd": usd, "cotizar": False}
    return {"creditos": creditos, "plan": "Enterprise", "paga": True, "usd": None, "cotizar": True}


def _base_costos(d):
    """Uso actual en las unidades en que cobra cada servicio. None = servicio no disponible."""
    b = {"neon": None, "r2": None, "cloudinary": None}
    n = d.get("neon") or {}
    if n.get("configurado") and not n.get("error"):
        b["neon"] = [(str(p["nombre"]), p["bytes"] / GIB) for p in n.get("proyectos", [])]
    r = d.get("r2") or {}
    if r.get("configurado") and not r.get("error"):
        b["r2"] = (r.get("total") or 0) / GIB
    c = d.get("cloudinary") or {}
    if c.get("configurado") and not c.get("error"):
        usado = (c.get("creditos") or {}).get("usado")
        # los créditos incluyen almacenamiento + ancho de banda + transformaciones; si no vienen, solo el almacenamiento
        b["cloudinary"] = float(usado) if usado is not None else (c.get("total") or 0) / GIB
    return b


def _escenario(etiqueta, neon_gbs, r2_gb, cld_cred, t, gp, **extra):
    e = {"etiqueta": etiqueta, "neon": None, "r2": None, "cloudinary": None, "total_usd": 0.0, "cotizar": False}
    e.update(extra)
    if neon_gbs is not None:
        e["neon"] = costo_neon(neon_gbs, t, gp)
    if r2_gb is not None:
        e["r2"] = costo_r2(r2_gb, t)
    if cld_cred is not None:
        e["cloudinary"] = costo_cld(cld_cred)
    for k in ("neon", "r2", "cloudinary"):
        if e[k]:
            if e[k].get("cotizar"):
                e["cotizar"] = True
            e["total_usd"] += e[k]["usd"] or 0.0
    e["total_mxn"] = e["total_usd"] * t["COSTO_USD_MXN"]
    return e


def calcular_costos(base, series, t, gp, hoy, factor=None):
    """Escenarios de costo mensual: (a) multiplicando el uso actual y (b) a 1/3/6/12 meses al ritmo real
    medido en el historial. También cuándo empiezas a pagar en cada servicio."""
    nb, rb, cb = base["neon"], base["r2"], base["cloudinary"]
    factores = list(FACTORES)
    if factor and factor not in factores:
        factores = sorted(factores + [factor])
    escenarios = []
    for f in factores:
        et = "Hoy" if f == 1 else (f"×{f:g} el uso actual" + (" (tu escenario)" if f == factor else ""))
        escenarios.append(_escenario(
            et, None if nb is None else [g * f for _, g in nb], None if rb is None else rb * f,
            None if cb is None else cb * f, t, gp, factor=f, propio=bool(factor and f == factor)))

    def ritmo(clave):
        s = series.get(clave)
        return proyectar(s["serie"], None, hoy)["por_dia"] if s else None

    r_neon = {n: ritmo("neon:" + n) for n, _ in (nb or [])}
    r_r2, r_cld = ritmo("r2"), ritmo("cloudinary:creditos")
    sin_ritmo = []
    if nb is not None and any(v is None for v in r_neon.values()):
        sin_ritmo.append("Neon")
    if rb is not None and r_r2 is None:
        sin_ritmo.append("Cloudflare R2")
    if cb is not None and r_cld is None:
        sin_ritmo.append("Cloudinary")
    hay_ritmo = any(v is not None for v in list(r_neon.values()) + [r_r2, r_cld])
    tiempo = None
    if hay_ritmo:
        tiempo = []
        for m in (1, 3, 6, 12):
            dias = 30 * m
            tiempo.append(_escenario(
                f"En {m} mes{'es' if m > 1 else ''}", None if nb is None else [g + max(r_neon[n] or 0, 0) * dias / GIB for n, g in nb],
                None if rb is None else rb + max(r_r2 or 0, 0) * dias / GIB,
                None if cb is None else cb + max(r_cld or 0, 0) * dias, t, gp, meses=m))

    def dias_a(clave, gratis):
        s = series.get(clave)
        return proyectar(s["serie"], gratis, hoy) if s else None

    umbrales = {}
    if nb:
        fs = [gp / g for _, g in nb if g > 0] + ([t["NEON_GRATIS_TOTAL_GB"] / sum(g for _, g in nb)] if sum(g for _, g in nb) > 0 else [])
        ps = [dias_a("neon:" + n, gp * GIB) for n, _ in nb]
        umbrales["neon"] = _umbral(min(fs) if fs else None, [p for p in ps if p])
    if rb is not None:
        p = dias_a("r2", t["R2_GRATIS_GB"] * GIB)
        umbrales["r2"] = _umbral(t["R2_GRATIS_GB"] / rb if rb > 0 else None, [p] if p else [])
    if cb is not None:
        p = dias_a("cloudinary:creditos", PLANES_CLD[0][1])
        umbrales["cloudinary"] = _umbral(PLANES_CLD[0][1] / cb if cb > 0 else None, [p] if p else [])
    return {"escenarios": escenarios, "tiempo": tiempo, "sin_ritmo": sin_ritmo, "umbrales": umbrales}


def _umbral(factor, proyecciones):
    """Cuándo se deja de ser gratis: cuántas veces el uso actual y (si hay historial) en cuántos días."""
    ya = factor is not None and factor <= 1
    dias = [p["dias"] for p in proyecciones if p["estado"] in ("crece", "superado") and p["dias"] is not None]
    fechas = [p["fecha"] for p in proyecciones if p["estado"] == "crece" and p["fecha"]]
    return {"factor": None if factor is None else round(factor, 1), "ya": ya,
            "dias": min(dias) if dias else None, "fecha": min(fechas) if fechas else None}


# --- Blueprint ----------------------------------------------------------------
_Modelo = None
_ModeloH = None
_tarea = {"fn": None, "dia": None, "intento": 0.0}


def instantanea_diaria():
    """Para el vigilante / cron de app.py: guarda UNA lectura por día aunque nadie abra el panel.
    Es barata de llamar seguido (si ya hay lectura de hoy, no hace nada). Debe llamarse dentro de un app_context."""
    fn = _tarea["fn"]
    if not fn or _tarea["dia"] == _hoy() or time.time() - _tarea["intento"] < 3 * 3600:
        return
    _tarea["intento"] = time.time()
    try:
        if fn():
            _tarea["dia"] = _hoy()
    except Exception as e:
        current_app.logger.warning("Instantánea diaria de almacenamiento: %s", e)


def crear_blueprint(db, registrar):
    global _Modelo, _ModeloH
    bp = Blueprint("almacen", __name__)

    if _ModeloH is None:
        class HistorialAlmacen(db.Model):
            """Una lectura por día y por servicio/proyecto (valor en bytes, o en créditos para Cloudinary)."""
            __tablename__ = "historial_almacen"
            fecha = db.Column(db.Date, primary_key=True)
            clave = db.Column(db.String(160), primary_key=True)
            valor = db.Column(db.Float, nullable=False)
            limite = db.Column(db.Float)
            unidad = db.Column(db.String(10), default="bytes")
        _ModeloH = HistorialAlmacen
    Historial = _ModeloH

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

    # --- historial diario ---------------------------------------------------------
    def asegurar_tabla_historial():
        if not _estado["tabla_h"]:
            Historial.__table__.create(db.engine, checkfirst=True)
            _estado["tabla_h"] = True

    def guardar_instantanea(d):
        """Guarda (o actualiza) la lectura de HOY. Un fallo aquí nunca debe romper el panel."""
        lecturas = _lecturas(d)
        if not lecturas:
            return
        try:
            asegurar_tabla_historial()
            hoy = _hoy()
            for clave, valor, limite, unidad in lecturas:
                clave = clave[:160]
                fila = db.session.get(Historial, (hoy, clave))
                if fila:
                    fila.valor, fila.limite, fila.unidad = float(valor), limite, unidad
                else:
                    db.session.add(Historial(fecha=hoy, clave=clave, valor=float(valor), limite=limite, unidad=unidad))
            if _estado["limpieza"] != hoy:
                Historial.query.filter(Historial.fecha < hoy - timedelta(days=CONSERVAR_DIAS)).delete()
                _estado["limpieza"] = hoy
            db.session.commit()
        except Exception as e:                      # p. ej. dos workers guardando a la vez: gana el primero
            db.session.rollback()
            current_app.logger.warning("Historial de almacenamiento: %s", e)

    def leer_series():
        """{clave: {"serie": [(fecha, valor)], "limite", "unidad"}} de los últimos HISTORIAL_DIAS días.
        Se ocultan las claves sin lectura en los últimos 3 días (proyectos que ya no existen)."""
        asegurar_tabla_historial()
        hoy = _hoy()
        filas = (Historial.query.filter(Historial.fecha >= hoy - timedelta(days=HISTORIAL_DIAS))
                 .order_by(Historial.fecha).all())
        series = {}
        for f in filas:
            s = series.setdefault(f.clave, {"serie": [], "limite": None, "unidad": f.unidad or "bytes"})
            s["serie"].append((f.fecha, f.valor))
            s["limite"], s["unidad"] = f.limite, f.unidad or "bytes"
        return {k: v for k, v in series.items() if (hoy - v["serie"][-1][0]).days <= 3}

    def items_historial():
        hoy = _hoy()
        try:
            series = leer_series()
        except Exception as e:
            db.session.rollback()
            current_app.logger.warning("Leer historial de almacenamiento: %s", e)
            return []
        items = []
        for clave, s in series.items():
            p = proyectar(s["serie"], s["limite"], hoy)
            items.append(dict(p, clave=clave, nombre=_etiqueta(clave), servicio=clave.split(":")[0],
                              unidad=s["unidad"], limite=s["limite"],
                              serie=[[f.isoformat(), v] for f, v in s["serie"]]))
        # sin límite en GB configurado, lo que importa en Cloudinary son los créditos: se oculta la fila duplicada
        if any(i["clave"] == "cloudinary:creditos" for i in items):
            items = [i for i in items if not (i["clave"] == "cloudinary" and not i["limite"])]
        return _ordenar_items(items)

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
                guardar_instantanea(datos)
                _cache["datos"], _cache["t"] = datos, time.time()
            return _cache["datos"]

    def tomar_si_falta():
        """Usada por instantanea_diaria(): True si ya hay (o se logró guardar) la lectura de hoy."""
        asegurar_tabla_historial()
        hay = lambda: db.session.query(Historial.fecha).filter(Historial.fecha == _hoy()).first() is not None
        if hay():
            return True
        datos_cacheados(True)
        return hay()

    _tarea["fn"] = tomar_si_falta

    @bp.route("/api/almacenamiento/resumen")
    def resumen():
        if not es_admin():
            return negado()
        d = _publico(datos_cacheados(request.args.get("forzar") == "1"))
        d["vinculos"] = _vinculos(_filas_proyectos(db))
        d["alertas"] = list(d.get("alertas") or []) + _alertas_historial(items_historial())   # copia: no tocar el caché
        return jsonify(ok=True, **d)

    @bp.route("/api/almacenamiento/historial")
    def historial():
        """Crecimiento diario por servicio/proyecto y en cuántos días se llega al límite."""
        if not es_admin():
            return negado()
        datos_cacheados()                       # asegura que exista al menos la lectura de hoy
        return jsonify(ok=True, items=items_historial(), hoy=_hoy().isoformat(), ventana=VENTANA_DIAS)

    @bp.route("/api/almacenamiento/costos")
    def costos():
        """Cuánto costaría el almacenamiento extra si el uso crece (multiplicando el uso o al ritmo real)."""
        if not es_admin():
            return negado()
        try:
            factor = float(request.args.get("factor", ""))
            factor = factor if math.isfinite(factor) and 0 < factor <= 1000 else None
        except ValueError:
            factor = None
        d = datos_cacheados()
        base = _base_costos(d)
        try:
            series = leer_series()
        except Exception as e:
            db.session.rollback()
            current_app.logger.warning("Leer historial de almacenamiento: %s", e)
            series = {}
        t, gp = _tarifas(), _gratis_neon_proyecto()
        res = calcular_costos(base, series, t, gp, _hoy(), factor)
        return jsonify(ok=True, tarifas=t, tarifas_defecto=TARIFAS, tarifas_fecha=TARIFAS_FECHA,
                       propias=[k for k in TARIFAS if _origen(k) == "panel"], neon_gratis_proyecto=gp,
                       disponible={k: v is not None for k, v in base.items()},
                       planes_cloudinary=[{"plan": n, "creditos": c, "usd": u} for n, c, u in PLANES_CLD], **res)

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
        listo = {"neon": bool(_env("NEON_API_KEY")), "r2": _r2_configurado(), "cloudinary": _cld_configurado()}   # "costos" no es una conexión
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
                    if not math.isfinite(float(v)) or float(v) <= 0:
                        raise ValueError
                except ValueError:
                    return jsonify(ok=False, error="El límite debe ser un número de GB mayor que 0."), 400
            if v and nombre in TARIFAS:
                try:
                    x = float(v)
                    if not math.isfinite(x) or x < 0 or (x == 0 and nombre == "COSTO_USD_MXN"):
                        raise ValueError
                except ValueError:
                    return jsonify(ok=False, error=f"La tarifa {nombre} debe ser un número válido (no negativo)."), 400
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