"""render_panel.py — Estado de tus servicios en Render (varias cuentas) dentro del panel de ZEDYTH.

Qué hace:
  * Lee la API de Render con una o varias llaves (hasta 5; se guardan en /conexiones, cifradas).
    Una llave de Render ve todos los workspaces de su usuario; si tus SaaS están en usuarios distintos, usa una llave por usuario.
  * Por cada servicio muestra: cuenta, tipo, plan, suspendido o no, último deploy (resultado, commit, hora).
  * Liga cada servicio con una de tus plataformas SIN tocar la base de datos, comparando:
        repositorio (Proyecto.repo_url)  ·  dirección (url_produccion y subdominios)  ·  nombre idéntico.
  * Avisa al celular cuando un deploy reciente falla o un servicio queda suspendido (sin repetir el aviso).

Cuidado con los límites:
  * El resultado se guarda 5 min en memoria: abrir pantallas NO gasta consultas ni despierta a Neon.
  * Consultar la API de Render NO despierta tus servicios ni gasta sus horas de instancia.
  * La llave nunca sale del servidor: la pantalla solo ve los últimos 4 caracteres.

RAM y CPU: se leen de /v1/metrics/{cpu,memory,cpu-limit,memory-limit} (última hora, 4 consultas por llave sin importar
cuántos servicios haya). El % sale de uso ÷ límite del plan. Si Render no entrega algo, se muestra «—», nunca un dato inventado.

Conexión en app.py (ya aplicada en este paquete):
    import render_panel
    app.register_blueprint(render_panel.crear_blueprint(app, db, crear_notificacion, Proyecto))
    ... y render_panel.revisar() dentro de push_revisar (junto a servicios.revisar()).
"""
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib import error as _uerr, parse as _uparse, request as _ureq
from urllib.parse import urlsplit

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user

import ajustes

API = "https://api.render.com/v1"
CACHE_SEG = 300            # el resultado se reutiliza 5 min
MAX_LLAVES = 5
MAX_SERVICIOS = 60         # tope de servicios con consulta de deploy (cuida el límite de la API)
MAX_PAGINAS = 5            # x100 por listado
TIMEOUT = 15
HORAS_GRATIS_MES = 750     # referencia: horas de instancia gratis por cuenta (confirma en tu cuenta de Render)
AVISO_FALLO_HORAS = 24     # solo se avisan deploys fallidos de las últimas 24 h (evita avisar viejos al conectar)
PLATAFORMA = "Plataforma propia"

FALLIDOS = {"build_failed", "update_failed", "pre_deploy_failed"}
EN_CURSO = {"created", "build_in_progress", "update_in_progress", "pre_deploy_in_progress"}
MOTIVOS = {401: "llave rechazada (¿la borraste en Render o está mal copiada?)",
           403: "la llave no tiene permiso", 429: "Render pidió esperar (demasiadas consultas)"}

_cache = {"t": 0.0, "datos": None, "cargando": False}
_lock = threading.Lock()
_api = {}      # lo llena crear_blueprint


# --- Llaves y HTTP -------------------------------------------------------------------------------------------
def _llaves():
    """[(numero, llave)] de las cuentas con llave guardada (en pantalla o en variables de Render)."""
    out = []
    for i in range(1, MAX_LLAVES + 1):
        k = (ajustes.valor("RENDER_API_KEY" + ("" if i == 1 else f"_{i}")) or "").strip()
        if k:
            out.append((i, k))
    return out


def _get(ruta, llave, params=None):
    url = API + ruta + ("?" + _uparse.urlencode(params, doseq=True) if params else "")
    req = _ureq.Request(url, headers={"Authorization": "Bearer " + llave, "Accept": "application/json",
                                      "User-Agent": "zedyth-panel/1.0"})
    try:
        with _ureq.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8") or "null")
    except _uerr.HTTPError as e:
        raise RuntimeError(MOTIVOS.get(e.code, f"Render respondió error {e.code}")) from None
    except _uerr.URLError:
        raise RuntimeError("sin conexión con Render") from None
    except ValueError:
        raise RuntimeError("respuesta no válida de Render") from None


def _paginar(ruta, llave, params=None):
    """Los listados de Render devuelven [{cursor, <objeto>}]; se piden de 100 en 100."""
    items, cursor = [], None
    for _ in range(MAX_PAGINAS):
        p = dict(params or {}, limit=100)
        if cursor:
            p["cursor"] = cursor
        pag = _get(ruta, llave, p)
        if not isinstance(pag, list) or not pag:
            break
        items.extend(pag)
        ultimo = pag[-1]
        cursor = ultimo.get("cursor") if isinstance(ultimo, dict) else None
        if len(pag) < 100 or not cursor:
            break
    return items


# --- Lectura de servicios --------------------------------------------------------------------------------------
def _servicio(it, cuenta):
    s = it.get("service") if isinstance(it, dict) else None
    if not isinstance(s, dict) or not s.get("id"):
        return None
    det = s.get("serviceDetails") or {}
    url = det.get("url") or ""
    panel = s.get("dashboardUrl") or ""
    return {"id": s["id"], "nombre": s.get("name") or s["id"], "tipo": s.get("type") or "",
            "suspendido": s.get("suspended") == "suspended", "plan": det.get("plan") or "",
            "region": det.get("region") or "",
            "url": url if url.startswith("https://") else "",
            "repo": s.get("repo") or "", "rama": s.get("branch") or "",
            "auto_deploy": s.get("autoDeploy") == "yes",
            "panel": panel if panel.startswith("https://dashboard.render.com/") else "",
            "cuenta": cuenta, "deploy": None, "deploy_error": None, "metricas": None, "metricas_nota": None}


def _ultimo_deploy(llave, sid):
    r = _get(f"/services/{sid}/deploys", llave, {"limit": 1})
    d = r[0].get("deploy") if isinstance(r, list) and r and isinstance(r[0], dict) else None
    if not isinstance(d, dict):
        return None
    lineas = ((d.get("commit") or {}).get("message") or "").strip().splitlines()
    return {"id": d.get("id") or "", "estado": d.get("status") or "", "commit": (lineas[0] if lineas else "")[:90],
            "creado": d.get("createdAt"), "terminado": d.get("finishedAt")}


# --- RAM y CPU -------------------------------------------------------------------------------------------------
TIPOS_CON_METRICAS = {"web_service", "private_service", "background_worker"}
UMBRAL_RAM_AVISO = 90      # % de la memoria del plan a partir del cual se avisa
MB = 1024 * 1024


def _ts(v):
    """Marca de tiempo → número ordenable. Acepta epoch (número o texto) o fecha ISO como «2026-11-15T10:00:00Z»."""
    try:
        return float(v)
    except (TypeError, ValueError):
        t = _fecha(v if isinstance(v, str) else "")
        if t is None:
            raise ValueError("fecha ilegible")
        return t.timestamp()


def _series(resp):
    """{(recurso, instancia): [valores en orden de tiempo]}. Tolerante: lo que no se entienda se ignora."""
    out = {}
    for it in resp if isinstance(resp, list) else []:
        if not isinstance(it, dict):
            continue
        lab = {x.get("field"): x.get("value") for x in (it.get("labels") or []) if isinstance(x, dict)}
        vals = []
        for v in it.get("values") or []:
            try:
                vals.append((_ts(v["timestamp"]), float(v["value"])))
            except (TypeError, ValueError, KeyError):
                pass
        if lab.get("resource") and vals:
            out[(lab["resource"], lab.get("instance") or "")] = [x for _, x in sorted(vals)]
    return out


def _calc(uso, lim, rid):
    """Mejor instancia (la más cargada) de un recurso: {ultimo, pico, limite, pct, pico_pct} o None."""
    lim_rid = next((v[-1] for (r, _), v in lim.items() if r == rid and v), None)
    mejor = None
    for (r, inst), vals in uso.items():
        if r != rid or not vals:
            continue
        limite = (lim.get((r, inst)) or [lim_rid])[-1]
        pct = vals[-1] / limite * 100 if limite else None
        pico = max(vals) / limite * 100 if limite else None
        c = {"ultimo": vals[-1], "pico": max(vals), "limite": limite or None, "pct": pct, "pico_pct": pico}
        if mejor is None or (pct or 0) > (mejor["pct"] or 0) or (mejor["pct"] is None and pct is None and c["ultimo"] > mejor["ultimo"]):
            mejor = c
    return mejor


def _txt_ram(c):
    if not c:
        return None
    t = f"{c['ultimo'] / MB:.0f} MB"
    if c["limite"]:
        t += f" de {c['limite'] / MB:.0f} MB · {c['pct']:.0f}%"
    return t + (f" · pico 1 h: {c['pico_pct']:.0f}%" if c["pico_pct"] is not None else "")


def _txt_cpu(c):
    if not c:
        return None
    if c["limite"]:
        return f"{c['pct']:.0f}% de {c['limite']:g} CPU" + (f" · pico 1 h: {c['pico_pct']:.0f}%" if c["pico_pct"] is not None else "")
    return f"{c['ultimo']:.2f} CPU"


def _metricas(llave, ids):
    """{id_servicio: {"cpu": {...}, "ram": {...}}}. 4 consultas para TODOS los ids de esa llave (se unen con «o»)."""
    base = {"resource": ids}          # sin fechas: Render responde la última hora (así no dependemos del formato de fecha)
    cpu, cpu_l = _series(_get("/metrics/cpu", llave, base)), _series(_get("/metrics/cpu-limit", llave, base))
    ram, ram_l = _series(_get("/metrics/memory", llave, base)), _series(_get("/metrics/memory-limit", llave, base))
    out = {}
    for rid in ids:
        c, r = _calc(cpu, cpu_l, rid), _calc(ram, ram_l, rid)
        if c or r:
            if c:
                c["texto"] = _txt_cpu(c)
            if r:
                r["texto"] = _txt_ram(r)
            out[rid] = {"cpu": c, "ram": r}
    return out


def _estado(s):
    if s["suspendido"]:
        return "Suspendido", "mal"
    d = s["deploy"]
    if s["deploy_error"]:
        return "Sin lectura", "gris"
    if not d:
        return "Sin deploys", "gris"
    e = d["estado"]
    if e in FALLIDOS:
        return "Deploy fallido", "mal"
    if e in EN_CURSO:
        return "Desplegando", "amb"
    if e == "live":
        return "En línea", "ok"
    if e == "canceled":
        return "Deploy cancelado", "amb"
    return (e.replace("_", " ") or "Desconocido"), "gris"


def _leer():
    llaves_info, servicios, errores, origen = [], {}, [], {}
    for i, llave in _llaves():
        info = {"final": "····" + llave[-4:], "cuentas": [], "error": None}
        llaves_info.append(info)
        try:
            owners = [o["owner"] for o in _paginar("/owners", llave)
                      if isinstance(o, dict) and isinstance(o.get("owner"), dict)]
            if not owners:
                owners = [{"id": None, "name": f"Cuenta {i}"}]
            for o in owners:
                nombre = o.get("name") or o.get("email") or f"Cuenta {i}"
                info["cuentas"].append(nombre)
                for it in _paginar("/services", llave, {"ownerId": o["id"]} if o.get("id") else {}):
                    s = _servicio(it, nombre)
                    if s and s["id"] not in servicios:          # el mismo workspace puede verse con dos llaves
                        servicios[s["id"]] = s
                        origen[s["id"]] = llave
        except RuntimeError as e:
            info["error"] = str(e)
            errores.append(f"Llave {info['final']}: {e}")
    lista = list(servicios.values())
    if len(lista) > MAX_SERVICIOS:
        errores.append(f"Hay {len(lista)} servicios; solo se revisan los primeros {MAX_SERVICIOS}.")
        lista = lista[:MAX_SERVICIOS]

    def _dep(s):
        if s["suspendido"]:
            return
        try:
            s["deploy"] = _ultimo_deploy(origen[s["id"]], s["id"])
        except RuntimeError as e:
            s["deploy_error"] = str(e)

    if lista:
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(_dep, lista))
    por_llave = {}
    for s in lista:
        if s["tipo"] in TIPOS_CON_METRICAS and not s["suspendido"]:
            por_llave.setdefault(origen[s["id"]], []).append(s)
    for llave, svs in por_llave.items():
        try:
            m = _metricas(llave, [x["id"] for x in svs])
            for x in svs:
                x["metricas"] = m.get(x["id"])
                if not x["metricas"]:
                    x["metricas_nota"] = "Render no devolvió datos de la última hora (normal si el servicio estaba dormido)"
        except RuntimeError as e:             # sin métricas no se cae nada: se explica el motivo
            errores.append(f"Métricas de RAM/CPU no disponibles con la llave ····{llave[-4:]}: {e}")
            for x in svs:
                x["metricas_nota"] = f"Render respondió: {e}"
    for s in lista:
        s["estado"], s["nivel"] = _estado(s)

    cuentas = {}
    for s in lista:
        c = cuentas.setdefault(s["cuenta"], {"nombre": s["cuenta"], "total": 0, "suspendidos": 0, "fallidos": 0,
                                             "gratis_web": 0, "aviso": None})
        c["total"] += 1
        c["suspendidos"] += s["suspendido"]
        c["fallidos"] += s["nivel"] == "mal" and not s["suspendido"]
        c["gratis_web"] += (s["tipo"] == "web_service" and s["plan"] == "free" and not s["suspendido"])
    for c in cuentas.values():
        if c["gratis_web"] > 1:
            c["aviso"] = (f"{c['gratis_web']} servicios web gratis comparten ~{HORAS_GRATIS_MES} h de instancia al mes: "
                          f"si los mantienes despiertos 24/7 no alcanza (≈{HORAS_GRATIS_MES // c['gratis_web']} h cada uno). "
                          "Confirma el cupo en tu cuenta de Render.")
    return {"actualizado": datetime.now(timezone.utc).isoformat(), "llaves": llaves_info, "servicios": lista,
            "cuentas": list(cuentas.values()), "errores": errores}


def datos(forzar=False):
    """Lectura (con caché de 5 min). Bloquea mientras lee; para pantallas pesadas usa solo_cache()."""
    with _lock:
        if not forzar and _cache["datos"] is not None and time.time() - _cache["t"] < CACHE_SEG:
            return _cache["datos"]
        if not _llaves():
            _cache.update(datos=None, t=0.0)
            return None
        nuevo = _leer()
        todo_fallo = nuevo["llaves"] and all(i["error"] for i in nuevo["llaves"])
        _cache["datos"] = nuevo
        _cache["t"] = time.time() - (CACHE_SEG - 30 if todo_fallo else 0)   # si todo falló, reintenta en 30 s
        return nuevo


def solo_cache():
    return _cache["datos"]


def _leer_en_segundo_plano():
    if _cache["cargando"]:
        return
    _cache["cargando"] = True

    def _t():
        try:
            datos()
        except Exception:
            pass
        finally:
            _cache["cargando"] = False
    threading.Thread(target=_t, daemon=True).start()


def invalidar():
    _cache["t"] = 0.0


def probar():
    """(ok, mensaje) para el botón «Probar conexión» de /conexiones. Una consulta mínima por llave."""
    llaves = _llaves()
    if not llaves:
        return False, "No hay ninguna llave de Render guardada."
    partes, buenas = [], 0
    for _, k in llaves:
        try:
            o = _get("/owners", k, {"limit": 20})
            nombres = [x["owner"].get("name") or x["owner"].get("email") for x in (o or [])
                       if isinstance(x, dict) and isinstance(x.get("owner"), dict)]
            partes.append(f"····{k[-4:]}: funciona ({', '.join(n for n in nombres if n) or 'sin workspaces'})")
            buenas += 1
        except RuntimeError as e:
            partes.append(f"····{k[-4:]}: {e}")
    invalidar()
    return buenas == len(llaves), f"{buenas} de {len(llaves)} llaves funcionan. " + " · ".join(partes)


# --- Ligar servicios con plataformas ----------------------------------------------------------------------------
def _host(u):
    u = (u or "").strip()
    if not u:
        return ""
    try:
        h = urlsplit(u if "//" in u else "//" + u).hostname or ""
    except ValueError:
        return ""
    h = h.lower()
    return h[4:] if h.startswith("www.") else h


def _repo(u):
    m = re.search(r"github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", (u or "").strip(), re.I)
    return f"{m.group(1)}/{m.group(2)}".lower() if m else ""


def _norm(t):
    return re.sub(r"[^a-z0-9]", "", (t or "").lower())


def vincular(proyecto, servicios, dominios=()):
    """Servicios de Render que parecen de esta plataforma, del más al menos seguro (repo, dirección, nombre)."""
    repo, nom = _repo(proyecto.repo_url), _norm(proyecto.nombre)
    hosts = {_host(proyecto.url_produccion)} | {_host(d) for d in dominios}
    hosts.discard("")
    res = []
    for s in servicios:
        pts = 0
        if repo and _repo(s["repo"]) == repo:
            pts += 3
        if hosts and _host(s["url"]) in hosts:
            pts += 4
        if len(nom) >= 4 and _norm(s["nombre"]) == nom:
            pts += 2
        if pts:
            res.append((pts, s))
    res.sort(key=lambda x: -x[0])
    return [s for _, s in res]


def por_proyecto(p):
    """Para la pestaña de una plataforma. NUNCA espera a Render: usa la caché y, si está vacía, la llena de fondo."""
    if not _llaves():
        return {"conectado": False, "servicios": [], "pendiente": False, "errores": []}
    d = solo_cache()
    if d is None:
        _leer_en_segundo_plano()
        return {"conectado": True, "servicios": [], "pendiente": True, "errores": []}
    return {"conectado": True, "pendiente": False, "errores": d["errores"], "actualizado": d["actualizado"],
            "servicios": [_con_hace(s) for s in vincular(p, d["servicios"], [x.nombre for x in p.subdominios])]}


# --- Fechas ---------------------------------------------------------------------------------------------------------
def _fecha(iso):
    try:
        t = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def _hace(iso):
    t = _fecha(iso)
    if t is None:
        return ""
    seg = max(0, (datetime.now(timezone.utc) - t).total_seconds())
    if seg < 3600:
        return f"hace {max(1, round(seg / 60))} min"
    return f"hace {round(seg / 3600)} h" if seg < 86400 else f"hace {round(seg / 86400)} d"


def _con_hace(s):
    """Copia del servicio con «hace X» ya calculado (la caché dura 5 min; el «hace» se calcula al mostrar)."""
    d = s.get("deploy")
    return dict(s, deploy=dict(d, hace=_hace(d["terminado"] or d["creado"])) if d else None)


# --- Avisos --------------------------------------------------------------------------------------------------------
def _reciente(iso, horas=AVISO_FALLO_HORAS):
    t = _fecha(iso)
    return t is not None and datetime.now(timezone.utc) - t <= timedelta(hours=horas)


def alertar(d, notificar):
    """Manda los avisos pendientes. `notificar` = crear_notificacion de app.py (ya evita repetir por `clave`)."""
    if not d:
        return 0
    n = 0
    sem = datetime.now(timezone.utc).isocalendar()
    for s in d["servicios"]:
        if s["suspendido"]:
            notificar("Render", f"Render: «{s['nombre']}» está suspendido", f"Cuenta {s['cuenta']}. Revisa su plan o pagos en Render.",
                      "/render", urgente=True, clave=f"render-susp-{s['id']}-{sem[0]}-{sem[1]}")      # 1 aviso por semana
            n += 1
        dep = s.get("deploy")
        if dep and dep["estado"] in FALLIDOS and _reciente(dep["terminado"] or dep["creado"]):
            notificar("Render", f"Deploy fallido: {s['nombre']}", (dep["commit"] or "Sin mensaje de commit") + f" · cuenta {s['cuenta']}",
                      "/render", urgente=True, clave=f"render-fallo-{s['id']}-{dep['id']}")
            n += 1
        ram = (s.get("metricas") or {}).get("ram")
        if ram and ram["pct"] is not None and ram["pct"] >= UMBRAL_RAM_AVISO and not s["suspendido"]:
            notificar("Render", f"Render: «{s['nombre']}» casi sin memoria", f"RAM al {ram['pct']:.0f}% del plan ({ram['texto']}). Puede reiniciarse por falta de memoria.",
                      "/render", urgente=False, clave=f"render-ram-{s['id']}-{sem[0]}-{sem[1]}")        # 1 aviso por semana
            n += 1
    return n


def revisar():
    """Para push_revisar (cron): lee Render si la caché venció y avisa. Nunca lanza error."""
    try:
        if _llaves() and _api.get("notificar"):
            alertar(datos(), _api["notificar"])
    except Exception:
        pass


# --- Pantalla y API ------------------------------------------------------------------------------------------------
def crear_blueprint(app, db, crear_notificacion, Proyecto):
    bp = Blueprint("render_panel", __name__)
    _api["notificar"] = crear_notificacion

    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def publico(d):
        """Lo que ve la pantalla: servicios con el nombre de la plataforma ligada. Sin llaves."""
        plats = Proyecto.query.filter_by(tipo=PLATAFORMA).all()
        dueno = {}
        for p in plats:
            for s in vincular(p, d["servicios"], [x.nombre for x in p.subdominios]):
                dueno.setdefault(s["id"], p)
        servicios = []
        for s in d["servicios"]:
            p = dueno.get(s["id"])
            servicios.append(dict(_con_hace(s), plataforma=p.nombre if p else None, plataforma_id=p.id if p else None))
        return {"ok": True, "conectado": True, "actualizado": d["actualizado"], "llaves": d["llaves"],
                "cuentas": d["cuentas"], "servicios": servicios, "errores": d["errores"]}

    @bp.route("/render")
    def pagina():
        if not es_admin():
            return "Solo administradores.", 403
        return render_template("render.html")

    @bp.route("/api/render/resumen")
    def api_resumen():
        if not es_admin():
            return jsonify(ok=False, error="Solo administradores."), 403
        try:
            d = datos()
        except Exception:
            return jsonify(ok=False, error="No se pudo leer Render."), 502
        if d is None:
            return jsonify(ok=True, conectado=False)
        return jsonify(publico(d))

    @bp.route("/api/render/actualizar", methods=["POST"])
    def api_actualizar():
        if not es_admin():
            return jsonify(ok=False, error="Solo administradores."), 403
        if not isinstance(request.get_json(silent=True), dict):
            return jsonify(ok=False, error="Solicitud no válida."), 400
        try:
            d = datos(forzar=True)
        except Exception:
            return jsonify(ok=False, error="No se pudo leer Render."), 502
        if d is None:
            return jsonify(ok=True, conectado=False)
        return jsonify(publico(d))

    return bp
