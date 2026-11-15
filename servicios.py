"""servicios.py — Estado y costo de TODOS los servicios del negocio en un solo lugar.

Qué junta:
  * Catálogo propio de servicios (Render, Neon, R2, Cloudinary, Meta, Gemini, dominios...): plan, costo, ciclo y renovación.
  * Estado: de las conexiones que ya tienes (lecturas de Almacenamiento y pool de Llaves) y, opcionalmente, de una URL
    de estado que se visita con el mismo verificador anti-SSRF de monitor.py.
  * Costo mensual en MXN: catálogo + costo de IA del mes (llaves.py) + estimado por uso de Neon/R2/Cloudinary.
  * Renovaciones unificadas: el catálogo, los costos por plataforma (CostoServicio) y los Vencimientos (dominio/SSL/hosting).

Se conecta en app.py igual que llaves.py (ver instrucciones al final de este archivo):
    import servicios
    app.register_blueprint(servicios.crear_blueprint(app, db, registrar, crear_notificacion, Proyecto, CostoServicio, Vencimiento, Auditoria))

Reglas para que NO se cuente dos veces un costo:
  * El catálogo es para costos que NO están ya como «costo de plataforma» (CostoServicio). La pantalla avisa si detecta un posible duplicado.
  * El estimado por uso de Neon/R2/Cloudinary solo entra al total de un servicio si NO le pusiste precio en el catálogo.
  * Las lecturas de Almacenamiento se toman de su caché: abrir esta pantalla NO despierta a Neon ni gasta cuota de las APIs.

Variables de entorno (opcionales):
    SERVICIOS_AVISO_DIAS   días de anticipación para avisar renovaciones del catálogo (por defecto 30)
"""
import calendar
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint, render_template, request, redirect, url_for, abort, Response
from flask_login import current_user

try:
    import monitor                      # verificador de URLs con protección anti-SSRF
except Exception:                       # sin monitor.py el módulo funciona, solo sin «verificar URL»
    monitor = None

PROVEEDORES = ["Render", "Neon", "Cloudflare R2", "Cloudinary", "Meta (WhatsApp)", "Google (Gemini)", "Anthropic",
               "OpenAI", "UptimeRobot", "Dominio / registrador", "GitHub", "Stripe / procesador de pagos",
               "PAC / CFDI", "Otro"]          # los nombres repetidos coinciden con los de llaves.py a propósito
CATEGORIAS = ["Hosting", "Base de datos", "Almacenamiento", "IA", "Mensajería", "Dominio", "Monitoreo", "Pagos",
              "Código", "Otro"]
CATEGORIA_DE = {"Render": "Hosting", "Neon": "Base de datos", "Cloudflare R2": "Almacenamiento",
                "Cloudinary": "Almacenamiento", "Meta (WhatsApp)": "Mensajería", "Google (Gemini)": "IA",
                "Anthropic": "IA", "OpenAI": "IA", "UptimeRobot": "Monitoreo", "Dominio / registrador": "Dominio",
                "GitHub": "Código", "Stripe / procesador de pagos": "Pagos", "PAC / CFDI": "Pagos"}
PERIODOS = {"Mensual": 1, "Trimestral": 3, "Anual": 12}
MONEDAS = ("MXN", "USD")
FUENTES = [("", "Sin conexión automática (solo fecha y costo)"),
           ("almacenamiento:neon", "Neon (lectura de Almacenamiento)"),
           ("almacenamiento:r2", "Cloudflare R2 (lectura de Almacenamiento)"),
           ("almacenamiento:cloudinary", "Cloudinary (lectura de Almacenamiento)"),
           ("almacenamiento:uptimerobot", "UptimeRobot (lectura de Almacenamiento)"),
           ("llaves", "Llaves de API de este proveedor (pool de Llaves)")]
FUENTES_VALIDAS = {f for f, _ in FUENTES}
UMBRALES_RENOV = (30, 14, 7, 3, 1, 0)         # días antes en que se avisa (una vez por umbral)
AVISO_DIAS = int(os.environ.get("SERVICIOS_AVISO_DIAS", "30") or 30)
MAX_SERVICIOS = 300
PLATAFORMA = "Plataforma propia"              # Proyecto.tipo de tus plataformas (para armar los enlaces)
UMBRAL_USO = 80                               # % de un límite a partir del cual el estado pasa a «Atención»
CAMBIO_DEFECTO = 18.7

MENSAJES = {
    "creado": "Servicio agregado al catálogo.",
    "editado": "Servicio actualizado.",
    "renovado": "Renovación registrada: se movió la próxima fecha.",
    "pausado": "Servicio pausado: ya no cuenta en costos ni avisos.",
    "activado": "Servicio activo de nuevo.",
    "eliminado": "Servicio eliminado del catálogo.",
    "verificado": "Verificación terminada.",
}

_api = {}      # lo llena crear_blueprint (misma técnica que llaves.py)


# --- API pública (para el resto de app.py) ------------------------------------------------------
def costo_mensual():
    """Costos compartidos del mes en MXN: {fijo, ia, almacenamiento, total, tipo_cambio}. Para Finanzas."""
    return _api["costo_mensual"]()


def salidas_proyeccion():
    """Renovaciones del catálogo como [(fecha, paso_en_meses, monto_mxn)] para la proyección de 12 meses de Finanzas."""
    return _api["salidas"]()


def resumen_plataformas(pids):
    """Para la pantalla de Plataformas: {"por_plat": {pid: {...}}, "compartido": {...}, "contador": {...}}.
    Cada grupo trae: filas (servicios con su estado), mes (catálogo, MXN/mes), ia (IA del mes, MXN), nivel (peor estado)
    y prox (próxima renovación: (fecha, nombre) o None). «compartido» = servicios sin plataforma."""
    return _api["resumen"](pids)


def revisar():
    """Para el vigilante de app.py: avisa renovaciones próximas/vencidas y verifica las URLs de estado."""
    try:
        _api["revisar"]()
    except Exception:       # nunca debe tumbar al vigilante
        pass


# --- utilidades puras -----------------------------------------------------------------------------
def _sumar_meses(d, n):
    m = d.month - 1 + n
    y = d.year + m // 12
    m = m % 12 + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def _tipo_cambio():
    """MXN por US$: el mismo que usa Almacenamiento (editable en su sección «Costos»)."""
    try:
        import almacenamiento
        v = float(almacenamiento._tarifa("COSTO_USD_MXN"))
        return v if v > 0 else CAMBIO_DEFECTO
    except Exception:
        return CAMBIO_DEFECTO


def _a_mxn(monto, moneda, tc):
    return float(monto or 0) * (tc if (moneda or "MXN") == "USD" else 1.0)


def _hace(seg):
    if seg is None:
        return ""
    if seg < 90:
        return "hace un momento"
    m = int(seg // 60)
    if m < 60:
        return f"hace {m} min"
    h = m // 60
    if h < 48:
        return f"hace {h} h"
    return f"hace {h // 24} días"


def _url_ok(valor):
    """http(s) con dominio, sin usuario ni contraseña. Devuelve (url|None, error|None)."""
    v = (valor or "").strip()
    if not v:
        return None, None
    if len(v) > 300:
        return None, "la dirección es demasiado larga (máximo 300 caracteres)."
    try:
        p = urlsplit(v)
        p.port
    except ValueError:
        return None, "la dirección no es válida."
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        return None, "la dirección debe empezar con https:// e incluir el dominio (sin usuario ni contraseña)."
    return v, None


def _clave_prov(proveedor):
    """Primera palabra del proveedor, para detectar posibles duplicados con los costos por plataforma."""
    p = (proveedor or "").lower().replace("(", " ").replace("/", " ").split()
    return p[0] if p and p[0] != "otro" else ""


def _datos_almacenamiento():
    """(datos, edad_en_segundos) de la última lectura en caché de Almacenamiento; (None, None) si no hay."""
    try:
        import almacenamiento
        d = almacenamiento._cache.get("datos")
        if not d:
            return None, None
        return d, max(0, int(time.time() - almacenamiento._cache["t"]))
    except Exception:
        return None, None


def _estado_almacenamiento(clave, datos, edad):
    """(nivel, texto) de un servicio leído por Almacenamiento: neon | r2 | cloudinary | uptimerobot."""
    if datos is None:
        return ("sin", "Sin lectura reciente de Almacenamiento")
    d = datos.get(clave) or {}
    if not d.get("configurado"):
        return ("sin", "No está conectado en Almacenamiento")
    cuando = _hace(edad)
    if d.get("error"):
        return ("falla", f"No se pudo leer: {str(d['error'])[:90]} ({cuando})")
    if clave == "uptimerobot":
        caidos = [m.get("nombre", "?") for m in (d.get("monitores") or []) if m.get("caido")]
        if caidos:
            return ("falla", f"Caído: {', '.join(caidos[:3])} ({cuando})")
        return ("ok", f"Sin monitores caídos ({cuando})")
    for p in (d.get("proyectos") or []):
        if ((p.get("horas") or {}).get("estado")) == "agotadas":
            return ("falla", f"Neon · {p.get('nombre', '?')}: sin horas de cómputo este mes ({cuando})")
    pcts = [d.get("pct")] + [p.get("pct") for p in (d.get("proyectos") or [])]
    pcts += [p.get("cu_pct") for p in (d.get("proyectos") or [])]
    pcts = [x for x in pcts if isinstance(x, (int, float))]
    peor = max(pcts) if pcts else None
    if peor is None:
        return ("ok", f"Conectado ({cuando})")
    if peor >= 100:
        return ("falla", f"Límite superado: {peor}% ({cuando})")
    if peor >= UMBRAL_USO:
        return ("alerta", f"Al {peor}% de su límite ({cuando})")
    return ("ok", f"Al {peor}% de su límite ({cuando})")


def _estado_llaves(proveedor):
    try:
        import llaves
        r = llaves.estado_pool(proveedor)
    except Exception:
        return ("sin", "Estado de llaves no disponible")
    if r["total"] == 0:
        return ("sin", "Sin llaves registradas en Llaves")
    if r["usables"] == 0:
        return ("falla", "Ninguna llave utilizable (revisa Llaves)")
    problemas = r["invalidas"] + r["vencidas"] + r["descanso"]
    if problemas:
        return ("alerta", f"{r['usables']} de {r['total']} llaves utilizables")
    return ("ok", f"{r['usables']} llave(s) utilizable(s)")


def _combinar(estados):
    """Peor de varios (nivel, texto). «sin» solo si ninguno tiene dato real."""
    rango = {"ok": 1, "alerta": 2, "falla": 3}
    reales = [e for e in estados if e and e[0] in rango]
    if not reales:
        return ("sin", next((e[1] for e in estados if e), "Sin conexión automática"))
    nivel = max(reales, key=lambda e: rango[e[0]])[0]
    textos = [e[1] for e in reales if e[0] != "ok"] or [reales[0][1]]
    return (nivel, " · ".join(textos))


def crear_blueprint(app, db, registrar, avisar, Proyecto, CostoServicio, Vencimiento, Auditoria):
    bp = Blueprint("servicios", __name__)

    class Servicio(db.Model):
        __tablename__ = "servicio"
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(100), nullable=False)
        proveedor = db.Column(db.String(40), nullable=False)
        categoria = db.Column(db.String(20))
        proyecto_id = db.Column(db.Integer, db.ForeignKey("proyecto.id"))     # None = compartido por todo el negocio
        plan = db.Column(db.String(80))
        monto = db.Column(db.Numeric(14, 2, asdecimal=False), default=0)      # lo que pagas en cada periodo
        moneda = db.Column(db.String(3), default="MXN")
        periodicidad = db.Column(db.String(12), default="Mensual")
        proxima_renovacion = db.Column(db.Date)
        ultimo_pago = db.Column(db.Date)
        fuente = db.Column(db.String(40), default="")                         # de dónde sale su estado automático
        url_estado = db.Column(db.String(300))
        texto_estado = db.Column(db.String(80))                               # texto que debe aparecer en esa URL
        url_panel = db.Column(db.String(300))                                 # enlace a la consola del proveedor
        notas = db.Column(db.String(300))
        activo = db.Column(db.Boolean, default=True)
        estado_ultimo = db.Column(db.String(8))                               # ok | falla (de la URL de estado)
        estado_detalle = db.Column(db.String(200))
        estado_en = db.Column(db.DateTime)
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        creado_por = db.Column(db.String(80))
        proyecto = db.relationship(Proyecto)

    estado_tablas = {"ok": False}

    def asegurar():
        if estado_tablas["ok"]:
            return
        Servicio.__table__.create(db.engine, checkfirst=True)
        estado_tablas["ok"] = True

    # --- reglas de acceso ---------------------------------------------------------------------------
    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def solo_admin(f):
        @wraps(f)
        def envoltura(*a, **k):
            if not es_admin():
                abort(403)
            return f(*a, **k)
        return envoltura

    def mal(texto):
        return Response(f"Dato no válido: {texto}", 400)

    # --- lectura y validación del formulario ----------------------------------------------------------
    def leer_fecha(campo):
        v = (request.form.get(campo) or "").strip()
        if not v:
            return None, None
        try:
            return date.fromisoformat(v), None
        except ValueError:
            return None, f"«{campo}» no es una fecha válida."

    def leer_monto():
        v = (request.form.get("monto") or "").replace(",", "").replace("$", "").strip() or "0"
        try:
            d = Decimal(v)
        except InvalidOperation:
            return None, "el monto no es un número válido."
        if not d.is_finite() or d < 0 or d > Decimal("99999999"):
            return None, "el monto debe estar entre 0 y 99,999,999."
        return float(d.quantize(Decimal("0.01"))), None

    def leer_form():
        f = request.form
        nombre = (f.get("nombre") or "").strip()
        if not 2 <= len(nombre) <= 100:
            return None, "el nombre debe tener entre 2 y 100 caracteres."
        proveedor = f.get("proveedor", "")
        if proveedor not in PROVEEDORES:
            return None, "proveedor desconocido."
        categoria = f.get("categoria", "")
        if categoria not in CATEGORIAS:
            categoria = CATEGORIA_DE.get(proveedor, "Otro")
        moneda, periodicidad = f.get("moneda", "MXN"), f.get("periodicidad", "Mensual")
        if moneda not in MONEDAS or periodicidad not in PERIODOS:
            return None, "moneda o periodicidad desconocida."
        fuente = f.get("fuente", "")
        if fuente not in FUENTES_VALIDAS:
            return None, "conexión de estado desconocida."
        monto, err = leer_monto()
        if err:
            return None, err
        prox, err = leer_fecha("proxima_renovacion")
        if err:
            return None, err
        ult, err = leer_fecha("ultimo_pago")
        if err:
            return None, err
        url_estado, err = _url_ok(f.get("url_estado"))
        if err:
            return None, "URL de estado: " + err
        url_panel, err = _url_ok(f.get("url_panel"))
        if err:
            return None, "enlace a la consola: " + err
        if url_estado and monitor is None:
            return None, "falta monitor.py para verificar URLs."
        plan, texto, notas = [(f.get(c) or "").strip() for c in ("plan", "texto_estado", "notas")]
        if len(plan) > 80 or len(texto) > 80 or len(notas) > 300:
            return None, "algún texto es demasiado largo (plan y texto: 80; notas: 300)."
        pid = None
        if f.get("proyecto_id"):
            p = db.session.get(Proyecto, int(f["proyecto_id"])) if f["proyecto_id"].isdigit() else None
            if p is None:
                return None, "plataforma no encontrada."
            pid = p.id
        return {"nombre": nombre, "proveedor": proveedor, "categoria": categoria, "proyecto_id": pid,
                "plan": plan or None, "monto": monto, "moneda": moneda, "periodicidad": periodicidad,
                "proxima_renovacion": prox, "ultimo_pago": ult, "fuente": fuente, "url_estado": url_estado,
                "texto_estado": texto or None, "url_panel": url_panel, "notas": notas or None}, None

    def cargar(sid):
        s = db.session.execute(db.select(Servicio).where(Servicio.id == sid).with_for_update()).scalar_one_or_none()
        if s is None:
            abort(404)
        return s

    def detalle(s):
        return f"{s.nombre} · {s.proveedor} · {s.moneda} {s.monto or 0:,.2f}/{(s.periodicidad or '').lower()}"[:290]

    # --- costos ---------------------------------------------------------------------------------------
    def activos():
        asegurar()
        return Servicio.query.filter_by(activo=True).all()

    def mensual_mxn(s, tc):
        return _a_mxn(s.monto, s.moneda, tc) / PERIODOS.get(s.periodicidad, 1)

    def estimado_almacenamiento(datos, excluidos):
        """USD estimados HOY por uso en Neon/R2/Cloudinary (el «Hoy» del estimador de Almacenamiento).
        Se omiten los que ya tienen precio en el catálogo (para no contarlos dos veces)."""
        if not datos:
            return {}
        try:
            import almacenamiento as a
            esc = a.calcular_costos(a._base_costos(datos), {}, a._tarifas(), a._gratis_neon_proyecto(), a._hoy())
            hoy = next(e for e in esc["escenarios"] if e.get("etiqueta") == "Hoy")
        except Exception as e:
            app.logger.warning("Servicios: no se pudo estimar el almacenamiento: %s", e)
            return {}
        salida = {}
        for k in ("neon", "r2", "cloudinary"):
            e = hoy.get(k)
            if e is not None and k not in excluidos:
                salida[k] = {"usd": e.get("usd") or 0.0, "paga": bool(e.get("paga")), "cotizar": bool(e.get("cotizar"))}
        return salida

    def ia_mes_usd(proyecto_id=None):
        try:
            import llaves
            return float(llaves.costo_mes(proyecto_id) or 0.0)
        except Exception:
            return 0.0

    def calcular_costos():
        tc = _tipo_cambio()
        lista = activos()
        fijo = sum(mensual_mxn(s, tc) for s in lista)
        datos, _ = _datos_almacenamiento()
        con_precio = {s.fuente.split(":", 1)[1] for s in lista
                      if (s.fuente or "").startswith("almacenamiento:") and (s.monto or 0) > 0}
        est = estimado_almacenamiento(datos, con_precio)
        alm = sum(v["usd"] for v in est.values()) * tc
        ia = ia_mes_usd() * tc
        return {"fijo": fijo, "ia": ia, "almacenamiento": alm, "total": fijo + ia + alm, "tipo_cambio": tc,
                "estimado": est}

    def salidas():
        tc = _tipo_cambio()
        return [(s.proxima_renovacion, PERIODOS.get(s.periodicidad, 1), _a_mxn(s.monto, s.moneda, tc))
                for s in activos() if s.proxima_renovacion and (s.monto or 0) > 0]

    # --- renovaciones unificadas ------------------------------------------------------------------------
    def renovaciones(tc):
        hoy = date.today()
        items = []

        def agregar(fecha, tipo, nombre, det, p, monto, enlace, clave):
            items.append({"fecha": fecha, "dias": (fecha - hoy).days, "tipo": tipo, "nombre": nombre, "detalle": det,
                          "proyecto": p.nombre if p else "Compartido", "pid": p.id if p else None,
                          "monto": monto, "enlace": enlace, "clave": clave, "dup": False})

        for s in activos():
            if s.proxima_renovacion:
                agregar(s.proxima_renovacion, "Catálogo", s.nombre, s.proveedor, s.proyecto,
                        _a_mxn(s.monto, s.moneda, tc) or None, "/servicios", _clave_prov(s.proveedor))
        for k in CostoServicio.query.filter(CostoServicio.proxima_fecha_pago.isnot(None)).all():
            p = k.proyecto
            enlace = (f"/plataformas/{p.id}?tab=finanzas" if p.tipo == PLATAFORMA else f"/clientes/{p.cliente_id}")
            agregar(k.proxima_fecha_pago, "Costo de plataforma", k.proveedor, k.concepto or "", p,
                    float(k.monto_periodo or k.monto_mensual or 0) or None, enlace, _clave_prov(k.proveedor))
        for v in Vencimiento.query.all():
            if v.fecha:
                agregar(v.fecha, v.tipo or "Vencimiento", v.nombre, v.notas or "", v.proyecto, None,
                        f"/proyectos/{v.proyecto_id}/seguridad", (v.nombre or "").lower())
        items.sort(key=lambda i: (i["fecha"], i["nombre"].lower()))
        # posible duplicado: misma plataforma y un proveedor que se parece, en fechas cercanas
        for i, a in enumerate(items[:500]):
            for b in items[i + 1:500]:
                if a["tipo"] == b["tipo"] or a["pid"] != b["pid"] or abs((a["fecha"] - b["fecha"]).days) > 10:
                    continue
                ka, kb = a["clave"], b["clave"]
                if ka and kb and (ka in kb or kb in ka):
                    a["dup"] = b["dup"] = True
        return items

    # --- verificación de URLs de estado ------------------------------------------------------------------
    def verificar(lista):
        """Visita las URLs en paralelo (solo red) y guarda el resultado. Devuelve [(servicio, estado_previo)]."""
        if monitor is None:
            return []
        trabajos = [(s, {"url": s.url_estado, "metodo": "GET", "timeout_s": 10, "cod_min": 200, "cod_max": 399,
                         "texto": s.texto_estado or ""}) for s in lista if s.url_estado]
        if not trabajos:
            return []
        with ThreadPoolExecutor(max_workers=min(6, len(trabajos))) as ex:
            resultados = list(ex.map(lambda t: monitor.comprobar(t[1]), trabajos))
        ahora, salida = datetime.utcnow(), []
        for (s, _), r in zip(trabajos, resultados):
            previo = s.estado_ultimo
            s.estado_ultimo = "ok" if r["ok"] else "falla"
            s.estado_detalle = (f"{r['ms']} ms" if r["ok"] else (r["error"] or "Sin respuesta"))[:200]
            s.estado_en = ahora
            salida.append((s, previo))
        return salida

    def estado_de(s, datos, edad, ahora):
        partes = []
        if (s.fuente or "").startswith("almacenamiento:"):
            partes.append(_estado_almacenamiento(s.fuente.split(":", 1)[1], datos, edad))
        elif s.fuente == "llaves":
            partes.append(_estado_llaves(s.proveedor))
        if s.url_estado:
            if s.estado_ultimo is None:
                partes.append(("sin", "URL de estado sin verificar"))
            else:
                cuando = _hace((ahora - s.estado_en).total_seconds()) if s.estado_en else ""
                partes.append((s.estado_ultimo, f"{s.estado_detalle or ''} ({cuando})"))
        return _combinar(partes) if partes else ("sin", "Sin conexión automática")

    # --- vigilante ---------------------------------------------------------------------------------------
    def _revisar():
        asegurar()
        hoy, ahora = date.today(), datetime.utcnow()
        lista = Servicio.query.filter_by(activo=True).all()
        for s in lista:
            if not s.proxima_renovacion:
                continue
            dias = (s.proxima_renovacion - hoy).days
            if dias > AVISO_DIAS:
                continue
            if dias < 0:
                titulo = f"Servicio vencido: {s.nombre}"
                clave = f"serv-venc-{s.id}-{s.proxima_renovacion}-{hoy}"          # mientras siga vencido, un aviso al día
            else:
                umbral = min(u for u in UMBRALES_RENOV if dias <= u)
                titulo = f"Se renueva {'hoy' if dias == 0 else f'en {dias} día(s)'}: {s.nombre}"
                clave = f"serv-ren-{s.id}-{s.proxima_renovacion}-{umbral}"
            cuerpo = f"{s.proveedor} · {s.moneda} {s.monto or 0:,.2f} ({(s.periodicidad or '').lower()})"
            avisar("Servicio", titulo, cuerpo, "/servicios", urgente=dias <= 3, clave=clave)
        for s, previo in verificar([s for s in lista if s.url_estado]):
            if s.estado_ultimo == "falla" and previo != "falla":
                avisar("Servicio", f"Servicio con falla: {s.nombre}", s.estado_detalle or "", "/servicios",
                       urgente=True, clave=f"serv-falla-{s.id}-{ahora:%Y%m%d%H}")
            elif s.estado_ultimo == "ok" and previo == "falla":
                avisar("Servicio", f"Servicio recuperado: {s.nombre}", s.estado_detalle or "", "/servicios",
                       urgente=False, clave=f"serv-ok-{s.id}-{ahora:%Y%m%d%H}")
        db.session.commit()

    def resumen(pids):
        tc, hoy, ahora = _tipo_cambio(), date.today(), datetime.utcnow()
        datos, edad = _datos_almacenamiento()
        rango = {"sin": 0, "ok": 1, "alerta": 2, "falla": 3}
        contador = {"ok": 0, "alerta": 0, "falla": 0, "sin": 0}
        grupos = {}

        def grupo_de(pid):
            return grupos.setdefault(pid, {"filas": [], "mes": 0.0, "ia": 0.0, "nivel": "sin", "prox": None})

        for pid in list(pids or []):
            grupo_de(pid)["ia"] = ia_mes_usd(pid) * tc
        grupo_de(None)
        for s in activos():
            nivel, texto = estado_de(s, datos, edad, ahora)
            contador[nivel] += 1
            g = grupo_de(s.proyecto_id)
            dias = (s.proxima_renovacion - hoy).days if s.proxima_renovacion else None
            g["filas"].append({"id": s.id, "nombre": s.nombre, "proveedor": s.proveedor, "categoria": s.categoria,
                               "plan": s.plan, "nivel": nivel, "texto": texto, "mes": mensual_mxn(s, tc),
                               "fecha": s.proxima_renovacion, "dias": dias, "panel": s.url_panel})
            g["mes"] += mensual_mxn(s, tc)
            if rango[nivel] > rango[g["nivel"]]:
                g["nivel"] = nivel
            if s.proxima_renovacion and (g["prox"] is None or s.proxima_renovacion < g["prox"][0]):
                g["prox"] = (s.proxima_renovacion, s.nombre)
        for g in grupos.values():
            g["filas"].sort(key=lambda f: (f["dias"] is None, f["dias"] if f["dias"] is not None else 0, f["nombre"].lower()))
        compartido = grupos.pop(None)
        return {"por_plat": grupos, "compartido": compartido, "contador": contador, "tc": tc}

    _api.update(costo_mensual=calcular_costos, salidas=salidas, revisar=_revisar, resumen=resumen)

    # --- pantallas ---------------------------------------------------------------------------------------
    @bp.route("/servicios")
    @solo_admin
    def index():
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        tc = _tipo_cambio()
        datos, edad = _datos_almacenamiento()
        lista = Servicio.query.order_by(Servicio.activo.desc(), Servicio.categoria, Servicio.nombre).all()
        costos_pp = CostoServicio.query.all()
        filas, contador = [], {"ok": 0, "alerta": 0, "falla": 0, "sin": 0}
        for s in lista:
            nivel, texto = estado_de(s, datos, edad, ahora)
            if s.activo:
                contador[nivel] += 1
            clave = _clave_prov(s.proveedor)
            dup = bool(clave) and any(clave in (k.proveedor or "").lower() for k in costos_pp)
            filas.append({"s": s, "nivel": nivel, "texto": texto,
                          "mes": mensual_mxn(s, tc), "periodo": _a_mxn(s.monto, s.moneda, tc),
                          "dias": (s.proxima_renovacion - hoy).days if s.proxima_renovacion else None, "dup": dup})
        costos = calcular_costos()
        ia_filas = []
        total_asignado = 0.0
        proyectos = Proyecto.query.order_by(Proyecto.nombre).all()
        for p in proyectos:
            usd = ia_mes_usd(p.id)
            if usd > 0:
                ia_filas.append({"nombre": p.nombre, "mxn": usd * tc, "usd": usd})
                total_asignado += usd
        resto = ia_mes_usd() - total_asignado
        if resto > 0.000001:
            ia_filas.append({"nombre": "Global (sin plataforma)", "mxn": resto * tc, "usd": resto})
        ren = renovaciones(tc)
        todas = request.args.get("todas") == "1"
        visibles = [r for r in ren if todas or r["dias"] <= 90]
        proximas = [r for r in ren if r["dias"] >= 0]
        avisos = []
        if any((r["s"].fuente or "").startswith("almacenamiento:") for r in filas) and datos is None:
            avisos.append("Aún no hay una lectura de Almacenamiento en memoria: pulsa «Actualizar lecturas» para ver el estado de Neon, R2 y Cloudinary.")
        try:
            import zedith
            if not zedith.PRECIO_IN_USD_M and not zedith.PRECIO_OUT_USD_M:
                avisos.append("ZEDITH_PRECIO_IN y ZEDITH_PRECIO_OUT valen 0 en Render: se registran los tokens de la IA, pero su costo siempre sale en $0. Pon el precio por millón de tokens de tu modelo (en USD).")
        except Exception:
            pass
        if any(r["s"].url_estado and r["s"].estado_ultimo is None for r in filas if r["s"].activo):
            avisos.append("Hay servicios con URL de estado que todavía no se han verificado: pulsa «Verificar URLs».")
        bitacora = Auditoria.query.filter_by(entidad="Servicio").order_by(Auditoria.fecha.desc(), Auditoria.id.desc()).limit(10).all()
        return render_template(
            "servicios.html", filas=filas, contador=contador, costos=costos, ia_filas=ia_filas,
            renovaciones=visibles, hay_mas=len(ren) > len(visibles), todas=todas,
            vencidas=sum(1 for r in ren if r["dias"] < 0), siguiente=(proximas[0] if proximas else None),
            avisos=avisos, bitacora=bitacora, proyectos=proyectos, proveedores=PROVEEDORES, categorias=CATEGORIAS,
            periodos=list(PERIODOS), monedas=MONEDAS, fuentes=FUENTES, tc=tc, hay_monitor=monitor is not None,
            alm_edad=_hace(edad) if edad is not None else None,
            mensaje=MENSAJES.get(request.args.get("m", "")))

    @bp.route("/servicios/nuevo", methods=["POST"])
    @solo_admin
    def nuevo():
        asegurar()
        if Servicio.query.count() >= MAX_SERVICIOS:
            return mal(f"el catálogo ya tiene {MAX_SERVICIOS} servicios.")
        d, err = leer_form()
        if err:
            return mal(err)
        s = Servicio(**d, creado_por=current_user.username)
        db.session.add(s)
        db.session.flush()
        registrar("crear_servicio", "Servicio", s.id, detalle(s))
        db.session.commit()
        return redirect(url_for("servicios.index", m="creado"))

    @bp.route("/servicios/<int:sid>/editar", methods=["POST"])
    @solo_admin
    def editar(sid):
        asegurar()
        s = cargar(sid)
        d, err = leer_form()
        if err:
            db.session.rollback()
            return mal(err)
        if (d["url_estado"], d["texto_estado"]) != (s.url_estado, s.texto_estado):
            s.estado_ultimo = s.estado_detalle = s.estado_en = None          # otra URL: el resultado anterior ya no vale
        for k, v in d.items():
            setattr(s, k, v)
        registrar("editar_servicio", "Servicio", s.id, detalle(s))
        db.session.commit()
        return redirect(url_for("servicios.index", m="editado"))

    @bp.route("/servicios/<int:sid>/renovar", methods=["POST"])
    @solo_admin
    def renovar(sid):
        """Registra que se pagó: ultimo_pago = hoy y la próxima fecha avanza un periodo (hasta quedar en el futuro)."""
        asegurar()
        s = cargar(sid)
        hoy, paso = date.today(), PERIODOS.get(s.periodicidad, 1)
        nueva = _sumar_meses(s.proxima_renovacion or hoy, paso)
        for _ in range(1200):
            if nueva > hoy:
                break
            nueva = _sumar_meses(nueva, paso)
        antes = s.proxima_renovacion
        s.ultimo_pago, s.proxima_renovacion = hoy, nueva
        registrar("renovar_servicio", "Servicio", s.id,
                  f"{s.nombre} · {s.moneda} {s.monto or 0:,.2f} · {antes or 'sin fecha'} → {nueva}"[:290])
        db.session.commit()
        return redirect(url_for("servicios.index", m="renovado"))

    @bp.route("/servicios/<int:sid>/activo", methods=["POST"])
    @solo_admin
    def activo(sid):
        asegurar()
        s = cargar(sid)
        s.activo = not s.activo
        registrar("activar_servicio" if s.activo else "pausar_servicio", "Servicio", s.id, detalle(s))
        db.session.commit()
        return redirect(url_for("servicios.index", m="activado" if s.activo else "pausado"))

    @bp.route("/servicios/<int:sid>/eliminar", methods=["POST"])
    @solo_admin
    def eliminar(sid):
        asegurar()
        s = cargar(sid)
        registrar("eliminar_servicio", "Servicio", s.id, detalle(s))
        db.session.delete(s)
        db.session.commit()
        return redirect(url_for("servicios.index", m="eliminado"))

    @bp.route("/servicios/<int:sid>/verificar", methods=["POST"])
    @solo_admin
    def verificar_uno(sid):
        asegurar()
        s = cargar(sid)
        verificar([s])
        db.session.commit()
        return redirect(url_for("servicios.index", m="verificado"))

    @bp.route("/servicios/verificar", methods=["POST"])
    @solo_admin
    def verificar_todos():
        asegurar()
        verificar(Servicio.query.filter(Servicio.activo.is_(True), Servicio.url_estado.isnot(None)).all())
        db.session.commit()
        return redirect(url_for("servicios.index", m="verificado"))

    return bp


# ----------------------------------------------------------------------------------------------------
# CÓMO CONECTARLO EN app.py (cinco cambios pequeños):
#
# 1) Arriba, junto a "import llaves":                import servicios
# 2) Al final, junto a las otras register_blueprint:
#       app.register_blueprint(servicios.crear_blueprint(app, db, registrar, crear_notificacion, Proyecto, CostoServicio, Vencimiento, Auditoria))
# 3) En inicializacion_y_seguridad(), la línea de roles pasa a:
#       startswith(("llaves.", "respaldos.", "servicios."))
# 4) En _vigilante() y en push_revisar(), justo después de llaves.revisar():   servicios.revisar()
# 5) En finanzas(): ver el parche de Finanzas (costos compartidos y proyección de renovaciones).
# ----------------------------------------------------------------------------------------------------
