"""operaciones.py — Calendario de mantenimientos, centro de alertas y atajos a todos tus servicios.

Qué agrega (todo solo para administradores):
  * /mantenimientos   Calendario de ventanas de mantenimiento de tus proveedores (Render, Neon, Cloudflare...).
                      Avisa 24 h antes y al comenzar. Mientras hay una ventana activa, los avisos «Caído» del Monitor
                      bajan de urgente a aviso normal y llevan la nota de la ventana (no se pierden, solo dejan de gritar).
  * Centro de alertas Agrupa avisos repetidos, separa Críticas / Avisos / Sin leer y permite SILENCIAR un tipo de aviso
                      por 1, 4, 8 o 24 horas. Un aviso silenciado queda en el historial (marcado como leído) pero no manda push.
  * /atajos           Un solo lugar con enlaces a la consola de cada servicio que usas, tus plataformas y sus repositorios.

Se conecta en app.py (ver LEEME_MEJORAS.txt):
    import operaciones
    app.register_blueprint(operaciones.crear_blueprint(app, db, registrar, crear_notificacion, Proyecto))

Zona horaria: las fechas se guardan en UTC y se muestran/capturan en hora local. Por defecto UTC-6 (centro de México, sin
horario de verano). Cambia con la variable de entorno PANEL_UTC_OFFSET (por ejemplo -5).
"""
import os
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint, Response, abort, redirect, render_template, request, url_for
from flask_login import current_user

try:
    UTC_OFFSET = int(os.environ.get("PANEL_UTC_OFFSET", "-6") or -6)
except ValueError:
    UTC_OFFSET = -6

PROVEEDORES = ["Render", "Neon", "Cloudflare", "GitHub", "Google (Gemini)", "Meta (WhatsApp)", "Cloudinary", "UptimeRobot", "Otro"]
HORAS_SILENCIO = (1, 4, 8, 24)
MAX_SILENCIO_H = 24
MAX_MANTENIMIENTOS = 500

# Consola de cada proveedor, para los atajos (se usa si el servicio del catálogo no trae su propio enlace).
CONSOLAS = {
    "Render": "https://dashboard.render.com",
    "Neon": "https://console.neon.tech",
    "Cloudflare R2": "https://dash.cloudflare.com",
    "Cloudflare": "https://dash.cloudflare.com",
    "Cloudinary": "https://console.cloudinary.com",
    "Meta (WhatsApp)": "https://developers.facebook.com/apps",
    "Google (Gemini)": "https://aistudio.google.com/apikey",
    "Anthropic": "https://console.anthropic.com",
    "OpenAI": "https://platform.openai.com",
    "UptimeRobot": "https://dashboard.uptimerobot.com",
    "GitHub": "https://github.com",
    "Stripe / procesador de pagos": "https://dashboard.stripe.com",
}
ESTADO_ESTATUS = {      # páginas públicas de estado de cada proveedor
    "Render": "https://status.render.com",
    "Neon": "https://neonstatus.com",
    "Cloudflare R2": "https://www.cloudflarestatus.com",
    "Cloudflare": "https://www.cloudflarestatus.com",
    "GitHub": "https://www.githubstatus.com",
}

_api = {}      # lo llena crear_blueprint (misma técnica que servicios.py y llaves.py)


# --- utilidades de fecha y enlaces --------------------------------------------------------------------
def a_utc(local):
    return local - timedelta(hours=UTC_OFFSET)


def a_local(utc):
    return utc + timedelta(hours=UTC_OFFSET) if utc else None


def enlace_seguro(url):
    """Solo http/https con dominio; todo lo demás (javascript:, data:, vacío) se descarta."""
    try:
        u = urlsplit((url or "").strip())
    except ValueError:
        return ""
    return u.geturl() if u.scheme in ("http", "https") and u.netloc else ""


def agrupar(filas):
    """Junta avisos repetidos (mismo tipo y título) en una sola fila.

    `filas` viene ordenada de la más nueva a la más vieja. Devuelve lista de dicts
    {n: el más reciente, veces, sin_leer, urgente, primera}, con las críticas sin leer primero,
    luego avisos sin leer y al final lo ya leído (cada bloque, de lo más nuevo a lo más viejo).
    """
    grupos, orden = {}, []
    for n in filas:
        k = (n.tipo or "", n.titulo or "")
        g = grupos.get(k)
        if g is None:
            g = grupos[k] = {"n": n, "veces": 0, "sin_leer": 0, "urgente": False, "primera": n.hora}
            orden.append(k)
        g["veces"] += 1
        g["sin_leer"] += 0 if n.leida else 1
        g["urgente"] = g["urgente"] or bool(n.urgente)
        g["primera"] = n.hora
    lista = [grupos[k] for k in orden]

    def rango(g):
        if g["sin_leer"] and g["urgente"]:
            return 0
        return 1 if g["sin_leer"] else 2
    lista.sort(key=rango)           # estable: dentro de cada bloque se conserva el orden por fecha
    return lista


# --- API pública (para app.py) -------------------------------------------------------------------------
def silenciado(tipo):
    """True si ese tipo de aviso está silenciado ahora. Nunca lanza error."""
    f = _api.get("silenciado")
    try:
        return bool(f and f(tipo))
    except Exception:
        return False


def mantenimiento_activo(ahora=None):
    """La ventana de mantenimiento en curso como dict {proveedor, titulo, fin_local} o None."""
    f = _api.get("activo")
    try:
        return f(ahora) if f else None
    except Exception:
        return None


def revisar():
    """Para el vigilante (push_revisar): avisa 24 h antes y al comenzar cada ventana."""
    f = _api.get("revisar")
    try:
        return f() if f else 0
    except Exception:
        return 0


# --- blueprint -----------------------------------------------------------------------------------------
def crear_blueprint(app, db, registrar, avisar, Proyecto):
    bp = Blueprint("operaciones", __name__)

    class Mantenimiento(db.Model):
        __tablename__ = "mantenimiento"
        id = db.Column(db.Integer, primary_key=True)
        proveedor = db.Column(db.String(40), nullable=False)
        titulo = db.Column(db.String(200), nullable=False)
        inicio = db.Column(db.DateTime, nullable=False)        # UTC
        fin = db.Column(db.DateTime, nullable=False)           # UTC
        afecta = db.Column(db.String(200))
        notas = db.Column(db.String(300))
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        creado_por = db.Column(db.String(80))

    class Silencio(db.Model):
        __tablename__ = "silencio_aviso"
        tipo = db.Column(db.String(30), primary_key=True)
        hasta = db.Column(db.DateTime, nullable=False)         # UTC
        creado_por = db.Column(db.String(80))

    estado = {"ok": False}

    def asegurar():
        if estado["ok"]:
            return
        Mantenimiento.__table__.create(db.engine, checkfirst=True)
        Silencio.__table__.create(db.engine, checkfirst=True)
        estado["ok"] = True

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

    # --- lógica reutilizable ---
    def _silenciado(tipo):
        asegurar()
        s = db.session.get(Silencio, (tipo or "")[:30])
        return bool(s and s.hasta > datetime.utcnow())

    def _activo(ahora=None):
        asegurar()
        ahora = ahora or datetime.utcnow()
        m = (Mantenimiento.query.filter(Mantenimiento.inicio <= ahora, Mantenimiento.fin > ahora)
             .order_by(Mantenimiento.fin).first())
        return {"proveedor": m.proveedor, "titulo": m.titulo, "fin_local": a_local(m.fin)} if m else None

    def _revisar():
        asegurar()
        ahora, n = datetime.utcnow(), 0
        for m in Mantenimiento.query.filter(Mantenimiento.fin > ahora, Mantenimiento.inicio <= ahora + timedelta(hours=24)).all():
            ini = a_local(m.inicio).strftime("%d/%m %H:%M")
            if m.inicio > ahora:
                r = avisar("Mantenimiento", f"Mantenimiento de {m.proveedor} en menos de 24 h",
                           f"{m.titulo} · {ini} (hora local) · {m.afecta or 'Puede haber reinicios o cortes breves'}",
                           "/mantenimientos", urgente=False, clave=f"mant-{m.id}-previo")
            else:
                r = avisar("Mantenimiento", f"Comenzó el mantenimiento de {m.proveedor}",
                           f"{m.titulo} · termina aprox. {a_local(m.fin).strftime('%d/%m %H:%M')} (hora local). "
                           "Si algo cae durante la ventana, puede ser por esto.",
                           "/mantenimientos", urgente=False, clave=f"mant-{m.id}-inicio")
            n += 1 if r else 0
        return n

    _api.update(silenciado=_silenciado, activo=_activo, revisar=_revisar)

    # --- mantenimientos -------------------------------------------------------------------------------
    def leer_fecha(campo):
        v = (request.form.get(campo) or "").strip()
        try:
            return a_utc(datetime.strptime(v, "%Y-%m-%dT%H:%M")), None
        except ValueError:
            return None, f"«{campo}» no es una fecha y hora válida."

    @bp.route("/mantenimientos")
    @solo_admin
    def mantenimientos():
        asegurar()
        ahora = datetime.utcnow()
        todos = Mantenimiento.query.order_by(Mantenimiento.inicio.desc()).limit(MAX_MANTENIMIENTOS).all()
        en_curso = [m for m in todos if m.inicio <= ahora < m.fin]
        proximos = sorted([m for m in todos if m.inicio > ahora], key=lambda m: m.inicio)
        pasados = [m for m in todos if m.fin <= ahora][:15]
        pre = {k: (request.args.get(k) or "")[:200] for k in ("proveedor", "titulo", "inicio", "fin", "afecta")}
        return render_template("mantenimientos.html", en_curso=en_curso, proximos=proximos, pasados=pasados,
                               proveedores=PROVEEDORES, a_local=a_local, pre=pre, utc_offset=UTC_OFFSET,
                               estatus=ESTADO_ESTATUS, mensaje=request.args.get("m", ""))

    @bp.route("/mantenimientos/nuevo", methods=["POST"])
    @solo_admin
    def mantenimiento_nuevo():
        asegurar()
        prov = (request.form.get("proveedor") or "").strip()[:40]
        titulo = (request.form.get("titulo") or "").strip()[:200]
        if prov not in PROVEEDORES or not titulo:
            return mal("elige un proveedor y escribe un título.")
        ini, e1 = leer_fecha("inicio")
        fin, e2 = leer_fecha("fin")
        if e1 or e2:
            return mal(e1 or e2)
        if fin <= ini:
            return mal("el fin debe ser después del inicio.")
        if fin - ini > timedelta(days=14):
            return mal("una ventana no puede durar más de 14 días.")
        if Mantenimiento.query.count() >= MAX_MANTENIMIENTOS:
            return mal("hay demasiados registros; elimina los viejos.")
        m = Mantenimiento(proveedor=prov, titulo=titulo, inicio=ini, fin=fin,
                          afecta=(request.form.get("afecta") or "").strip()[:200] or None,
                          notas=(request.form.get("notas") or "").strip()[:300] or None,
                          creado_por=getattr(current_user, "username", None))
        db.session.add(m)
        db.session.flush()
        registrar("Crear", "Mantenimiento", m.id, f"{prov}: {titulo}")
        db.session.commit()
        return redirect(url_for("operaciones.mantenimientos", m="creado"))

    @bp.route("/mantenimientos/<int:mid>/eliminar", methods=["POST"])
    @solo_admin
    def mantenimiento_eliminar(mid):
        asegurar()
        m = db.session.get(Mantenimiento, mid)
        if m is None:
            abort(404)
        registrar("Eliminar", "Mantenimiento", m.id, f"{m.proveedor}: {m.titulo}")
        db.session.delete(m)
        db.session.commit()
        return redirect(url_for("operaciones.mantenimientos", m="eliminado"))

    # --- silencios de avisos ----------------------------------------------------------------------------
    @bp.route("/notificaciones/silenciar", methods=["POST"])
    @solo_admin
    def silenciar():
        asegurar()
        tipo = (request.form.get("tipo") or "").strip()[:30]
        try:
            horas = int(request.form.get("horas") or 0)
        except ValueError:
            horas = 0
        if not tipo or horas not in HORAS_SILENCIO:
            return mal("elige un tipo de aviso y un tiempo de la lista.")
        horas = min(horas, MAX_SILENCIO_H)
        hasta = datetime.utcnow() + timedelta(hours=horas)
        s = db.session.get(Silencio, tipo)
        if s is None:
            s = Silencio(tipo=tipo, hasta=hasta)
            db.session.add(s)
        s.hasta, s.creado_por = hasta, getattr(current_user, "username", None)
        registrar("Silenciar", "Aviso", None, f"{tipo} por {horas} h")
        db.session.commit()
        return redirect(url_for("notificaciones"))

    @bp.route("/notificaciones/silencio/quitar", methods=["POST"])
    @solo_admin
    def quitar_silencio():
        asegurar()
        s = db.session.get(Silencio, (request.form.get("tipo") or "")[:30])
        if s is not None:
            registrar("Quitar silencio", "Aviso", None, s.tipo)
            db.session.delete(s)
            db.session.commit()
        return redirect(url_for("notificaciones"))

    def silencios_activos():
        asegurar()
        ahora = datetime.utcnow()
        return [{"tipo": s.tipo, "hasta": a_local(s.hasta)} for s in
                Silencio.query.filter(Silencio.hasta > ahora).order_by(Silencio.hasta).all()]

    _api["silencios_activos"] = silencios_activos

    # --- atajos ------------------------------------------------------------------------------------------
    def _catalogo():
        """Servicios del catálogo (tabla `servicio` de servicios.py) sin acoplarse a su modelo."""
        try:
            filas = db.session.execute(db.text(
                "SELECT nombre, proveedor, categoria, url_panel, activo FROM servicio ORDER BY categoria, nombre")).all()
        except Exception:
            db.session.rollback()
            return []
        return [{"nombre": f[0], "proveedor": f[1] or "", "categoria": f[2] or "Otro",
                 "url": enlace_seguro(f[3]) or CONSOLAS.get(f[1] or "", ""), "activo": bool(f[4])} for f in filas]

    @bp.route("/atajos")
    @solo_admin
    def atajos():
        servicios = [s for s in _catalogo() if s["activo"]]
        grupos = {}
        for s in servicios:
            grupos.setdefault(s["categoria"], []).append(s)
        con_catalogo = {s["proveedor"] for s in servicios}
        faltan = [{"proveedor": p, "url": u} for p, u in CONSOLAS.items()
                  if p not in con_catalogo and p != "Cloudflare"]
        plataformas = []
        for p in Proyecto.query.filter_by(tipo="Plataforma propia").order_by(Proyecto.nombre).all():
            plataformas.append({"id": p.id, "nombre": p.nombre, "sitio": enlace_seguro(p.url_produccion),
                                "repo": enlace_seguro(p.repo_url), "stack": p.stack or ""})
        return render_template("atajos.html", grupos=grupos, faltan=faltan, plataformas=plataformas,
                               estatus=ESTADO_ESTATUS, total=len(servicios))

    return bp
