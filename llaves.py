"""llaves.py — Registro de llaves de API: cifradas, con pool de rotación, uso diario y bitácora.

Se conecta en app.py igual que monitor.py:
    import llaves
    app.register_blueprint(llaves.crear_blueprint(app, db, registrar, crear_notificacion, Proyecto, Auditoria))

Cifrado: ya NO hace falta ninguna variable nueva. Sin LLAVES_MASTER, las llaves se cifran con una clave derivada de
SECRET_KEY (la que ya tienes en Render). Si defines LLAVES_MASTER, esa pasa a ser la principal y lo guardado antes
sigue abriéndose. Opcionales (Render):
    LLAVES_MASTER       clave Fernet principal. Genérala con:
                        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    LLAVES_MASTER_ANT   (opcional) claves anteriores separadas por coma, para rotar la maestra sin perder llaves.
    LLAVES_ENFRIAR_MIN  minutos que una llave descansa tras un error 429 (por defecto 15).
    LLAVES_SIN_MFA=1    (no recomendado) permite administrar llaves sin tener TOTP activado.

Uso desde el resto de la app (dentro de un contexto de aplicación):
    k = llaves.obtener_llave("Anthropic", proyecto_id)          # None si no hay ninguna disponible
    resp = llamar_api(k.secreto)
    if resp.status_code in (401, 403, 429):
        llaves.reportar_fallo(k.id, resp.status_code)            # la saca del pool (429: descansa; 401/403: inválida)
        k = llaves.obtener_llave("Anthropic", proyecto_id)       # y pide la siguiente
    llaves.registrar_uso(k.id, peticiones=1, tokens_in=1200, tokens_out=300, costo=0.012)

El valor completo de una llave NUNCA se muestra ni se escribe en la bitácora: solo los últimos 4 caracteres.
"""
import base64
import hashlib
import os
from collections import namedtuple
from datetime import date, datetime, timedelta
from functools import wraps

from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from flask import Blueprint, render_template, request, redirect, url_for, abort, Response
from flask_login import current_user
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

PROVEEDORES = ["Anthropic", "OpenAI", "Google (Gemini)", "Meta (WhatsApp)", "Cloudinary", "Cloudflare R2",
               "Neon", "Render", "Stripe / procesador de pagos", "PAC / CFDI", "API de plataforma (lectura)", "Otro"]
AMBIENTES = ["Producción", "Pruebas", "Desarrollo"]
ENFRIAR_MIN = int(os.environ.get("LLAVES_ENFRIAR_MIN", "15"))
AVISO_VENCE_DIAS = 14
UMBRAL_USO = 0.80
# Si una plataforma no tiene llave propia de un proveedor, ¿puede usar la global del negocio? Por defecto sí (como siempre).
# Con LLAVES_HEREDAR_GLOBAL=0 cada plataforma usa SOLO las suyas. También se decide por llamada con heredar=True/False.
HEREDAR_GLOBAL = os.environ.get("LLAVES_HEREDAR_GLOBAL", "1") != "0"

LlaveEntregada = namedtuple("LlaveEntregada", "id secreto proveedor etiqueta")

MENSAJES = {
    "creada": "Llave guardada (cifrada). Solo se mostrarán sus últimos 4 caracteres.",
    "api_ok": "API conectada: la llave quedó guardada (cifrada) y se hizo la primera lectura. Abajo ves el resultado.",
    "rotada": "Llave rotada: el valor anterior ya no existe en el sistema.",
    "desactivada": "Llave desactivada al instante.",
    "activada": "Llave activada de nuevo.",
    "revocada": "Llave revocada: el secreto se borró del sistema.",
    "editada": "Datos de la llave actualizados.",
    "movida": "Orden del pool actualizado.",
    "recifrada": "Todas las llaves se volvieron a cifrar con la clave maestra actual.",
}

_api = {}      # lo llena crear_blueprint (misma técnica que monitor.py)
_base_cifrado = {"secreto": None}     # SECRET_KEY de la app (solo si es fija); la pone crear_blueprint


# --- API pública (para el resto de app.py) ------------------------------------------------------
def obtener_llave(proveedor, proyecto_id=None, ambiente="Producción", heredar=None):
    """Primera llave disponible del pool (por orden), o None. Salta las desactivadas, vencidas o en descanso.
    heredar=False: solo las de esa plataforma (nunca las globales). None = lo que diga LLAVES_HEREDAR_GLOBAL."""
    return _api["obtener"](proveedor, proyecto_id, ambiente, heredar)


def obtener_llaves(proveedor, proyecto_id=None, ambiente="Producción", heredar=None):
    """Lista de todas las llaves utilizables, en orden de pool. Útil para probarlas una por una."""
    return _api["todas"](proveedor, proyecto_id, ambiente, heredar)


def reportar_fallo(llave_id, codigo_http):
    """429 → la llave descansa unos minutos; 401/403 → queda inválida hasta que alguien la revise."""
    _api["fallo"](llave_id, codigo_http)


def registrar_uso(llave_id, peticiones=1, tokens_in=0, tokens_out=0, costo=0.0):
    """Suma el consumo del día a la llave y avisa al llegar al 80 % de su límite diario."""
    _api["uso"](llave_id, peticiones, tokens_in, tokens_out, costo)


def costo_mes(proyecto_id=None):
    """Costo de IA del mes en curso (de todas las plataformas, o de una). Para conectarlo a Finanzas."""
    return _api["costo_mes"](proyecto_id)


def estado_pool(proveedor, proyecto_id=None):
    """Resumen del pool de un proveedor (todas las plataformas y ambientes, o solo una), para la pantalla de Servicios:
    {total, usables, invalidas, vencidas, descanso, desactivadas}. Las revocadas no cuentan."""
    return _api["estado_pool"](proveedor, proyecto_id)


def crear_llave(proveedor, proyecto_id, etiqueta, secreto, ambiente="Producción"):
    """Guarda una llave cifrada ligada a una plataforma (la usa conectores.py). Devuelve (id, error)."""
    return _api["crear"](proveedor, proyecto_id, etiqueta, secreto, ambiente)


def panel_plataforma(proyecto_id):
    """Todo lo que necesita la pestaña Conexiones de la ficha: llaves de la plataforma (sin secretos), resumen y avisos."""
    return _api["panel_plat"](proyecto_id)


def resumen_plataforma(proyecto_id):
    """Para la ficha de una plataforma: {total, activas, problemas, por_vencer, heredadas, costo_mes}. Sin secretos."""
    return _api["resumen_plat"](proyecto_id)


def revisar():
    """Para el vigilante de app.py: avisa llaves por vencer, vencidas o con rotación programada pendiente."""
    try:
        _api["revisar"]()
    except Exception:       # nunca debe tumbar al vigilante
        pass


# --- Cifrado ------------------------------------------------------------------------------------
def _fernet():
    """MultiFernet: LLAVES_MASTER primero (si existe), luego las anteriores y, al final, la clave derivada de SECRET_KEY.
    Sin LLAVES_MASTER, la derivada es la principal. None solo si no hay ninguna (local sin SECRET_KEY fija)."""
    claves = []
    principal = (os.environ.get("LLAVES_MASTER") or "").strip()
    anteriores = [k.strip() for k in (os.environ.get("LLAVES_MASTER_ANT") or "").split(",") if k.strip()]
    try:
        claves += [Fernet(k) for k in ([principal] if principal else []) + anteriores]
    except (ValueError, TypeError):
        return None
    base = _base_cifrado["secreto"]
    if base:
        claves.append(Fernet(base64.urlsafe_b64encode(hashlib.sha256(("llaves|" + base).encode()).digest())))
    return MultiFernet(claves) if claves else None


def cifrado_listo():
    return _fernet() is not None


def crear_blueprint(app, db, registrar, avisar, Proyecto, Auditoria):
    bp = Blueprint("llaves", __name__)
    if app.config.get("SECRET_KEY_FIJA", True):          # una SECRET_KEY al azar por arranque no sirve para cifrar lo guardado
        _base_cifrado["secreto"] = str(app.config["SECRET_KEY"])

    class LlaveApi(db.Model):
        __tablename__ = "llave_api"
        id = db.Column(db.Integer, primary_key=True)
        proveedor = db.Column(db.String(40), nullable=False)
        proyecto_id = db.Column(db.Integer, db.ForeignKey("proyecto.id"))      # None = llave global del negocio
        etiqueta = db.Column(db.String(80), nullable=False)
        ambiente = db.Column(db.String(20), default="Producción")
        ultimos4 = db.Column(db.String(4))
        secreto = db.Column(db.Text)                                           # Fernet; None si fue revocada
        creada = db.Column(db.DateTime, default=datetime.utcnow)
        vence = db.Column(db.Date)
        estado = db.Column(db.String(12), default="activa")                    # activa | desactivada | invalida | revocada
        orden = db.Column(db.Integer, default=0)                               # posición en su pool
        bloqueada_hasta = db.Column(db.DateTime)                               # descanso tras un 429
        fallos = db.Column(db.Integer, default=0)
        rotar_cada_dias = db.Column(db.Integer)
        rotada_en = db.Column(db.DateTime)
        creado_por = db.Column(db.String(80))
        limite_peticiones = db.Column(db.Integer)                              # por día
        limite_tokens = db.Column(db.BigInteger)                               # por día
        ultimo_uso = db.Column(db.DateTime)
        proyecto = db.relationship(Proyecto)

    class UsoIA(db.Model):
        __tablename__ = "uso_ia"
        fecha = db.Column(db.Date, primary_key=True)
        llave_id = db.Column(db.Integer, primary_key=True)
        proyecto_id = db.Column(db.Integer)
        proveedor = db.Column(db.String(40))
        peticiones = db.Column(db.Integer, default=0)
        tokens_in = db.Column(db.BigInteger, default=0)
        tokens_out = db.Column(db.BigInteger, default=0)
        costo = db.Column(db.Float, default=0.0)

    estado_tablas = {"ok": False}

    def asegurar():
        if estado_tablas["ok"]:
            return
        for m in (LlaveApi, UsoIA):
            m.__table__.create(db.engine, checkfirst=True)
        estado_tablas["ok"] = True

    # --- reglas de acceso ------------------------------------------------------------------------
    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def mfa_ok():
        return os.environ.get("LLAVES_SIN_MFA") == "1" or bool(getattr(current_user, "totp_activo", False))

    def solo_admin(f):
        @wraps(f)
        def envoltura(*a, **k):
            if not es_admin():
                abort(403)
            return f(*a, **k)
        return envoltura

    def escribe(f):
        """Admin + cifrado configurado + TOTP activo (guardar llaves sin MFA no es aceptable)."""
        @wraps(f)
        @solo_admin
        def envoltura(*a, **k):
            if not mfa_ok():
                return Response("Activa la verificación en dos pasos (TOTP) en Seguridad antes de administrar llaves.", 403)
            return f(*a, **k)
        return envoltura

    def mal(texto):
        return Response(f"Dato no válido: {texto}", 400)

    def plat_activa():
        """La plataforma con la que se trabaja (?plataforma=N en la URL o en el formulario), o None = vista general."""
        raw = request.values.get("plataforma")
        if not raw:
            return None
        p = db.session.get(Proyecto, int(raw)) if raw.isdigit() else None
        if p is None:
            abort(404)
        return p

    def volver(m=None):
        dest = request.form.get("volver") or ""
        if dest.startswith("/plataformas/") and "//" not in dest and "\\" not in dest:
            if m and m in MENSAJES:
                dest += ("&" if "?" in dest else "?") + "m=" + m
            return redirect(dest)
        p = plat_activa()
        return redirect(url_for("llaves.index", m=m, plataforma=p.id if p else None))

    # --- utilidades -------------------------------------------------------------------------------
    def leer_secreto(campo):
        s = (request.form.get(campo) or "").strip()
        if not 8 <= len(s) <= 4000:
            return None, "El valor de la llave debe tener entre 8 y 4000 caracteres."
        if any(c.isspace() for c in s):
            return None, "El valor de la llave no puede llevar espacios ni saltos de línea."
        return s, None

    def leer_fecha(campo):
        v = (request.form.get(campo) or "").strip()
        if not v:
            return None, None
        try:
            return date.fromisoformat(v), None
        except ValueError:
            return None, f"«{campo}» no es una fecha válida."

    def leer_entero(campo, minimo=1, maximo=10**12):
        v = (request.form.get(campo) or "").replace(",", "").strip()
        if not v:
            return None, None
        if not v.isdigit() or not minimo <= int(v) <= maximo:
            return None, f"«{campo}» debe ser un número entero entre {minimo} y {maximo}."
        return int(v), None

    def grupo(k):
        return db.and_(LlaveApi.proveedor == k.proveedor, LlaveApi.ambiente == k.ambiente,
                       LlaveApi.proyecto_id == k.proyecto_id if k.proyecto_id else LlaveApi.proyecto_id.is_(None))

    def estado_visible(k, ahora, hoy):
        if k.estado != "activa":
            return k.estado
        if k.vence and k.vence < hoy:
            return "vencida"
        if k.bloqueada_hasta and k.bloqueada_hasta > ahora:
            return "en descanso"
        return "activa"

    def cifrar(secreto):
        return _fernet().encrypt(secreto.encode()).decode()

    # --- API interna -------------------------------------------------------------------------------
    def _disponibles(proveedor, proyecto_id, ambiente, heredar=None):
        """Todas las llaves utilizables, en orden de pool (las de la plataforma primero; las globales solo si se hereda)."""
        asegurar()
        if heredar is None:
            heredar = HEREDAR_GLOBAL
        f = _fernet()
        if f is None:
            return []
        ahora, hoy = datetime.utcnow(), date.today()

        def buscar(pid):
            q = LlaveApi.query.filter(LlaveApi.proveedor == proveedor, LlaveApi.ambiente == ambiente,
                                      LlaveApi.estado == "activa", LlaveApi.secreto.isnot(None),
                                      or_(LlaveApi.vence.is_(None), LlaveApi.vence >= hoy),
                                      or_(LlaveApi.bloqueada_hasta.is_(None), LlaveApi.bloqueada_hasta <= ahora))
            q = q.filter(LlaveApi.proyecto_id == pid) if pid else q.filter(LlaveApi.proyecto_id.is_(None))
            return q.order_by(LlaveApi.orden, LlaveApi.id).all()

        filas = buscar(proyecto_id) + (buscar(None) if proyecto_id and heredar else [])
        salida = []
        for k in filas:
            try:
                salida.append(LlaveEntregada(k.id, f.decrypt(k.secreto.encode()).decode(), k.proveedor, k.etiqueta))
            except InvalidToken:
                app.logger.error("Llave %s no se pudo descifrar (¿cambió LLAVES_MASTER?)", k.id)
        return salida

    def _obtener(proveedor, proyecto_id, ambiente, heredar=None):
        lista = _disponibles(proveedor, proyecto_id, ambiente, heredar)
        return lista[0] if lista else None

    def _fallo(llave_id, codigo):
        asegurar()
        k = db.session.execute(db.select(LlaveApi).where(LlaveApi.id == llave_id).with_for_update()).scalar_one_or_none()
        if k is None:
            return
        k.fallos = (k.fallos or 0) + 1
        if codigo == 429:
            k.bloqueada_hasta = datetime.utcnow() + timedelta(minutes=ENFRIAR_MIN)
            detalle = f"HTTP 429: descansa {ENFRIAR_MIN} min; el pool pasa a la siguiente"
            urgente = False
        elif codigo in (401, 403):
            k.estado = "invalida"
            detalle = f"HTTP {codigo}: rechazada por el proveedor; fuera del pool hasta revisarla"
            urgente = True
        else:
            db.session.rollback()
            return
        registrar("llave_fallo", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4} · {detalle}")
        db.session.commit()
        avisar("Llave", f"Llave {k.proveedor} · {k.etiqueta}: error {codigo}", detalle, "/llaves",
               urgente=urgente, clave=f"llave-fallo-{k.id}-{codigo}-{datetime.utcnow():%Y%m%d%H}")

    def _uso(llave_id, peticiones, tokens_in, tokens_out, costo):
        asegurar()
        hoy = date.today()
        for _ in range(2):
            try:
                u = db.session.execute(db.select(UsoIA).where(UsoIA.fecha == hoy, UsoIA.llave_id == llave_id).with_for_update()).scalar_one_or_none()
                k = db.session.get(LlaveApi, llave_id)
                if k is None:
                    return
                if u is None:
                    u = UsoIA(fecha=hoy, llave_id=llave_id, proyecto_id=k.proyecto_id, proveedor=k.proveedor,
                              peticiones=0, tokens_in=0, tokens_out=0, costo=0.0)
                    db.session.add(u)
                u.peticiones = (u.peticiones or 0) + int(peticiones)
                u.tokens_in = (u.tokens_in or 0) + int(tokens_in)
                u.tokens_out = (u.tokens_out or 0) + int(tokens_out)
                u.costo = round((u.costo or 0.0) + float(costo), 6)
                k.ultimo_uso = datetime.utcnow()
                db.session.commit()
                break
            except IntegrityError:
                db.session.rollback()       # otro worker creó la fila al mismo tiempo: se reintenta una vez
        else:
            return
        for nombre, usado, limite in (("peticiones", u.peticiones, k.limite_peticiones),
                                      ("tokens", (u.tokens_in or 0) + (u.tokens_out or 0), k.limite_tokens)):
            if limite and usado >= UMBRAL_USO * limite:
                pct = int(usado * 100 / limite)
                avisar("Llave", f"{k.proveedor} · {k.etiqueta}: {pct}% del límite diario de {nombre}",
                       f"{usado:,} de {limite:,} {nombre} hoy.", "/llaves", urgente=pct >= 100,
                       clave=f"llave80-{k.id}-{hoy}-{nombre}-{'100' if pct >= 100 else '80'}")

    def _costo_mes(proyecto_id):
        asegurar()
        ini = date.today().replace(day=1)
        q = db.select(db.func.coalesce(db.func.sum(UsoIA.costo), 0.0)).where(UsoIA.fecha >= ini)
        if proyecto_id:
            q = q.where(UsoIA.proyecto_id == proyecto_id)
        return float(db.session.scalar(q) or 0.0)

    def _estado_pool(proveedor, proyecto_id=None):
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        r = {"total": 0, "usables": 0, "invalidas": 0, "vencidas": 0, "descanso": 0, "desactivadas": 0}
        listo = cifrado_listo()
        q = LlaveApi.query.filter(LlaveApi.proveedor == proveedor, LlaveApi.estado != "revocada")
        if proyecto_id:
            q = q.filter(LlaveApi.proyecto_id == proyecto_id)
        for k in q.all():
            r["total"] += 1
            e = estado_visible(k, ahora, hoy)
            if e == "activa":
                r["usables"] += 1 if (listo and k.secreto) else 0
            elif e == "invalida":
                r["invalidas"] += 1
            elif e == "vencida":
                r["vencidas"] += 1
            elif e == "en descanso":
                r["descanso"] += 1
            else:
                r["desactivadas"] += 1
        return r

    def _resumen_plat(pid):
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        r = {"total": 0, "activas": 0, "problemas": 0, "por_vencer": 0, "heredadas": 0, "costo_mes": _costo_mes(pid)}
        for k in LlaveApi.query.filter(LlaveApi.proyecto_id == pid, LlaveApi.estado != "revocada").all():
            r["total"] += 1
            e = estado_visible(k, ahora, hoy)
            if e == "activa":
                r["activas"] += 1
            elif e in ("invalida", "vencida", "en descanso"):
                r["problemas"] += 1
            if k.estado == "activa" and k.vence and 0 <= (k.vence - hoy).days <= AVISO_VENCE_DIAS:
                r["por_vencer"] += 1
        if HEREDAR_GLOBAL:      # llaves globales que esta plataforma todavía puede usar
            r["heredadas"] = LlaveApi.query.filter(LlaveApi.proyecto_id.is_(None), LlaveApi.estado == "activa").count()
        return r

    def _panel_plat(pid):
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        ks = LlaveApi.query.filter(LlaveApi.proyecto_id == pid).order_by(
            LlaveApi.proveedor, LlaveApi.ambiente, LlaveApi.orden, LlaveApi.id).all()
        uso = {u.llave_id: u for u in UsoIA.query.filter(UsoIA.fecha == hoy, UsoIA.llave_id.in_([k.id for k in ks])).all()} if ks else {}
        filas = [{"id": k.id, "proveedor": k.proveedor, "etiqueta": k.etiqueta, "ambiente": k.ambiente, "ultimos4": k.ultimos4,
                  "estado": estado_visible(k, ahora, hoy), "vence": k.vence,
                  "dias": (k.vence - hoy).days if k.vence else None,
                  "pet": uso[k.id].peticiones if k.id in uso else 0} for k in ks]
        return {"llaves": filas, "resumen": _resumen_plat(pid), "proveedores": PROVEEDORES, "ambientes": AMBIENTES,
                "mfa": mfa_ok(), "cifrado": cifrado_listo(), "heredar": HEREDAR_GLOBAL}

    def _url_llaves(k):
        return f"/llaves?plataforma={k.proyecto_id}" if k.proyecto_id else "/llaves"

    def _revisar():
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        for k in LlaveApi.query.filter(LlaveApi.estado == "activa").all():
            nombre = f"{k.proveedor} · {k.etiqueta}"
            if k.vence:
                dias = (k.vence - hoy).days
                if dias <= AVISO_VENCE_DIAS:
                    titulo = f"Llave vencida: {nombre}" if dias < 0 else f"Llave por vencer en {dias} día(s): {nombre}"
                    avisar("Llave", titulo, "Rótala o renueva la fecha en /llaves.", _url_llaves(k), urgente=dias <= 3,
                           clave=f"llave-vence-{k.id}-{k.vence}-{'v' if dias < 0 else 'p'}")
            if k.rotar_cada_dias:
                base = k.rotada_en or k.creada or ahora
                if base + timedelta(days=k.rotar_cada_dias) <= ahora:
                    avisar("Llave", f"Toca rotar la llave: {nombre}", f"Programada cada {k.rotar_cada_dias} días.", _url_llaves(k),
                           urgente=False, clave=f"llave-rotar-{k.id}-{base:%Y%m%d}")

    def _crear(proveedor, proyecto_id, etiqueta, secreto, ambiente="Producción"):
        if not cifrado_listo():
            return None, "No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER)."
        if proveedor not in PROVEEDORES or ambiente not in AMBIENTES:
            return None, "proveedor o ambiente desconocido."
        etiqueta = (etiqueta or "").strip()
        if not 2 <= len(etiqueta) <= 80:
            return None, "la etiqueta debe tener entre 2 y 80 caracteres."
        secreto = (secreto or "").strip()
        if not 8 <= len(secreto) <= 4000 or any(c.isspace() for c in secreto):
            return None, "La llave debe tener entre 8 y 4000 caracteres y sin espacios."
        ultimo = db.session.scalar(db.select(db.func.max(LlaveApi.orden)).where(
            LlaveApi.proveedor == proveedor, LlaveApi.ambiente == ambiente,
            LlaveApi.proyecto_id == proyecto_id if proyecto_id else LlaveApi.proyecto_id.is_(None)))
        k = LlaveApi(proveedor=proveedor, proyecto_id=proyecto_id, etiqueta=etiqueta, ambiente=ambiente, ultimos4=secreto[-4:],
                     secreto=cifrar(secreto), orden=(ultimo if ultimo is not None else -1) + 1,
                     creado_por=getattr(current_user, "username", None))
        db.session.add(k)
        db.session.flush()
        registrar("crear_llave", "LlaveApi", k.id, f"{proveedor} · {etiqueta} · {ambiente} · ****{k.ultimos4}")
        return k.id, None          # el commit lo hace quien llama (así conector + llave se guardan juntos)

    _api.update(obtener=_obtener, todas=_disponibles, fallo=_fallo, uso=_uso, costo_mes=_costo_mes, revisar=_revisar,
                estado_pool=_estado_pool, resumen_plat=_resumen_plat, panel_plat=_panel_plat, crear=_crear)

    # --- pantallas ------------------------------------------------------------------------------------
    @bp.route("/llaves")
    @solo_admin
    def index():
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        act = plat_activa()
        q = LlaveApi.query
        if act:
            q = q.filter(LlaveApi.proyecto_id == act.id)
        llaves = q.order_by(LlaveApi.proveedor, LlaveApi.proyecto_id, LlaveApi.ambiente, LlaveApi.orden, LlaveApi.id).all()
        uso_hoy = {u.llave_id: u for u in UsoIA.query.filter_by(fecha=hoy).all()}
        filas = []
        for k in llaves:
            u = uso_hoy.get(k.id)
            tokens = ((u.tokens_in or 0) + (u.tokens_out or 0)) if u else 0
            filas.append({
                "k": k, "estado": estado_visible(k, ahora, hoy),
                "dias": (k.vence - hoy).days if k.vence else None,
                "pet": u.peticiones if u else 0, "tok": tokens,
                "pct_pet": int((u.peticiones if u else 0) * 100 / k.limite_peticiones) if k.limite_peticiones else None,
                "pct_tok": int(tokens * 100 / k.limite_tokens) if k.limite_tokens else None,
            })
        ini = hoy.replace(day=1)
        cons = db.select(UsoIA.proyecto_id, UsoIA.proveedor, db.func.sum(UsoIA.peticiones), db.func.sum(UsoIA.tokens_in + UsoIA.tokens_out),
                         db.func.sum(UsoIA.costo)).where(UsoIA.fecha >= ini)
        if act:
            cons = cons.where(UsoIA.proyecto_id == act.id)
        mes = db.session.execute(cons.group_by(UsoIA.proyecto_id, UsoIA.proveedor).order_by(db.func.sum(UsoIA.costo).desc())).all()
        proyectos = Proyecto.query.order_by(Proyecto.nombre).all()
        nombres = {p.id: p.nombre for p in proyectos}
        resumen = {
            "activas": sum(1 for f in filas if f["estado"] == "activa"),
            "por_vencer": sum(1 for f in filas if f["dias"] is not None and 0 <= f["dias"] <= AVISO_VENCE_DIAS and f["k"].estado == "activa"),
            "problemas": sum(1 for f in filas if f["estado"] in ("invalida", "vencida", "en descanso")),
            "costo_mes": sum((m[4] or 0) for m in mes),
        }
        bq = Auditoria.query.filter_by(entidad="LlaveApi")
        if act:
            ids = [f["k"].id for f in filas]
            bq = bq.filter(Auditoria.entidad_id.in_(ids)) if ids else None
        bitacora = bq.order_by(Auditoria.fecha.desc(), Auditoria.id.desc()).limit(15).all() if bq is not None else []
        return render_template("llaves.html", filas=filas, resumen=resumen, mes=mes, nombres=nombres, proyectos=proyectos,
                               proveedores=PROVEEDORES, ambientes=AMBIENTES, bitacora=bitacora,
                               cifrado=cifrado_listo(), mfa=mfa_ok(), enfriar=ENFRIAR_MIN,
                               mensaje=MENSAJES.get(request.args.get("m", "")),
                               act=act, qplat=(f"?plataforma={act.id}" if act else ""))

    @bp.route("/llaves/nueva", methods=["POST"])
    @escribe
    def nueva():
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        proveedor = request.form.get("proveedor", "")
        ambiente = request.form.get("ambiente", "")
        etiqueta = (request.form.get("etiqueta") or "").strip()
        if proveedor not in PROVEEDORES or ambiente not in AMBIENTES:
            return mal("proveedor o ambiente desconocido.")
        if not 2 <= len(etiqueta) <= 80:
            return mal("la etiqueta debe tener entre 2 y 80 caracteres.")
        secreto, err = leer_secreto("secreto")
        if err:
            return mal(err)
        vence, err = leer_fecha("vence")
        if err:
            return mal(err)
        rotar, err = leer_entero("rotar_cada_dias", 1, 3650)
        if err:
            return mal(err)
        lim_p, err = leer_entero("limite_peticiones")
        if err:
            return mal(err)
        lim_t, err = leer_entero("limite_tokens")
        if err:
            return mal(err)
        pid = None
        act = plat_activa()
        if act:
            pid = act.id                      # desde la pantalla de una plataforma NUNCA se crea una llave global
        elif request.form.get("proyecto_id"):
            p = db.session.get(Proyecto, int(request.form["proyecto_id"])) if request.form["proyecto_id"].isdigit() else None
            if p is None:
                return mal("plataforma no encontrada.")
            pid = p.id
        ultimo = db.session.scalar(db.select(db.func.max(LlaveApi.orden)).where(
            LlaveApi.proveedor == proveedor, LlaveApi.ambiente == ambiente,
            LlaveApi.proyecto_id == pid if pid else LlaveApi.proyecto_id.is_(None)))
        k = LlaveApi(proveedor=proveedor, proyecto_id=pid, etiqueta=etiqueta, ambiente=ambiente, ultimos4=secreto[-4:],
                     secreto=cifrar(secreto), vence=vence, orden=(ultimo if ultimo is not None else -1) + 1,
                     rotar_cada_dias=rotar, limite_peticiones=lim_p, limite_tokens=lim_t, creado_por=current_user.username)
        db.session.add(k)
        db.session.flush()
        registrar("crear_llave", "LlaveApi", k.id, f"{proveedor} · {etiqueta} · {ambiente} · ****{k.ultimos4}")
        db.session.commit()
        return volver("creada")

    def cargar(lid):
        k = db.session.execute(db.select(LlaveApi).where(LlaveApi.id == lid).with_for_update()).scalar_one_or_none()
        if k is None:
            abort(404)
        act = plat_activa()
        if act and k.proyecto_id != act.id:        # desde la pantalla de una plataforma solo se tocan SUS llaves
            abort(404)
        return k

    @bp.route("/llaves/<int:lid>/rotar", methods=["POST"])
    @escribe
    def rotar(lid):
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        k = cargar(lid)
        if k.estado == "revocada" and not request.form.get("secreto"):
            return mal("falta el nuevo valor de la llave.")
        secreto, err = leer_secreto("secreto")
        if err:
            return mal(err)
        antes = k.ultimos4
        k.secreto, k.ultimos4 = cifrar(secreto), secreto[-4:]
        k.rotada_en, k.fallos, k.bloqueada_hasta, k.estado = datetime.utcnow(), 0, None, "activa"
        vence, err = leer_fecha("vence")
        if err:
            db.session.rollback()
            return mal(err)
        if request.form.get("vence"):
            k.vence = vence
        registrar("rotar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{antes} → ****{k.ultimos4}")
        db.session.commit()
        return volver("rotada")

    @bp.route("/llaves/<int:lid>/desactivar", methods=["POST"])
    @escribe
    def desactivar(lid):
        asegurar()
        k = cargar(lid)
        if k.estado == "revocada":
            db.session.rollback()
            return volver()
        k.estado = "desactivada"
        registrar("desactivar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("desactivada")

    @bp.route("/llaves/<int:lid>/activar", methods=["POST"])
    @escribe
    def activar(lid):
        asegurar()
        k = cargar(lid)
        if k.estado == "revocada" or not k.secreto:
            db.session.rollback()
            return mal("una llave revocada no se reactiva: rótala con un valor nuevo.")
        k.estado, k.fallos, k.bloqueada_hasta = "activa", 0, None
        registrar("activar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("activada")

    @bp.route("/llaves/<int:lid>/revocar", methods=["POST"])
    @escribe
    def revocar(lid):
        asegurar()
        k = cargar(lid)
        k.estado, k.secreto = "revocada", None          # el secreto se borra de verdad
        registrar("revocar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("revocada")

    @bp.route("/llaves/<int:lid>/editar", methods=["POST"])
    @escribe
    def editar(lid):
        asegurar()
        k = cargar(lid)
        etiqueta = (request.form.get("etiqueta") or "").strip()
        if not 2 <= len(etiqueta) <= 80:
            db.session.rollback()
            return mal("la etiqueta debe tener entre 2 y 80 caracteres.")
        vence, e1 = leer_fecha("vence")
        rotar, e2 = leer_entero("rotar_cada_dias", 1, 3650)
        lim_p, e3 = leer_entero("limite_peticiones")
        lim_t, e4 = leer_entero("limite_tokens")
        if e1 or e2 or e3 or e4:
            db.session.rollback()
            return mal(e1 or e2 or e3 or e4)
        k.etiqueta, k.vence, k.rotar_cada_dias, k.limite_peticiones, k.limite_tokens = etiqueta, vence, rotar, lim_p, lim_t
        registrar("editar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("editada")

    @bp.route("/llaves/<int:lid>/mover", methods=["POST"])
    @escribe
    def mover(lid):
        asegurar()
        k = cargar(lid)
        sube = request.form.get("dir") == "subir"
        hermanas = LlaveApi.query.filter(grupo(k)).order_by(LlaveApi.orden, LlaveApi.id).all()
        for i, h in enumerate(hermanas):          # normaliza 0..n-1 y luego intercambia
            h.orden = i
        i = next(n for n, h in enumerate(hermanas) if h.id == k.id)
        j = i - 1 if sube else i + 1
        if 0 <= j < len(hermanas):
            hermanas[i].orden, hermanas[j].orden = hermanas[j].orden, hermanas[i].orden
            registrar("ordenar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · {'sube' if sube else 'baja'} en el pool")
        db.session.commit()
        return volver("movida")

    @bp.route("/llaves/recifrar", methods=["POST"])
    @escribe
    def recifrar():
        """Tras cambiar LLAVES_MASTER (poniendo la vieja en LLAVES_MASTER_ANT): todo pasa a la clave nueva."""
        asegurar()
        f = _fernet()
        if f is None:
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        n = 0
        for k in LlaveApi.query.filter(LlaveApi.secreto.isnot(None)).with_for_update().all():
            try:
                k.secreto = f.rotate(k.secreto.encode()).decode()
                n += 1
            except InvalidToken:
                db.session.rollback()
                return mal(f"la llave #{k.id} no se pudo descifrar con ninguna clave maestra: no se cambió nada.")
        registrar("recifrar_llaves", "LlaveApi", None, f"{n} llaves re-cifradas con la clave maestra actual")
        db.session.commit()
        return volver("recifrada")

    return bp