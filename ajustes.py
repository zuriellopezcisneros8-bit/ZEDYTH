"""ajustes.py — Llaves y configuración editables desde la pantalla (/conexiones), sin entrar a Render.

Cómo funciona
  • Cada valor se guarda CIFRADO (Fernet) en la tabla `ajuste_sistema` de tu base (Neon).
  • El cifrado usa SECRET_KEY, que ya tienes en Render: no hace falta ninguna variable nueva.
  • Todo el sistema lee con  ajustes.valor("NOMBRE")  → primero lo guardado en la pantalla; si no hay nada,
    la variable de entorno de Render (así lo que ya tienes en Render sigue funcionando); si tampoco, el defecto.
  • Un valor nunca se vuelve a mostrar completo: solo los últimos 4 caracteres de los secretos.

Lo único que sigue en Render (no puede vivir en la base que desbloquea): DATABASE_URL, SECRET_KEY, ADMIN_PASSWORD.

Se conecta en app.py:
    import ajustes
    ajustes.iniciar(app, db)                                   # justo después de  db = SQLAlchemy(app)
    app.register_blueprint(ajustes.crear_blueprint(registrar, vapid_diagnostico))
"""
import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from datetime import date, datetime
from functools import wraps

from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

TTL = 120           # segundos que cada proceso reutiliza lo leído de la base: así no se despierta a Neon en cada visita.
                    # Quien guarda lo ve al instante; otros procesos del servidor se enteran en ≤ TTL.

_e = {"app": None, "db": None, "modelo": None, "cache": {}, "t": 0.0, "tabla": False, "ilegibles": 0}
_lock = threading.Lock()


# --- Catálogo: qué se puede configurar desde la pantalla -------------------------------------------------------
def _c(nombre, etiqueta, secreto=False, ayuda="", ejemplo="", multilinea=False, validar=None, generar=None):
    return {"nombre": nombre, "etiqueta": etiqueta, "secreto": secreto, "ayuda": ayuda, "ejemplo": ejemplo,
            "multilinea": multilinea, "validar": validar, "generar": generar}


GRUPOS = [
    {"clave": "ia", "titulo": "Inteligencia artificial (ZEDITH · Gemini)", "icono": "ph-sparkle", "prueba": "gemini",
     "intro": "El chat de ZEDITH usa llaves de Gemini. Pon una o varias (una por línea): si una se agota o falla, "
              "pasa sola a la siguiente. Para llaves por plataforma o con límites diarios usa la sección Llaves.",
     "donde": ("Consíguelas gratis en aistudio.google.com/apikey (botón «Create API key»).",),
     "campos": [
         _c("GEMINI_API_KEYS", "Llaves de Gemini", True, "Una por línea (o separadas por coma).",
            "AIza…", multilinea=True, validar="gemini"),
         _c("GEMINI_MODEL", "Modelo", False, "Déjalo vacío para usar el modelo por defecto.", "gemini-3.5-flash-lite", validar="modelo"),
         _c("ZEDITH_PRECIO_IN", "Precio por millón de tokens de entrada (USD)", False,
            "Solo para calcular el costo en Llaves. 0 = no calcular.", "0.10", validar="decimal"),
         _c("ZEDITH_PRECIO_OUT", "Precio por millón de tokens de salida (USD)", False, "", "0.40", validar="decimal"),
         _c("ZEDITH_CUPO_MES", "Cupos de desarrollo que te quedan este mes", False,
            "Número REAL. 0 = agenda llena. Vacío = ZEDITH no menciona cupos.", "3", validar="entero"),
         _c("ZEDITH_PROMO", "Promoción vigente (texto)", False, "Solo escribe una promoción REAL.", "10% en tu primer sistema", validar="texto200"),
         _c("ZEDITH_PROMO_HASTA", "La promoción vence el", False, "Formato AAAA-MM-DD.", "2026-12-31", validar="fecha"),
     ]},
    {"clave": "avisos", "titulo": "Avisos al celular y al correo", "icono": "ph-bell-ringing", "prueba": "avisos",
     "intro": "Cuando entra un pedido o hay una alerta, el sistema te avisa por Telegram y/o correo. Los dos son opcionales.",
     "donde": ("Telegram: habla con @BotFather, crea un bot con /newbot y copia el token. Para el chat id, escríbele "
               "a tu bot y abre api.telegram.org/bot<TOKEN>/getUpdates: ahí sale «chat»: «id».",
               "Correo (Gmail): activa la verificación en dos pasos y crea una «contraseña de aplicación» en "
               "myaccount.google.com/apppasswords. No uses tu contraseña normal."),
     "campos": [
         _c("TELEGRAM_BOT_TOKEN", "Telegram · token del bot", True, "", "123456789:AAH…", validar="telegram_token"),
         _c("TELEGRAM_CHAT_ID", "Telegram · chat id", False, "", "123456789", validar="telegram_chat"),
         _c("SMTP_USER", "Correo · usuario que envía", False, "", "tucorreo@gmail.com", validar="correo"),
         _c("SMTP_PASS", "Correo · contraseña de aplicación", True, "Se aceptan los espacios; se quitan solos.", "abcd efgh ijkl mnop", validar="smtp_pass"),
         _c("AVISO_EMAIL", "Correo · a quién le llega", False, "Vacío = al mismo usuario que envía.", "", validar="correo"),
         _c("SMTP_HOST", "Correo · servidor", False, "Vacío = smtp.gmail.com.", "smtp.gmail.com", validar="host"),
         _c("SMTP_PORT", "Correo · puerto (SSL)", False, "Vacío = 465.", "465", validar="puerto"),
     ]},
    {"clave": "push", "titulo": "Alertas push en el celular (VAPID)", "icono": "ph-device-mobile", "prueba": "vapid",
     "intro": "Son el par de llaves que permite mandar alertas a los dispositivos. Si no tienes un par, genéralo con el "
              "botón: se guardan las dos, cifradas, sin que veas ni copies nada. Si cambias el par, hay que volver a "
              "activar las alertas en cada dispositivo.",
     "donde": (), "generar_par": "VAPID",
     "campos": [
         _c("VAPID_PUBLIC_KEY", "Llave pública", False, "Unos 87 caracteres.", "", validar="vapid_pub"),
         _c("VAPID_PRIVATE_KEY", "Llave privada", True, "Unos 43 caracteres.", "", validar="vapid_priv"),
         _c("VAPID_CONTACT", "Contacto", False, "mailto:tucorreo@… (vacío = el de la empresa).", "mailto:tucorreo@gmail.com", validar="contacto"),
     ]},
    {"clave": "respaldos", "titulo": "Respaldos automáticos (Cloudflare R2)", "icono": "ph-cloud-arrow-up", "prueba": "r2",
     "intro": "Para los respaldos crea un bucket SOLO para eso y un token de R2 exclusivo (Object Read & Write sobre ese bucket). "
              "No reutilices el de las imágenes.",
     "donde": ("Cloudflare → R2 → Manage API tokens → Create API token. Ahí salen el Access Key ID y el Secret Access Key "
               "(el secreto solo se muestra una vez). El Account ID aparece en la página principal de R2.",),
     "campos": [
         _c("BACKUP_R2_ACCOUNT_ID", "Account ID", False, "", "", validar="r2_cuenta"),
         _c("BACKUP_R2_ACCESS_KEY_ID", "Access Key ID", True, "", "", validar="r2_id"),
         _c("BACKUP_R2_SECRET_ACCESS_KEY", "Secret Access Key", True, "", "", validar="r2_secreto"),
         _c("BACKUP_R2_BUCKET", "Bucket", False, "", "respaldos-zedyth", validar="bucket"),
         _c("BACKUP_R2_PREFIJO", "Carpeta dentro del bucket", False, "Vacío = panel/", "panel/", validar="prefijo"),
         _c("BACKUP_KEY", "Clave para cifrar los respaldos", True,
            "Sin ella los respaldos NO se cifran. Genérala con el botón y GUÁRDALA en tu gestor de contraseñas: "
            "sin esta clave no se pueden restaurar.", "", validar="fernet", generar="fernet"),
         _c("BACKUP_DATABASE_URL", "Cadena de conexión para respaldar (opcional)", True,
            "Solo si quieres respaldar con otro usuario distinto al de la app. Empieza con postgresql://", "", validar="url_pg"),
     ]},
    {"clave": "render", "titulo": "Render (hosting de tus plataformas)", "icono": "ph-rocket-launch", "prueba": "render",
     "intro": "Con la llave, el panel lee tus servicios de Render: estado, plan y último deploy, y te avisa si un deploy falla o un servicio se suspende. "
              "Una llave ve todos los workspaces de su usuario; si tus plataformas están en usuarios distintos de Render, usa una llave por usuario (hasta 5). "
              "Estas son las llaves GENERALES: cada plataforma puede tener la suya en su ficha → Conexiones.",
     "donde": ("Render → Account Settings → API Keys → Create API Key. Cópiala al crearla. Es una llave de toda tu cuenta: guárdala solo aquí.",),
     "campos": [
         _c("RENDER_API_KEY", "Llave de Render · usuario 1", True, "", "rnd_…", validar="render_key"),
         _c("RENDER_API_KEY_2", "Llave de Render · usuario 2 (opcional)", True, "", "rnd_…", validar="render_key"),
         _c("RENDER_API_KEY_3", "Llave de Render · usuario 3 (opcional)", True, "", "rnd_…", validar="render_key"),
         _c("RENDER_API_KEY_4", "Llave de Render · usuario 4 (opcional)", True, "", "rnd_…", validar="render_key"),
         _c("RENDER_API_KEY_5", "Llave de Render · usuario 5 (opcional)", True, "", "rnd_…", validar="render_key"),
     ]},
    {"clave": "sitio", "titulo": "Sitio público y tareas programadas", "icono": "ph-globe", "prueba": None,
     "intro": "Datos opcionales de la página pública y el token del cron externo (por ejemplo cron-job.org).",
     "donde": ("El cron llama a  https://TU-SITIO/api/push/revisar?token=TU_TOKEN  cada 5 minutos para mantener despierto "
               "el servidor y revisar alertas. Genera el token con el botón y cópialo en ese momento (solo se muestra una vez).",),
     "campos": [
         _c("SITE_URL", "Dirección pública del sitio", False, "Con https://", "https://zedyth.onrender.com", validar="url_sitio"),
         _c("GA_ID", "Google Analytics (ID)", False, "", "G-XXXXXXXXXX", validar="ga"),
         _c("AGENDA_URL", "Enlace para agendar llamadas", False, "Debe empezar con https://", "https://calendly.com/…", validar="url_https"),
         _c("CRON_TOKEN", "Token del cron externo", True, "", "", validar="token", generar="token"),
     ]},
]
CAMPOS = {c["nombre"]: c for g in GRUPOS for c in g["campos"]}
GRUPO_DE = {c["nombre"]: g["clave"] for g in GRUPOS for c in g["campos"]}
POR_CLAVE = {g["clave"]: g for g in GRUPOS}


# --- Cifrado ------------------------------------------------------------------------------------------------------
def _fernet():
    app = _e["app"]
    base = str(app.config["SECRET_KEY"]) if app else ""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("ajustes|" + base).encode()).digest()))


def clave_fija():
    """False solo en local sin SECRET_KEY: la clave cambia en cada arranque y lo guardado no se podría leer después."""
    app = _e["app"]
    return bool(app and app.config.get("SECRET_KEY_FIJA", True))


# --- Lectura (lo usan todos los módulos) --------------------------------------------------------------------------
def _cargar():
    """Lee y descifra todo lo guardado. Usa una conexión propia para no tocar la transacción de quien llama."""
    app, db = _e["app"], _e["db"]
    with app.app_context():
        if not _e["tabla"]:
            _e["modelo"].__table__.create(db.engine, checkfirst=True)
            _e["tabla"] = True
        with db.engine.connect() as con:
            filas = con.execute(db.text("SELECT nombre, valor FROM ajuste_sistema")).all()
        f, nuevas, malas = _fernet(), {}, 0
        for nombre, valor in filas:
            if nombre not in CAMPOS:
                continue
            try:
                nuevas[nombre] = f.decrypt(valor.encode()).decode()
            except (InvalidToken, ValueError):          # SECRET_KEY cambió o el dato se dañó
                malas += 1
        return nuevas, malas


def refrescar(forzar=False):
    if _e["app"] is None:
        return _e["cache"]
    if not forzar and time.time() - _e["t"] < TTL:
        return _e["cache"]
    with _lock:
        if not forzar and time.time() - _e["t"] < TTL:
            return _e["cache"]
        try:
            _e["cache"], _e["ilegibles"] = _cargar()
            _e["t"] = time.time()
        except Exception as ex:                          # la base dormida o caída no debe tumbar a quien pregunta
            _e["t"] = time.time() - TTL + 15            # reintenta en 15 s y mientras tanto usa lo último que se leyó
            try:
                _e["app"].logger.warning("Ajustes: no se pudo leer la base (%s)", ex)
            except Exception:
                pass
    return _e["cache"]


def valor(nombre, defecto=""):
    """Pantalla → variable de entorno (Render) → defecto. Siempre texto sin espacios en los extremos."""
    v = (refrescar().get(nombre) or "").strip()
    if v:
        return v
    return (os.environ.get(nombre) or "").strip() or defecto


def origen(nombre):
    """'panel' si se guardó desde la pantalla, 'entorno' si viene de Render, None si no existe."""
    if (refrescar().get(nombre) or "").strip():
        return "panel"
    if (os.environ.get(nombre) or "").strip():
        return "entorno"
    if nombre == "GEMINI_API_KEYS" and any(k.startswith("GEMINI_") and v.strip() for k, v in os.environ.items()):
        return "entorno"
    return None


# --- Validación de lo que se pega -----------------------------------------------------------------------------------
def _limpiar_llave(v):
    v = (v or "").strip().strip("\"'").strip()
    for pref in ("VAPID_PRIVATE_KEY=", "VAPID_PUBLIC_KEY="):
        if v.startswith(pref):
            v = v[len(pref):].strip().strip("\"'")
    return "".join(v.split())


def _b64u(t):
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def par_vapid_valido(pub, priv):
    """None si el par está bien; si no, un texto que dice qué corregir."""
    try:
        raw_priv = _b64u(priv)
        raw_pub = _b64u(pub)
    except Exception:
        return "Las llaves VAPID deben ser solo la cadena (sin comillas, sin «NOMBRE=» y sin espacios)."
    if len(raw_priv) != 32:
        return f"La llave privada VAPID mide {len(raw_priv)} bytes y debe medir 32 (unos 43 caracteres)."
    if len(raw_pub) != 65 or raw_pub[0] != 4:
        return f"La llave pública VAPID mide {len(raw_pub)} bytes y debe medir 65 (unos 87 caracteres)."
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        llave = ec.derive_private_key(int.from_bytes(raw_priv, "big"), ec.SECP256R1())
        esperada = llave.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    except Exception:
        return "La llave privada VAPID no es una llave EC P-256 válida."
    if esperada != raw_pub:
        return "La llave pública y la privada VAPID no son pareja: deben venir del mismo par."
    return None


def generar_par_vapid():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    k = ec.generate_private_key(ec.SECP256R1())
    return (b(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
            b(k.private_numbers().private_value.to_bytes(32, "big")))


_RE = {
    "correo": re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$"),
    "host": re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"),
    "telegram_token": re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,60}$"),
    "telegram_chat": re.compile(r"^(-?\d{5,20}|@[A-Za-z0-9_]{4,60})$"),
    "modelo": re.compile(r"^[A-Za-z0-9._-]{3,80}$"),
    "ga": re.compile(r"^[A-Za-z0-9-]{4,30}$"),
    "r2_cuenta": re.compile(r"^[A-Za-z0-9]{16,64}$"),
    "r2_id": re.compile(r"^[A-Za-z0-9]{16,64}$"),
    "r2_secreto": re.compile(r"^[A-Za-z0-9/+=_-]{32,128}$"),
    "bucket": re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"),
    "prefijo": re.compile(r"^[A-Za-z0-9_./-]{0,60}$"),
    "token": re.compile(r"^[A-Za-z0-9_-]{24,100}$"),
    "render_key": re.compile(r"^[A-Za-z0-9_-]{20,120}$"),
}


def validar(campo, v):
    """(valor_limpio, None) o (None, mensaje). Nunca incluye el valor en el mensaje."""
    tipo, nombre = campo["validar"], campo["etiqueta"]
    if tipo == "gemini":
        llaves = [k.strip().strip("\"'") for k in re.split(r"[,\s]+", v) if k.strip()]
        if not llaves:
            return None, f"{nombre}: pega al menos una llave."
        for k in llaves:
            if not re.fullmatch(r"[A-Za-z0-9_-]{20,120}", k):
                return None, f"{nombre}: una de las llaves no tiene el formato de Gemini (letras, números, - y _; unos 39 caracteres)."
        return "\n".join(dict.fromkeys(llaves)), None
    if tipo == "smtp_pass":
        v = v.replace(" ", "")
        return (v, None) if 8 <= len(v) <= 100 else (None, f"{nombre}: debe tener entre 8 y 100 caracteres.")
    if tipo in ("vapid_pub", "vapid_priv"):
        v = _limpiar_llave(v)
        return (v, None) if v else (None, f"{nombre}: viene vacía.")
    if tipo == "contacto":
        return (v, None) if re.fullmatch(r"(mailto:[^@\s]+@[^@\s]+\.[^@\s]+|https://\S+)", v) else (None, f"{nombre}: debe empezar con mailto: o https://")
    if tipo == "decimal":
        try:
            n = float(v.replace(",", "."))
        except ValueError:
            return None, f"{nombre}: debe ser un número."
        return (str(n), None) if 0 <= n <= 100000 else (None, f"{nombre}: fuera de rango.")
    if tipo == "entero":
        return (v, None) if v.isdigit() and int(v) <= 100000 else (None, f"{nombre}: debe ser un número entero.")
    if tipo == "puerto":
        return (v, None) if v.isdigit() and 1 <= int(v) <= 65535 else (None, f"{nombre}: debe ser un puerto entre 1 y 65535.")
    if tipo == "texto200":
        return (v, None) if len(v) <= 200 else (None, f"{nombre}: máximo 200 caracteres.")
    if tipo == "fecha":
        try:
            date.fromisoformat(v)
        except ValueError:
            return None, f"{nombre}: usa el formato AAAA-MM-DD."
        return v, None
    if tipo == "fernet":
        try:
            Fernet(v.encode())
        except Exception:
            return None, f"{nombre}: no es una clave válida. Usa el botón «Generar» para crear una."
        return v, None
    if tipo == "url_pg":
        return (v, None) if v.startswith(("postgresql://", "postgres://")) else (None, f"{nombre}: debe empezar con postgresql://")
    if tipo == "url_https":
        return (v, None) if re.fullmatch(r"https://\S{4,300}", v) else (None, f"{nombre}: debe empezar con https://")
    if tipo == "url_sitio":
        v = v.rstrip("/")
        return (v, None) if re.fullmatch(r"(https://\S{4,300}|http://(localhost|127\.0\.0\.1)(:\d+)?)", v) else (None, f"{nombre}: debe empezar con https://")
    rx = _RE.get(tipo)
    if rx is not None:
        return (v, None) if rx.fullmatch(v) else (None, f"{nombre}: el formato no es válido. Revisa que lo copiaste completo y sin espacios.")
    return v, None


# --- Cómo se ve cada campo en pantalla ------------------------------------------------------------------------------
def _vista(c):
    v = refrescar().get(c["nombre"]) or ""
    if c["nombre"] == "GEMINI_API_KEYS" and v:
        n = len([x for x in v.split("\n") if x.strip()])
        return f"{n} llave{'s' if n != 1 else ''} (la última termina en ····{v.strip()[-4:]})"
    if c["secreto"]:
        return f"····{v[-4:]}" if v else ""
    return v


def estado_grupo(g, vapid_diag=None):
    """'ok' | 'falta' | 'parcial' según lo que el grupo necesita para funcionar."""
    n = {c["nombre"]: origen(c["nombre"]) for c in g["campos"]}
    clave = g["clave"]
    if clave == "ia":
        return "ok" if n["GEMINI_API_KEYS"] else "falta"
    if clave == "avisos":
        tg = bool(n["TELEGRAM_BOT_TOKEN"] and n["TELEGRAM_CHAT_ID"])
        mail = bool(n["SMTP_USER"] and n["SMTP_PASS"])
        return "ok" if (tg or mail) else ("parcial" if any(n[k] for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_USER", "SMTP_PASS")) else "falta")
    if clave == "push":
        if not (n["VAPID_PUBLIC_KEY"] and n["VAPID_PRIVATE_KEY"]):
            return "parcial" if (n["VAPID_PUBLIC_KEY"] or n["VAPID_PRIVATE_KEY"]) else "falta"
        return "ok" if (vapid_diag is None or vapid_diag() is None) else "parcial"
    if clave == "respaldos":
        req = ("BACKUP_R2_ACCOUNT_ID", "BACKUP_R2_ACCESS_KEY_ID", "BACKUP_R2_SECRET_ACCESS_KEY", "BACKUP_R2_BUCKET")
        if all(n[k] for k in req):
            return "ok" if n["BACKUP_KEY"] else "parcial"       # sin clave de cifrado, el respaldo va sin cifrar
        return "parcial" if any(n[k] for k in req) else "falta"
    return "ok" if any(n.values()) else "falta"


# --- Pruebas de conexión ----------------------------------------------------------------------------------------------
def _probar_gemini():
    import zedith
    llaves = zedith._llaves()
    if not llaves:
        return False, "No hay ninguna llave de Gemini guardada."
    salida, buenas = [], 0
    for k in llaves[:10]:
        req = urllib.request.Request(zedith.URL.format(zedith.modelo()), method="POST",
                                     data=json.dumps({"contents": [{"role": "user", "parts": [{"text": "Responde solo: ok"}]}],
                                                      "generationConfig": {"maxOutputTokens": 8}}).encode(),
                                     headers={"Content-Type": "application/json", "x-goog-api-key": k})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            salida.append(f"····{k[-4:]}: funciona")
            buenas += 1
        except urllib.error.HTTPError as ex:
            motivo = {400: "modelo o petición no válida", 401: "llave rechazada", 403: "llave rechazada o sin permiso",
                      404: "ese modelo no existe", 429: "sin cuota por ahora"}.get(ex.code, f"error {ex.code}")
            salida.append(f"····{k[-4:]}: {motivo}")
        except Exception as ex:
            salida.append(f"····{k[-4:]}: sin conexión ({type(ex).__name__})")
    return buenas > 0, f"{buenas} de {len(salida)} llaves funcionan con el modelo {zedith.modelo()}. " + " · ".join(salida)


def _probar_avisos():
    import notificar
    hecho, errores = [], []
    if valor("TELEGRAM_BOT_TOKEN") and valor("TELEGRAM_CHAT_ID"):
        try:
            notificar._telegram("✅ Prueba de ZEDYTH: Telegram está conectado.")
            hecho.append("Telegram: mensaje enviado, revisa tu celular")
        except urllib.error.HTTPError as ex:
            errores.append({401: "Telegram rechazó el token del bot", 400: "Telegram no encontró ese chat id (escríbele primero a tu bot)",
                            404: "el token del bot no existe"}.get(ex.code, f"Telegram respondió error {ex.code}"))
        except Exception as ex:
            errores.append(f"Telegram: sin conexión ({type(ex).__name__})")
    if valor("SMTP_USER") and valor("SMTP_PASS"):
        try:
            notificar._correo("Prueba de ZEDYTH", "Si lees esto, el correo de avisos está conectado.")
            hecho.append("Correo: enviado a " + (valor("AVISO_EMAIL") or valor("SMTP_USER")))
        except Exception as ex:
            import smtplib
            errores.append("Correo: el servidor rechazó el usuario o la contraseña (en Gmail necesitas una «contraseña de aplicación»)"
                           if isinstance(ex, smtplib.SMTPAuthenticationError) else f"Correo: {type(ex).__name__}")
    if not hecho and not errores:
        return False, "Falta configurar Telegram (token y chat id) o el correo (usuario y contraseña)."
    return not errores, " · ".join(hecho + errores)


def _probar_render():
    import render_panel
    return render_panel.probar()


def _probar_r2():
    import respaldos
    c = respaldos._cfg()
    if not c:
        return False, "Faltan datos: Account ID, Access Key ID, Secret Access Key y Bucket."
    try:
        respaldos._s3(c).list_objects_v2(Bucket=c["BUCKET"], Prefix=c["PREFIJO"], MaxKeys=1)
    except Exception as ex:
        codigo = getattr(ex, "response", {}).get("Error", {}).get("Code", type(ex).__name__)
        return False, {"NoSuchBucket": "ese bucket no existe en tu cuenta", "InvalidAccessKeyId": "el Access Key ID no es válido",
                       "SignatureDoesNotMatch": "el Secret Access Key no corresponde", "AccessDenied": "el token no tiene permiso sobre ese bucket"}.get(codigo, f"error {codigo}")
    return True, f"Conectado al bucket «{c['BUCKET']}». " + ("Los respaldos se cifran." if valor("BACKUP_KEY") else "Ojo: sin clave de cifrado los respaldos van sin cifrar.")


# --- Pantalla ---------------------------------------------------------------------------------------------------------
def crear_blueprint(registrar, vapid_diagnostico=None):
    bp = Blueprint("ajustes", __name__)
    db = _e["db"]
    Ajuste = _e["modelo"]

    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def solo_admin(f):
        @wraps(f)
        def w(*a, **k):
            if not es_admin():
                abort(403)
            return f(*a, **k)
        return w

    def _sin_totp():
        return not getattr(current_user, "totp_activo", False)

    def escribe(f):
        """Formularios: admin + TOTP activo (guardar llaves sin verificación en dos pasos no es aceptable)."""
        @wraps(f)
        @solo_admin
        def w(*a, **k):
            if _sin_totp():
                flash("Activa la verificación en dos pasos (TOTP) en Seguridad antes de guardar llaves.", "error")
                return redirect(url_for("ajustes.pagina"))
            return f(*a, **k)
        return w

    def escribe_json(f):
        """Igual, pero para los botones que responden sin recargar la página."""
        @wraps(f)
        @solo_admin
        def w(*a, **k):
            if _sin_totp():
                return jsonify(ok=False, mensaje="Activa la verificación en dos pasos (TOTP) en Seguridad."), 403
            return f(*a, **k)
        return w

    def enmascarar(c, v):
        return f"····{v.strip()[-4:]}" if c["secreto"] else v[:80]

    def guardar_varios(nuevos):
        f = _fernet()
        for n, v in nuevos.items():
            tok = f.encrypt(v.encode()).decode()
            fila = db.session.get(Ajuste, n)
            if fila:
                fila.valor, fila.actualizado, fila.actualizado_por = tok, datetime.utcnow(), current_user.username
            else:
                db.session.add(Ajuste(nombre=n, valor=tok, actualizado=datetime.utcnow(), actualizado_por=current_user.username))
            registrar("ajuste_guardar", "Ajuste", None, f"{n} · {enmascarar(CAMPOS[n], v)}")
        db.session.commit()
        refrescar(forzar=True)

    @bp.route("/conexiones")
    @solo_admin
    def pagina():
        refrescar(forzar=True)
        grupos = []
        for g in POR_CLAVE.values():
            campos = [dict(c, origen=origen(c["nombre"]), vista=_vista(c)) for c in g["campos"]]
            grupos.append(dict(g, campos=campos, estado=estado_grupo(g, vapid_diagnostico)))
        # Neon, R2, Cloudinary y UptimeRobot se conectan en /almacenamiento: aquí solo se muestra su estado
        guardadas = set()
        try:
            with db.engine.connect() as con:
                guardadas = {r[0] for r in con.execute(db.text("SELECT nombre FROM conexiones_almacen")).all()}
        except Exception:
            pass
        almacen = []
        for titulo, nombre in (("Neon (bases de datos)", "NEON_API_KEY"), ("Cloudflare R2 (archivos)", "R2_ACCESS_KEY_ID"),
                               ("Cloudinary (imágenes)", "CLOUDINARY_API_KEY"), ("UptimeRobot (monitoreo)", "UPTIMEROBOT_API_KEY")):
            o = "panel" if nombre in guardadas else ("entorno" if (os.environ.get(nombre) or "").strip() else None)
            almacen.append({"titulo": titulo, "origen": o})
        return render_template("conexiones.html", grupos=grupos, almacen=almacen, mfa=bool(getattr(current_user, "totp_activo", False)),
                               clave_fija=clave_fija(), ilegibles=_e["ilegibles"])

    @bp.route("/conexiones/guardar", methods=["POST"])
    @escribe
    def guardar():
        g = POR_CLAVE.get(request.form.get("grupo", ""))
        if g is None:
            abort(404)
        nuevos = {}
        for c in g["campos"]:
            v = request.form.get("c_" + c["nombre"], "")
            v = v.strip() if not c["multilinea"] else "\n".join(x.strip() for x in v.splitlines() if x.strip())
            if not v:
                continue                                   # vacío = no cambiar lo que ya hay
            limpio, err = validar(c, v)
            if err:
                flash(err, "error")
                return redirect(url_for("ajustes.pagina") + "#" + g["clave"])
            nuevos[c["nombre"]] = limpio
        if g["clave"] == "push" and ("VAPID_PUBLIC_KEY" in nuevos or "VAPID_PRIVATE_KEY" in nuevos):
            pub = nuevos.get("VAPID_PUBLIC_KEY") or valor("VAPID_PUBLIC_KEY")
            priv = nuevos.get("VAPID_PRIVATE_KEY") or valor("VAPID_PRIVATE_KEY")
            if pub and priv:
                err = par_vapid_valido(pub, priv)
                if err:
                    flash(err, "error")
                    return redirect(url_for("ajustes.pagina") + "#push")
        if not nuevos:
            flash("No escribiste nada nuevo: lo que ya estaba guardado se conserva.", "info")
            return redirect(url_for("ajustes.pagina") + "#" + g["clave"])
        guardar_varios(nuevos)
        flash(f"Guardado ({len(nuevos)} dato{'s' if len(nuevos) != 1 else ''}), cifrado. Ya está en uso; "
              "si el servidor tiene varios procesos, el resto lo toma en un par de minutos.", "ok")
        return redirect(url_for("ajustes.pagina") + "#" + g["clave"])

    @bp.route("/conexiones/quitar", methods=["POST"])
    @escribe
    def quitar():
        n = request.form.get("nombre", "")
        if n not in CAMPOS:
            abort(404)
        fila = db.session.get(Ajuste, n)
        if fila:
            db.session.delete(fila)
            registrar("ajuste_quitar", "Ajuste", None, n)
            db.session.commit()
        refrescar(forzar=True)
        resto = "Si también está en Render, seguirá usándose ese valor." if (os.environ.get(n) or "").strip() else ""
        flash(f"«{CAMPOS[n]['etiqueta']}» se quitó de la pantalla. {resto}".strip(), "ok")
        return redirect(url_for("ajustes.pagina") + "#" + GRUPO_DE[n])

    @bp.route("/conexiones/probar/<clave>", methods=["POST"])
    @escribe_json
    def probar(clave):
        refrescar(forzar=True)
        try:
            if clave == "gemini":
                ok, msg = _probar_gemini()
            elif clave == "avisos":
                ok, msg = _probar_avisos()
            elif clave == "r2":
                ok, msg = _probar_r2()
            elif clave == "render":
                ok, msg = _probar_render()
            elif clave == "vapid":
                if not (valor("VAPID_PUBLIC_KEY") and valor("VAPID_PRIVATE_KEY")):
                    ok, msg = False, "Faltan las llaves VAPID."
                else:
                    err = par_vapid_valido(valor("VAPID_PUBLIC_KEY"), valor("VAPID_PRIVATE_KEY"))
                    ok, msg = (err is None), (err or "El par de llaves es válido. Activa las alertas en tu celular desde Alertas.")
            else:
                abort(404)
        except Exception as ex:
            ok, msg = False, f"No se pudo probar ({type(ex).__name__})."
        return jsonify(ok=ok, mensaje=msg)

    @bp.route("/conexiones/generar/<nombre>", methods=["POST"])
    @escribe_json
    def generar(nombre):
        if nombre == "VAPID":
            existe = valor("VAPID_PUBLIC_KEY") or valor("VAPID_PRIVATE_KEY")
            if existe and request.form.get("confirmar") != "1":
                return jsonify(ok=False, mensaje="Ya hay un par. Cambiarlo obliga a reactivar las alertas en cada dispositivo."), 409
            pub, priv = generar_par_vapid()
            guardar_varios({"VAPID_PUBLIC_KEY": pub, "VAPID_PRIVATE_KEY": priv})
            return jsonify(ok=True, mensaje="Par de llaves creado y guardado cifrado. Ahora activa las alertas en tu celular desde Alertas.")
        c = CAMPOS.get(nombre)
        if not c or not c["generar"]:
            abort(404)
        if valor(nombre) and request.form.get("confirmar") != "1":
            aviso = ("Ya hay una clave. Si la cambias, los respaldos anteriores quedan ilegibles sin la clave vieja."
                     if nombre == "BACKUP_KEY" else "Ya hay un token. Si lo cambias, tendrás que actualizarlo en tu cron externo.")
            return jsonify(ok=False, mensaje=aviso), 409
        nuevo = Fernet.generate_key().decode() if c["generar"] == "fernet" else secrets.token_urlsafe(32)
        guardar_varios({nombre: nuevo})
        return jsonify(ok=True, secreto=nuevo, mensaje="Guardada, cifrada. Cópiala AHORA: es la única vez que se muestra completa.")

    return bp


# --- Arranque ---------------------------------------------------------------------------------------------------------
def iniciar(app, db):
    """Llamar una vez, justo después de crear db. Define la tabla; se crea sola en el primer uso."""
    _e["app"], _e["db"] = app, db

    class AjusteSistema(db.Model):
        """Valores de configuración guardados desde la pantalla. El valor va CIFRADO (Fernet)."""
        __tablename__ = "ajuste_sistema"
        nombre = db.Column(db.String(60), primary_key=True)
        valor = db.Column(db.Text, nullable=False)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado_por = db.Column(db.String(80))

    _e["modelo"] = AjusteSistema
    return AjusteSistema