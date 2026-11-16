"""vault.py — ZEDYTH OPS VAULT: workspace privado de ciberseguridad (solo administradores).

Qué incluye (todo bajo /vault):
  * Arsenal de código   Snippets OFFENSIVE / DEFENSIVE con lenguaje, variables {{PLACEHOLDER}} y versiones.
  * Cuaderno            Notas con [[wiki-links]], niveles de clasificación, plantillas (Recon, Finding, CTF) y notas efímeras.
  * Modo misión         Checklists interactivos OWASP Top 10, PTES y MITRE ATT&CK por objetivo.
  * Caja de herramientas (Base64, hex, URL, JWT, hashes, defang, IoCs, generadores): vive en el navegador
                        (static/js/vault_tools.js); lo que pegas ahí NO viaja al servidor.
  * Escáner de PDFs     Análisis estático (JavaScript, /Launch, archivos incrustados, ofuscación…) + ClamAV y VirusTotal por hash
                        si están configurados. El PDF NO se guarda: solo se analiza en memoria y se registra su hash.
  * Biblioteca          Herramientas y aprendizajes: qué hace cada una, cómo se usa y lo que aprendiste (por categoría y nivel).
  * Tecnologías         Registro de tecnologías, objetos y sistemas (propios o de terceros): cómo funcionan y en qué plataformas viven.
  * Búsqueda            Texto completo en títulos, etiquetas y contenido.
  * Seguridad           Todo el contenido se guarda CIFRADO (Fernet). Bloqueo por inactividad (5 min) en el servidor y en
                        el navegador: se desbloquea con la contraseña de tu cuenta.

Se conecta en app.py:
    import vault
    app.register_blueprint(vault.crear_blueprint(app, db, registrar, limitar))

Clave de cifrado: variable VAULT_KEY (una clave Fernet). Si no existe se deriva de SECRET_KEY. IMPORTANTE: si cambias esa
clave, lo ya guardado no se podrá leer. Define VAULT_KEY en Render y guárdala en un lugar seguro.
"""
import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, Response, abort, jsonify, render_template, request, session
from flask_login import current_user
from werkzeug.exceptions import HTTPException

import pdf_scan

LADOS = ("OFFENSIVE", "DEFENSIVE")
CLASIFICACIONES = ("PUBLICABLE", "INTERNO", "CONFIDENCIAL", "ZERO-DAY / CRÍTICO")
TIPOS_NOTA = ("Nota", "Captura", "Recon", "Finding", "CTF", "Aprendizaje", "Aprendí hoy")
TIPOS_HALLAZGO = ("Atajo", "Código", "Búsqueda", "Configuración", "Otro")
DONDE_SUGERIDOS = ("Windows", "Linux", "macOS", "Google", "Microsoft", "Navegador", "Terminal", "Otro")
CATEGORIAS_TEC = ("Hardware / objeto", "Software / app", "Protocolo / red", "Servicio / plataforma", "Sistema / arquitectura", "Concepto / técnica", "Otra")
ORIGENES_TEC = ("Nuestra", "De terceros")
ESTADOS_TEC = ("Idea", "En desarrollo", "En uso", "Archivada")
PLATAFORMAS_SUGERIDAS = ("Windows", "Linux", "macOS", "Android", "iOS", "Web", "Google", "Microsoft", "AWS", "Render", "GitHub", "Docker")
METODOLOGIAS = ("OWASP Top 10", "PTES", "MITRE ATT&CK")
CATEGORIAS_HERR = ("Malware / virus", "Actividad de personas", "Bots y automatización", "Red y tráfico", "Web y apps", "Forense y logs", "OSINT", "Otra")
NIVELES_HERR = ("Por probar", "Probando", "La domino")
LENGUAJES = ("auto", "bash", "python", "powershell", "sql", "cpp", "yara", "regex", "terminal", "javascript", "texto")
EFIMERAS_HORAS = (1, 24)           # además de «al cerrar»
BLOQUEO_SEGUNDOS = int(os.environ.get("VAULT_BLOQUEO_S", "300") or 300)
MAX_CUERPO = 400_000               # caracteres por elemento
MAX_ELEMENTOS = 5000
MAX_VERSIONES = 50
AL_CERRAR_CADUCA_H = 12            # respaldo del servidor para las notas «al cerrar» que el navegador no alcanzó a borrar

PLANTILLAS = {
    "Tecnología": ("## Qué es\n\n\n## Cómo funciona\n\n\n## Partes o componentes\n\n- \n\n## Dónde la usamos\n\n\n## Límites / cuidado\n\n\n## Relacionado\n\n- [[ ]]\n"),
    "Aprendí hoy": "## Qué aprendí\n\n\n## Para qué sirve\n\n\n## Cómo se hace\n\n",
    "Aprendizaje": ("# Lo que aprendí hoy\n\n- **Tema:** \n- **Fuente (curso, video, laboratorio):** \n\n"
                    "## Idea clave\n\n\n## Cómo lo probé\n\n\n## Herramientas usadas\n\n- [[ ]]\n\n## Dudas / qué sigue\n\n"),
    "Herramienta": ("## Para qué sirve\n\n\n## Cómo se usa\n\n```\n\n```\n\n## Lo que aprendí\n\n\n## Cuidado / límites\n\n\n## Relacionado\n\n- [[ ]]\n"),
    "Recon": ("# Ficha de reconocimiento\n\n"
              "- **Dominio:** \n- **Subdominios:** \n- **Puertos abiertos:** \n- **Tecnologías detectadas:** \n\n"
              "## Superficie de ataque\n\n\n## Notas\n\n"),
    "Finding": ("# Reporte de vulnerabilidad\n\n"
                "- **Severidad (CVSS):** \n- **Activo afectado:** \n\n"
                "## Descripción\n\n\n## Prueba de concepto (PoC)\n\n```\n\n```\n\n## Impacto\n\n\n## Remediación\n\n"),
    "CTF": ("# Bitácora de laboratorio / CTF\n\n"
            "- **Plataforma / máquina:** \n- **Objetivo:** {{TARGET_IP}}\n\n"
            "## Enumeración\n\n\n## Explotación\n\n\n## Escalada de privilegios\n\n\n## Lecciones aprendidas\n\n"),
}

CHECKLISTS = {
    "OWASP Top 10": [
        ("A01", "Control de acceso roto", ["IDOR: cambiar IDs en URL/cuerpo", "Escalada horizontal y vertical de privilegios", "CORS permisivo y forzado de navegación"]),
        ("A02", "Fallas criptográficas", ["TLS y suites débiles", "Datos sensibles en claro (tránsito/reposo)", "Hashing de contraseñas y gestión de llaves"]),
        ("A03", "Inyección", ["SQLi (parámetros, cabeceras, JSON)", "XSS reflejado, almacenado y DOM", "Inyección de comandos / plantillas (SSTI)"]),
        ("A04", "Diseño inseguro", ["Modelado de amenazas del flujo", "Límites de negocio y abuso de lógica"]),
        ("A05", "Configuración incorrecta", ["Cabeceras de seguridad (CSP, HSTS)", "Puertos/servicios y paneles expuestos", "Mensajes de error y modo debug"]),
        ("A06", "Componentes vulnerables", ["Inventario de dependencias y versiones", "CVE conocidos de cada componente"]),
        ("A07", "Fallas de identificación y autenticación", ["Fuerza bruta y bloqueo de cuentas", "Gestión de sesión (cookies, caducidad)", "MFA y recuperación de contraseña"]),
        ("A08", "Integridad de software y datos", ["Pipeline CI/CD y dependencias firmadas", "Deserialización insegura"]),
        ("A09", "Registro y monitoreo", ["Eventos críticos registrados", "Alertas y retención de logs"]),
        ("A10", "SSRF", ["Parámetros que cargan URLs", "Acceso a metadatos cloud / red interna"]),
    ],
    "PTES": [
        ("1", "Pre-engagement", ["Alcance y reglas de compromiso", "Autorización por escrito", "Ventanas y contactos de emergencia"]),
        ("2", "Recopilación de inteligencia", ["OSINT pasivo", "Enumeración de subdominios y DNS", "Fingerprinting de tecnologías"]),
        ("3", "Modelado de amenazas", ["Activos y atacantes probables", "Vectores prioritarios"]),
        ("4", "Análisis de vulnerabilidades", ["Escaneo de puertos y servicios", "Revisión manual de hallazgos", "Falsos positivos descartados"]),
        ("5", "Explotación", ["Pruebas de concepto controladas", "Evidencia (capturas, logs)"]),
        ("6", "Post-explotación", ["Alcance real del impacto", "Persistencia (solo si el alcance lo permite)", "Limpieza de artefactos"]),
        ("7", "Reporte", ["Resumen ejecutivo", "Detalle técnico y remediación", "Retest de correcciones"]),
    ],
    "MITRE ATT&CK": [
        ("TA0043", "Reconnaissance", ["Escaneo activo (T1595)", "Búsqueda en fuentes abiertas (T1593)"]),
        ("TA0042", "Resource Development", ["Infraestructura y cuentas (T1583/T1585)"]),
        ("TA0001", "Initial Access", ["Phishing (T1566)", "Explotación de app pública (T1190)", "Cuentas válidas (T1078)"]),
        ("TA0002", "Execution", ["Intérprete de comandos y scripts (T1059)"]),
        ("TA0003", "Persistence", ["Tareas programadas (T1053)", "Claves de ejecución / servicios (T1547/T1543)"]),
        ("TA0004", "Privilege Escalation", ["Explotación para escalar (T1068)", "Abuso de control de elevación (T1548)"]),
        ("TA0005", "Defense Evasion", ["Enmascaramiento (T1036)", "Deshabilitar herramientas de seguridad (T1562)"]),
        ("TA0006", "Credential Access", ["Volcado de credenciales (T1003)", "Fuerza bruta (T1110)"]),
        ("TA0007", "Discovery", ["Descubrimiento de red y cuentas (T1046/T1087)"]),
        ("TA0008", "Lateral Movement", ["Servicios remotos (T1021)"]),
        ("TA0009", "Collection", ["Datos del sistema local (T1005)"]),
        ("TA0011", "Command and Control", ["Protocolos de capa de aplicación (T1071)"]),
        ("TA0010", "Exfiltration", ["Exfiltración por canal C2 (T1041)"]),
        ("TA0040", "Impact", ["Cifrado para impacto (T1486)", "Denegación de servicio (T1498)"]),
    ],
}


def claves_checklist(metodologia):
    """Todas las claves de ítem válidas de una metodología, p. ej. 'A01.0'."""
    return {f"{cod}.{i}" for cod, _t, items in CHECKLISTS.get(metodologia, []) for i in range(len(items))}


def catalogo_para_cliente():
    return {m: [{"codigo": c, "titulo": t, "items": it} for c, t, it in filas] for m, filas in CHECKLISTS.items()}


# --- Cifrado -----------------------------------------------------------------
def _fernet(secreto_app):
    from cryptography.fernet import Fernet
    k = (os.environ.get("VAULT_KEY") or "").strip()
    if not k:
        k = base64.urlsafe_b64encode(hashlib.sha256(("vault:" + secreto_app).encode()).digest()).decode()
    return Fernet(k)


def cifrar(f, texto):
    return f.encrypt((texto or "").encode()).decode()


def descifrar(f, token):
    try:
        return f.decrypt((token or "").encode()).decode()
    except Exception:
        return None          # clave distinta o dato dañado


# --- Utilidades puras (con pruebas) ------------------------------------------
_RE_WIKI = re.compile(r"\[\[([^\[\]\n]{1,200})\]\]")


def enlaces_wiki(texto):
    """Títulos enlazados con [[...]] dentro de un texto (sin repetir, sin distinguir mayúsculas)."""
    vistos, salida = set(), []
    for m in _RE_WIKI.finditer(texto or ""):
        t = m.group(1).strip()
        if t and t.lower() not in vistos:
            vistos.add(t.lower())
            salida.append(t)
    return salida


def limpiar_etiquetas(texto):
    et, vistas = [], set()
    for p in re.split(r"[,\n;]", texto or ""):
        p = re.sub(r"\s+", " ", p.strip().lstrip("#"))[:30]
        if p and p.lower() not in vistas:
            vistas.add(p.lower())
            et.append(p)
    return et[:15]


def coincide(consulta, *campos):
    """Búsqueda de texto completo: todas las palabras de la consulta deben aparecer en algún campo."""
    pajar = "\n".join((c or "") for c in campos).lower()
    palabras = [w for w in re.split(r"\s+", (consulta or "").strip().lower()) if w]
    return bool(palabras) and all(w in pajar for w in palabras)


def informe_markdown(titulo, clasificacion, tipo, etiquetas, cuerpo, autor, ahora=None):
    """Nota técnica -> informe Markdown limpio para archivar o entregar."""
    ahora = ahora or datetime.utcnow()
    cab = [f"# {titulo}", "",
           f"> **Clasificación:** {clasificacion} · **Tipo:** {tipo} · **Fecha:** {ahora:%Y-%m-%d} · **Autor:** {autor}"]
    if etiquetas:
        cab.append(f"> **Etiquetas:** {', '.join(etiquetas)}")
    cuerpo = re.sub(r"^# .*\n+", "", (cuerpo or "").lstrip(), count=1) if (cuerpo or "").lstrip().startswith("# ") else (cuerpo or "")
    return "\n".join(cab) + "\n\n" + cuerpo.strip() + "\n"


def nombre_archivo(texto):
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", texto or "informe").strip("_.")[:60]
    return base or "informe"


# --- Blueprint ---------------------------------------------------------------
def crear_blueprint(app, db, registrar, limitar=None):
    bp = Blueprint("vault", __name__)
    secreto = app.config["SECRET_KEY"]
    F = _fernet(secreto)

    class VaultCodigo(db.Model):
        __tablename__ = "vault_codigo"
        id = db.Column(db.Integer, primary_key=True)
        titulo = db.Column(db.String(200), nullable=False)
        lado = db.Column(db.String(12), nullable=False)             # OFFENSIVE | DEFENSIVE
        lenguaje = db.Column(db.String(20), default="auto")
        etiquetas = db.Column(db.String(400), default="")
        cuerpo = db.Column(db.Text, nullable=False)                 # cifrado
        notas = db.Column(db.Text, default="")                      # cifrado: para qué sirve / qué aprendí
        version = db.Column(db.Integer, default=1)
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    class VaultVersion(db.Model):
        __tablename__ = "vault_version"
        id = db.Column(db.Integer, primary_key=True)
        codigo_id = db.Column(db.Integer, db.ForeignKey("vault_codigo.id", ondelete="CASCADE"), nullable=False, index=True)
        n = db.Column(db.Integer, nullable=False)
        nota = db.Column(db.String(200), default="")
        cuerpo = db.Column(db.Text, nullable=False)                 # cifrado
        fecha = db.Column(db.DateTime, default=datetime.utcnow)

    class VaultNota(db.Model):
        __tablename__ = "vault_nota"
        id = db.Column(db.Integer, primary_key=True)
        tipo = db.Column(db.String(12), default="Nota")
        titulo = db.Column(db.String(200), nullable=False)
        clasificacion = db.Column(db.String(24), default="INTERNO")
        etiquetas = db.Column(db.String(400), default="")
        cuerpo = db.Column(db.Text, default="")                     # cifrado
        expira = db.Column(db.DateTime)                             # UTC; NULL = no caduca
        al_cerrar = db.Column(db.Boolean, default=False)            # efímera: se borra al bloquear/cerrar la bóveda
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    class VaultChecklist(db.Model):
        __tablename__ = "vault_checklist"
        id = db.Column(db.Integer, primary_key=True)
        objetivo = db.Column(db.String(200), nullable=False)
        metodologia = db.Column(db.String(20), nullable=False)
        hechos = db.Column(db.Text, default="[]")                   # lista JSON de claves marcadas
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    class VaultHerramienta(db.Model):
        __tablename__ = "vault_herramienta"
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(200), nullable=False)
        categoria = db.Column(db.String(30), default="Otra")
        nivel = db.Column(db.String(16), default="Por probar")
        enlace = db.Column(db.String(400), default="")
        etiquetas = db.Column(db.String(400), default="")
        cuerpo = db.Column(db.Text, default="")                     # cifrado
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    class VaultHallazgo(db.Model):
        """«Si hago X pasa Y»: un acto, un resultado y un dónde. Lo valida el equipo con votos."""
        __tablename__ = "vault_hallazgo"
        id = db.Column(db.Integer, primary_key=True)
        titulo = db.Column(db.String(200), nullable=False)
        tipo = db.Column(db.String(16), default="Atajo")
        donde = db.Column(db.String(60), default="")
        etiquetas = db.Column(db.String(400), default="")
        enlace = db.Column(db.String(200), default="")              # título de una nota/bloque ([[enlace]])
        accion = db.Column(db.Text, default="")                     # cifrado: qué hice (teclas, comando, código)
        resultado = db.Column(db.Text, default="")                  # cifrado: qué pasó
        autor = db.Column(db.String(80), default="")
        autor_id = db.Column(db.Integer, index=True)
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    class VaultVoto(db.Model):
        __tablename__ = "vault_voto"
        __table_args__ = (db.UniqueConstraint("hallazgo_id", "usuario_id", name="uq_vault_voto"),)
        id = db.Column(db.Integer, primary_key=True)
        hallazgo_id = db.Column(db.Integer, db.ForeignKey("vault_hallazgo.id", ondelete="CASCADE"), nullable=False, index=True)
        usuario_id = db.Column(db.Integer, nullable=False)
        valor = db.Column(db.Integer, nullable=False)               # 1 = me funcionó, -1 = no me funcionó

    class VaultTecnologia(db.Model):
        """Registro de tecnologías, cosas u objetos: qué son, cómo funcionan y en qué plataformas se conectan."""
        __tablename__ = "vault_tecnologia"
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(200), nullable=False)
        categoria = db.Column(db.String(30), default="Otra")
        origen = db.Column(db.String(16), default="Nuestra")
        estado = db.Column(db.String(16), default="En uso")
        plataformas = db.Column(db.String(400), default="")         # opcional: lista separada por comas
        enlace = db.Column(db.String(400), default="")
        etiquetas = db.Column(db.String(400), default="")
        cuerpo = db.Column(db.Text, default="")                     # cifrado: cómo funciona
        autor = db.Column(db.String(80), default="")
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        actualizado = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    estado = {"ok": False}

    def asegurar():
        if estado["ok"]:
            return
        for m in (VaultCodigo, VaultVersion, VaultNota, VaultChecklist, VaultHerramienta, VaultHallazgo, VaultVoto, VaultTecnologia):
            m.__table__.create(db.engine, checkfirst=True)
        try:        # base ya existente: agrega la columna «notas» a vault_codigo sin perder nada
            from sqlalchemy import inspect, text
            if "notas" not in {c["name"] for c in inspect(db.engine).get_columns("vault_codigo")}:
                with db.engine.begin() as con:
                    con.execute(text("ALTER TABLE vault_codigo ADD COLUMN notas TEXT"))
        except Exception:
            db.session.rollback()
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

    def desbloqueado(tocar=True):
        t = session.get("vault_ts")
        ok = isinstance(t, (int, float)) and (time.time() - t) < BLOQUEO_SEGUNDOS
        if ok and tocar:
            session["vault_ts"] = time.time()
        return ok

    def api(f):
        """Rutas JSON: solo admin y bóveda desbloqueada (423 si está bloqueada)."""
        @wraps(f)
        @solo_admin
        def envoltura(*a, **k):
            asegurar()
            if not desbloqueado():
                return jsonify(ok=False, error="bloqueada"), 423
            purgar()
            return f(*a, **k)
        return envoltura

    def purgar(todo_al_cerrar=False):
        ahora = datetime.utcnow()
        q = VaultNota.query.filter(VaultNota.expira.isnot(None), VaultNota.expira <= ahora)
        n = q.delete(synchronize_session=False)
        viejas = VaultNota.query.filter(VaultNota.al_cerrar.is_(True))
        if not todo_al_cerrar:
            viejas = viejas.filter(VaultNota.creado <= ahora - timedelta(hours=AL_CERRAR_CADUCA_H))
        n += viejas.delete(synchronize_session=False)
        if n:
            db.session.commit()
        return n

    def datos():
        d = request.get_json(silent=True)
        if not isinstance(d, dict):
            abort(400)
        return d

    def texto(d, campo, maximo, obligatorio=False):
        v = d.get(campo)
        v = v if isinstance(v, str) else ""
        if obligatorio and not v.strip():
            abort(400, description=f"Falta {campo}")
        return v[:maximo]

    @bp.errorhandler(HTTPException)
    def error_json(e):
        """Las rutas /vault/api devuelven siempre JSON, también en errores."""
        if request.path.startswith("/vault/api/"):
            return jsonify(ok=False, error=e.description if e.code == 400 else e.name), e.code
        return e

    # ---- Página y bloqueo -----------------------------------------------------
    @bp.route("/vault")
    @solo_admin
    def vault_inicio():
        asegurar()
        cfg = {"desbloqueada": desbloqueado(tocar=False), "bloqueo_s": BLOQUEO_SEGUNDOS, "lados": list(LADOS),
               "clasificaciones": list(CLASIFICACIONES), "tipos": list(TIPOS_NOTA), "lenguajes": list(LENGUAJES),
               "metodologias": list(METODOLOGIAS), "categorias": list(CATEGORIAS_HERR), "niveles": list(NIVELES_HERR),
               "tipos_hall": list(TIPOS_HALLAZGO), "donde_sug": list(DONDE_SUGERIDOS),
               "cats_tec": list(CATEGORIAS_TEC), "origenes_tec": list(ORIGENES_TEC), "estados_tec": list(ESTADOS_TEC), "plat_sug": list(PLATAFORMAS_SUGERIDAS)}
        return render_template("vault.html", cfg=cfg)

    @bp.route("/vault/api/desbloquear", methods=["POST"])
    @solo_admin
    def vault_desbloquear():
        d = datos()
        clave = f"vault_unlock:{current_user.id}"
        if limitar and not limitar(clave, 6, 600, sumar=False):
            return jsonify(ok=False, error="Demasiados intentos. Espera unos minutos."), 429
        if not current_user.check_password(d.get("password") if isinstance(d.get("password"), str) else ""):
            if limitar:
                limitar(clave, 6, 600)
            registrar("vault_fallo", "vault", None, "Contraseña incorrecta al desbloquear")
            db.session.commit()
            return jsonify(ok=False, error="Contraseña incorrecta."), 403
        session["vault_ts"] = time.time()
        registrar("vault_abrir", "vault", None, "Bóveda desbloqueada")
        db.session.commit()
        return jsonify(ok=True)

    @bp.route("/vault/api/bloquear", methods=["POST"])
    @solo_admin
    def vault_bloquear():
        asegurar()
        session.pop("vault_ts", None)
        purgar(todo_al_cerrar=True)
        return jsonify(ok=True)

    @bp.route("/vault/api/latido", methods=["POST"])
    @api
    def vault_latido():
        return jsonify(ok=True)

    # ---- Inicio rápido: listados (sin contenido) ------------------------------
    def resumen_codigo(c):
        return {"id": c.id, "titulo": c.titulo, "lado": c.lado, "lenguaje": c.lenguaje, "etiquetas": limpiar_etiquetas(c.etiquetas),
                "version": c.version, "actualizado": c.actualizado.isoformat() + "Z"}

    def resumen_nota(n):
        return {"id": n.id, "titulo": n.titulo, "tipo": n.tipo, "clasificacion": n.clasificacion, "etiquetas": limpiar_etiquetas(n.etiquetas),
                "expira": n.expira.isoformat() + "Z" if n.expira else None, "al_cerrar": bool(n.al_cerrar),
                "actualizado": n.actualizado.isoformat() + "Z"}

    def resumen_check(c):
        try:
            hechos = json.loads(c.hechos or "[]")
        except ValueError:
            hechos = []
        return {"id": c.id, "objetivo": c.objetivo, "metodologia": c.metodologia, "hechos": hechos,
                "total": len(claves_checklist(c.metodologia)), "actualizado": c.actualizado.isoformat() + "Z"}

    def resumen_herr(h):
        return {"id": h.id, "nombre": h.nombre, "categoria": h.categoria, "nivel": h.nivel, "enlace": h.enlace or "",
                "etiquetas": limpiar_etiquetas(h.etiquetas), "actualizado": h.actualizado.isoformat() + "Z"}

    def votos_de(ids):
        """{hallazgo_id: (funciona, no_funciona, mi_voto)} para una lista de hallazgos."""
        r = {i: [0, 0, 0] for i in ids}
        if not ids:
            return {}
        for v in VaultVoto.query.filter(VaultVoto.hallazgo_id.in_(ids)).all():
            fila = r.get(v.hallazgo_id)
            if fila is None:
                continue
            fila[0 if v.valor == 1 else 1] += 1
            if v.usuario_id == current_user.id:
                fila[2] = v.valor
        return {k: tuple(v) for k, v in r.items()}

    def resumen_hall(h, votos=None):
        si, no, mio = (votos or {}).get(h.id, (0, 0, 0))
        return {"id": h.id, "titulo": h.titulo, "tipo": h.tipo, "donde": h.donde or "", "etiquetas": limpiar_etiquetas(h.etiquetas),
                "enlace": h.enlace or "", "autor": h.autor or "", "funciona": si, "no_funciona": no, "mi_voto": mio,
                "actualizado": h.actualizado.isoformat() + "Z"}

    def resumen_tec(t):
        return {"id": t.id, "nombre": t.nombre, "categoria": t.categoria, "origen": t.origen, "estado": t.estado,
                "plataformas": limpiar_etiquetas(t.plataformas), "enlace": t.enlace or "", "etiquetas": limpiar_etiquetas(t.etiquetas),
                "autor": t.autor or "", "actualizado": t.actualizado.isoformat() + "Z"}

    def entrantes_de(titulo, excluir=None):
        """Notas, bloques, herramientas, tecnologías y hallazgos que enlazan a un título con [[...]]."""
        buscado, salida = titulo.strip().lower(), []
        def enlaza(txt):
            return buscado in [x.lower() for x in enlaces_wiki(txt)]
        for tipo, modelo, campo in (("nota", VaultNota, "titulo"), ("codigo", VaultCodigo, "titulo"),
                                    ("herramienta", VaultHerramienta, "nombre"), ("tecnologia", VaultTecnologia, "nombre")):
            for o in modelo.query.all():
                if excluir != (tipo, o.id) and enlaza(descifrar(F, o.cuerpo)):
                    salida.append({"tipo": tipo, "id": o.id, "titulo": getattr(o, campo)})
        for o in VaultHallazgo.query.all():
            if excluir != ("hallazgo", o.id) and enlaza("\n".join([descifrar(F, o.accion) or "", descifrar(F, o.resultado) or "", f"[[{o.enlace}]]" if o.enlace else ""])):
                salida.append({"tipo": "hallazgo", "id": o.id, "titulo": o.titulo})
        return salida

    def lista_hallazgos():
        hs = VaultHallazgo.query.order_by(VaultHallazgo.actualizado.desc()).all()
        votos = votos_de([h.id for h in hs])
        return [resumen_hall(h, votos) for h in hs]

    @bp.route("/vault/api/inicio")
    @api
    def vault_datos():
        return jsonify(ok=True,
                       hallazgos=lista_hallazgos(),
                       tecnologias=[resumen_tec(t) for t in VaultTecnologia.query.order_by(VaultTecnologia.actualizado.desc()).all()],
                       codigo=[resumen_codigo(c) for c in VaultCodigo.query.order_by(VaultCodigo.actualizado.desc()).all()],
                       notas=[resumen_nota(n) for n in VaultNota.query.order_by(VaultNota.actualizado.desc()).all()],
                       checklists=[resumen_check(c) for c in VaultChecklist.query.order_by(VaultChecklist.actualizado.desc()).all()],
                       herramientas=[resumen_herr(h) for h in VaultHerramienta.query.order_by(VaultHerramienta.actualizado.desc()).all()],
                       catalogo=catalogo_para_cliente(), plantillas=PLANTILLAS)

    # ---- Código ---------------------------------------------------------------
    @bp.route("/vault/api/codigo/<int:cid>")
    @api
    def vault_codigo_ver(cid):
        c = db.session.get(VaultCodigo, cid) or abort(404)
        cuerpo = descifrar(F, c.cuerpo)
        vers = VaultVersion.query.filter_by(codigo_id=cid).order_by(VaultVersion.n.desc()).all()
        notas = (descifrar(F, c.notas) or "") if c.notas else ""
        return jsonify(ok=True, item=dict(resumen_codigo(c), cuerpo=cuerpo, notas=notas, ilegible=cuerpo is None),
                       versiones=[{"n": v.n, "nota": v.nota, "fecha": v.fecha.isoformat() + "Z"} for v in vers])

    @bp.route("/vault/api/codigo/<int:cid>/version/<int:n>")
    @api
    def vault_codigo_version(cid, n):
        v = VaultVersion.query.filter_by(codigo_id=cid, n=n).first() or abort(404)
        return jsonify(ok=True, n=v.n, nota=v.nota, cuerpo=descifrar(F, v.cuerpo) or "")

    @bp.route("/vault/api/codigo", methods=["POST"])
    @api
    def vault_codigo_guardar():
        d = datos()
        titulo = texto(d, "titulo", 200, True).strip()
        lado = d.get("lado")
        if lado not in LADOS:
            abort(400, description="Elige OFFENSIVE o DEFENSIVE")
        lenguaje = d.get("lenguaje") if d.get("lenguaje") in LENGUAJES else "auto"
        cuerpo = texto(d, "cuerpo", MAX_CUERPO)
        notas = texto(d, "notas", MAX_CUERPO)
        nota_version = texto(d, "nota_version", 200).strip()
        etiquetas = ", ".join(limpiar_etiquetas(texto(d, "etiquetas", 400)))
        cid = d.get("id")
        if cid:
            c = db.session.get(VaultCodigo, int(cid)) or abort(404)
            if descifrar(F, c.cuerpo) != cuerpo:        # cambió el código: la versión anterior queda en el historial
                c.version = (c.version or 1) + 1
                db.session.add(VaultVersion(codigo_id=c.id, n=c.version, nota=nota_version, cuerpo=cifrar(F, cuerpo)))
                c.cuerpo = cifrar(F, cuerpo)
                viejas = VaultVersion.query.filter_by(codigo_id=c.id).order_by(VaultVersion.n.desc()).offset(MAX_VERSIONES).all()
                for v in viejas:
                    db.session.delete(v)
            c.titulo, c.lado, c.lenguaje, c.etiquetas = titulo, lado, lenguaje, etiquetas
            if "notas" in d:
                c.notas = cifrar(F, notas)
        else:
            if VaultCodigo.query.count() >= MAX_ELEMENTOS:
                abort(400, description="Límite de elementos alcanzado")
            c = VaultCodigo(titulo=titulo, lado=lado, lenguaje=lenguaje, etiquetas=etiquetas, cuerpo=cifrar(F, cuerpo), notas=cifrar(F, notas), version=1)
            db.session.add(c)
            db.session.flush()
            db.session.add(VaultVersion(codigo_id=c.id, n=1, nota=nota_version or "Versión inicial", cuerpo=cifrar(F, cuerpo)))
        registrar("vault_codigo", "vault_codigo", c.id, f"{lado}: {titulo[:80]}")
        db.session.commit()
        return jsonify(ok=True, item=resumen_codigo(c))

    @bp.route("/vault/api/codigo/<int:cid>/restaurar/<int:n>", methods=["POST"])
    @api
    def vault_codigo_restaurar(cid, n):
        c = db.session.get(VaultCodigo, cid) or abort(404)
        v = VaultVersion.query.filter_by(codigo_id=cid, n=n).first() or abort(404)
        c.version = (c.version or 1) + 1
        db.session.add(VaultVersion(codigo_id=cid, n=c.version, nota=f"Restaurada desde v{n}", cuerpo=v.cuerpo))
        c.cuerpo = v.cuerpo
        registrar("vault_codigo", "vault_codigo", cid, f"Restaurada v{n}")
        db.session.commit()
        return jsonify(ok=True, item=resumen_codigo(c))

    @bp.route("/vault/api/codigo/<int:cid>", methods=["DELETE"])
    @api
    def vault_codigo_borrar(cid):
        c = db.session.get(VaultCodigo, cid) or abort(404)
        VaultVersion.query.filter_by(codigo_id=cid).delete()
        registrar("vault_codigo_borrar", "vault_codigo", cid, c.titulo[:80])
        db.session.delete(c)
        db.session.commit()
        return jsonify(ok=True)

    # ---- Notas ----------------------------------------------------------------
    @bp.route("/vault/api/nota/<int:nid>")
    @api
    def vault_nota_ver(nid):
        n = db.session.get(VaultNota, nid) or abort(404)
        cuerpo = descifrar(F, n.cuerpo)
        titulo_l = n.titulo.strip().lower()
        entrantes = []                      # backlinks: notas y snippets que enlazan a esta
        for o in VaultNota.query.filter(VaultNota.id != nid).all():
            if titulo_l in [t.lower() for t in enlaces_wiki(descifrar(F, o.cuerpo))]:
                entrantes.append({"tipo": "nota", "id": o.id, "titulo": o.titulo})
        for o in VaultCodigo.query.all():
            if titulo_l in [t.lower() for t in enlaces_wiki(descifrar(F, o.cuerpo))]:
                entrantes.append({"tipo": "codigo", "id": o.id, "titulo": o.titulo})
        for o in VaultHerramienta.query.all():
            if titulo_l in [t.lower() for t in enlaces_wiki(descifrar(F, o.cuerpo))]:
                entrantes.append({"tipo": "herramienta", "id": o.id, "titulo": o.nombre})
        for o in VaultHallazgo.query.all():
            texto_h = "\n".join([descifrar(F, o.accion) or "", descifrar(F, o.resultado) or "", f"[[{o.enlace}]]" if o.enlace else ""])
            if titulo_l in [t.lower() for t in enlaces_wiki(texto_h)]:
                entrantes.append({"tipo": "hallazgo", "id": o.id, "titulo": o.titulo})
        for o in VaultTecnologia.query.all():
            if titulo_l in [t.lower() for t in enlaces_wiki(descifrar(F, o.cuerpo))]:
                entrantes.append({"tipo": "tecnologia", "id": o.id, "titulo": o.nombre})
        return jsonify(ok=True, item=dict(resumen_nota(n), cuerpo=cuerpo, ilegible=cuerpo is None), entrantes=entrantes)

    @bp.route("/vault/api/nota", methods=["POST"])
    @api
    def vault_nota_guardar():
        d = datos()
        titulo = texto(d, "titulo", 200, True).strip()
        tipo = d.get("tipo") if d.get("tipo") in TIPOS_NOTA else "Nota"
        clasif = d.get("clasificacion") if d.get("clasificacion") in CLASIFICACIONES else "INTERNO"
        cuerpo = texto(d, "cuerpo", MAX_CUERPO)
        etiquetas = ", ".join(limpiar_etiquetas(texto(d, "etiquetas", 400)))
        efimera = d.get("efimera")                      # None | 1 | 24 | "cerrar"
        nid = d.get("id")
        if nid:
            n = db.session.get(VaultNota, int(nid)) or abort(404)
        else:
            if VaultNota.query.count() >= MAX_ELEMENTOS:
                abort(400, description="Límite de elementos alcanzado")
            n = VaultNota()
            db.session.add(n)
            if efimera == "cerrar":
                n.al_cerrar = True
            elif efimera in EFIMERAS_HORAS:
                n.expira = datetime.utcnow() + timedelta(hours=int(efimera))
        n.titulo, n.tipo, n.clasificacion, n.etiquetas, n.cuerpo = titulo, tipo, clasif, etiquetas, cifrar(F, cuerpo)
        db.session.flush()
        registrar("vault_nota", "vault_nota", n.id, f"{clasif}: {titulo[:80]}" if not (n.expira or n.al_cerrar) else "nota efímera")
        db.session.commit()
        return jsonify(ok=True, item=resumen_nota(n))

    @bp.route("/vault/api/nota/<int:nid>", methods=["DELETE"])
    @api
    def vault_nota_borrar(nid):
        n = db.session.get(VaultNota, nid) or abort(404)
        registrar("vault_nota_borrar", "vault_nota", nid, "" if (n.expira or n.al_cerrar) else n.titulo[:80])
        db.session.delete(n)
        db.session.commit()
        return jsonify(ok=True)

    @bp.route("/vault/api/nota/<int:nid>/informe.md")
    @api
    def vault_nota_informe(nid):
        n = db.session.get(VaultNota, nid) or abort(404)
        md = informe_markdown(n.titulo, n.clasificacion, n.tipo, limpiar_etiquetas(n.etiquetas), descifrar(F, n.cuerpo) or "",
                              current_user.nombre or current_user.username)
        registrar("vault_exportar", "vault_nota", nid, "Informe Markdown")
        db.session.commit()
        return Response(md, mimetype="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename={nombre_archivo(n.titulo)}.md", "Cache-Control": "no-store"})

    # ---- Biblioteca de herramientas y aprendizajes -----------------------------
    @bp.route("/vault/api/herramienta/<int:hid>")
    @api
    def vault_herr_ver(hid):
        h = db.session.get(VaultHerramienta, hid) or abort(404)
        cuerpo = descifrar(F, h.cuerpo)
        return jsonify(ok=True, item=dict(resumen_herr(h), cuerpo=cuerpo, ilegible=cuerpo is None))

    @bp.route("/vault/api/herramienta", methods=["POST"])
    @api
    def vault_herr_guardar():
        d = datos()
        nombre = texto(d, "nombre", 200, True).strip()
        cat = d.get("categoria") if d.get("categoria") in CATEGORIAS_HERR else "Otra"
        nivel = d.get("nivel") if d.get("nivel") in NIVELES_HERR else "Por probar"
        enlace = texto(d, "enlace", 400).strip()
        if enlace and not re.match(r"^https?://", enlace, re.I):
            abort(400, description="El enlace debe empezar con http:// o https://")
        etiquetas = ", ".join(limpiar_etiquetas(texto(d, "etiquetas", 400)))
        cuerpo = texto(d, "cuerpo", MAX_CUERPO)
        hid = d.get("id")
        if hid:
            h = db.session.get(VaultHerramienta, int(hid)) or abort(404)
        else:
            if VaultHerramienta.query.count() >= MAX_ELEMENTOS:
                abort(400, description="Límite de elementos alcanzado")
            h = VaultHerramienta()
            db.session.add(h)
        h.nombre, h.categoria, h.nivel, h.enlace, h.etiquetas, h.cuerpo = nombre, cat, nivel, enlace, etiquetas, cifrar(F, cuerpo)
        db.session.flush()
        registrar("vault_herr", "vault_herramienta", h.id, f"{cat}: {nombre[:80]}")
        db.session.commit()
        return jsonify(ok=True, item=resumen_herr(h))

    @bp.route("/vault/api/herramienta/<int:hid>", methods=["DELETE"])
    @api
    def vault_herr_borrar(hid):
        h = db.session.get(VaultHerramienta, hid) or abort(404)
        registrar("vault_herr_borrar", "vault_herramienta", hid, h.nombre[:80])
        db.session.delete(h)
        db.session.commit()
        return jsonify(ok=True)

    # ---- Tecnologías (qué son, cómo funcionan, dónde se conectan) --------------
    @bp.route("/vault/api/tecnologia/<int:tid>")
    @api
    def vault_tec_ver(tid):
        t = db.session.get(VaultTecnologia, tid) or abort(404)
        cuerpo = descifrar(F, t.cuerpo)
        return jsonify(ok=True, item=dict(resumen_tec(t), cuerpo=cuerpo, ilegible=cuerpo is None),
                       entrantes=entrantes_de(t.nombre, ("tecnologia", tid)))

    @bp.route("/vault/api/tecnologia", methods=["POST"])
    @api
    def vault_tec_guardar():
        d = datos()
        nombre = texto(d, "nombre", 200, True).strip()
        cat = d.get("categoria") if d.get("categoria") in CATEGORIAS_TEC else "Otra"
        origen = d.get("origen") if d.get("origen") in ORIGENES_TEC else "Nuestra"
        est = d.get("estado") if d.get("estado") in ESTADOS_TEC else "En uso"
        plataformas = ", ".join(limpiar_etiquetas(texto(d, "plataformas", 400)))
        enlace = texto(d, "enlace", 400).strip()
        if enlace and not re.match(r"^https?://", enlace, re.I):
            abort(400, description="El enlace debe empezar con http:// o https://")
        etiquetas = ", ".join(limpiar_etiquetas(texto(d, "etiquetas", 400)))
        cuerpo = texto(d, "cuerpo", MAX_CUERPO)
        tid = d.get("id")
        if tid:
            t = db.session.get(VaultTecnologia, int(tid)) or abort(404)
        else:
            if VaultTecnologia.query.count() >= MAX_ELEMENTOS:
                abort(400, description="Límite de elementos alcanzado")
            t = VaultTecnologia(autor=(current_user.nombre or current_user.username or "")[:80])
            db.session.add(t)
        t.nombre, t.categoria, t.origen, t.estado, t.plataformas, t.enlace, t.etiquetas, t.cuerpo = nombre, cat, origen, est, plataformas, enlace, etiquetas, cifrar(F, cuerpo)
        db.session.flush()
        registrar("vault_tecnologia", "vault_tecnologia", t.id, f"{cat}: {nombre[:80]}")
        db.session.commit()
        return jsonify(ok=True, item=resumen_tec(t))

    @bp.route("/vault/api/tecnologia/<int:tid>", methods=["DELETE"])
    @api
    def vault_tec_borrar(tid):
        t = db.session.get(VaultTecnologia, tid) or abort(404)
        registrar("vault_tecnologia_borrar", "vault_tecnologia", tid, t.nombre[:80])
        db.session.delete(t)
        db.session.commit()
        return jsonify(ok=True)

    # ---- Hallazgos («si hago X pasa Y») ----------------------------------------
    @bp.route("/vault/api/hallazgo/<int:hid>")
    @api
    def vault_hall_ver(hid):
        h = db.session.get(VaultHallazgo, hid) or abort(404)
        accion, resultado = descifrar(F, h.accion), descifrar(F, h.resultado)
        return jsonify(ok=True, item=dict(resumen_hall(h, votos_de([hid])), accion=accion or "", resultado=resultado or "",
                                          ilegible=accion is None or resultado is None))

    @bp.route("/vault/api/hallazgo", methods=["POST"])
    @api
    def vault_hall_guardar():
        d = datos()
        titulo = texto(d, "titulo", 200, True).strip()
        accion = texto(d, "accion", MAX_CUERPO)
        resultado = texto(d, "resultado", MAX_CUERPO)
        tipo = d.get("tipo") if d.get("tipo") in TIPOS_HALLAZGO else "Otro"
        donde = re.sub(r"\s+", " ", texto(d, "donde", 60)).strip()
        etiquetas = ", ".join(limpiar_etiquetas(texto(d, "etiquetas", 400)))
        enlace = re.sub(r"^\[\[|\]\]$", "", texto(d, "enlace", 200).strip()).strip()
        hid = d.get("id")
        if hid:
            h = db.session.get(VaultHallazgo, int(hid)) or abort(404)
        else:
            if VaultHallazgo.query.count() >= MAX_ELEMENTOS:
                abort(400, description="Límite de elementos alcanzado")
            h = VaultHallazgo(autor=(current_user.nombre or current_user.username or "")[:80], autor_id=current_user.id)
            db.session.add(h)
        h.titulo, h.tipo, h.donde, h.etiquetas, h.enlace = titulo, tipo, donde, etiquetas, enlace
        h.accion, h.resultado = cifrar(F, accion), cifrar(F, resultado)
        if hid:     # al cambiar el contenido, los votos anteriores ya no validan lo nuevo
            VaultVoto.query.filter_by(hallazgo_id=h.id).delete()
        db.session.flush()
        registrar("vault_hallazgo", "vault_hallazgo", h.id, f"{tipo}: {titulo[:80]}")
        db.session.commit()
        return jsonify(ok=True, item=resumen_hall(h, votos_de([h.id])))

    @bp.route("/vault/api/hallazgo/<int:hid>", methods=["DELETE"])
    @api
    def vault_hall_borrar(hid):
        h = db.session.get(VaultHallazgo, hid) or abort(404)
        VaultVoto.query.filter_by(hallazgo_id=hid).delete()
        registrar("vault_hallazgo_borrar", "vault_hallazgo", hid, h.titulo[:80])
        db.session.delete(h)
        db.session.commit()
        return jsonify(ok=True)

    @bp.route("/vault/api/hallazgo/<int:hid>/voto", methods=["POST"])
    @api
    def vault_hall_voto(hid):
        h = db.session.get(VaultHallazgo, hid) or abort(404)
        valor = datos().get("valor")
        if valor not in (1, -1, 0):
            abort(400, description="Voto no válido")
        v = VaultVoto.query.filter_by(hallazgo_id=hid, usuario_id=current_user.id).first()
        if valor == 0 or (v and v.valor == valor):      # volver a pulsar el mismo botón quita el voto
            if v:
                db.session.delete(v)
        elif v:
            v.valor = valor
        else:
            db.session.add(VaultVoto(hallazgo_id=hid, usuario_id=current_user.id, valor=valor))
        db.session.commit()
        return jsonify(ok=True, item=resumen_hall(h, votos_de([hid])))

    # ---- Checklists -----------------------------------------------------------
    @bp.route("/vault/api/checklist", methods=["POST"])
    @api
    def vault_check_crear():
        d = datos()
        objetivo = texto(d, "objetivo", 200, True).strip()
        met = d.get("metodologia")
        if met not in METODOLOGIAS:
            abort(400, description="Metodología no válida")
        c = VaultChecklist(objetivo=objetivo, metodologia=met, hechos="[]")
        db.session.add(c)
        db.session.commit()
        return jsonify(ok=True, item=resumen_check(c))

    @bp.route("/vault/api/checklist/<int:cid>", methods=["POST"])
    @api
    def vault_check_marcar(cid):
        c = db.session.get(VaultChecklist, cid) or abort(404)
        d = datos()
        validas = claves_checklist(c.metodologia)
        hechos = [k for k in (d.get("hechos") or []) if isinstance(k, str) and k in validas]
        c.hechos = json.dumps(sorted(set(hechos)))
        db.session.commit()
        return jsonify(ok=True, item=resumen_check(c))

    @bp.route("/vault/api/checklist/<int:cid>", methods=["DELETE"])
    @api
    def vault_check_borrar(cid):
        c = db.session.get(VaultChecklist, cid) or abort(404)
        db.session.delete(c)
        db.session.commit()
        return jsonify(ok=True)

    # ---- Escáner de PDFs ------------------------------------------------------
    @bp.route("/vault/api/pdf/escanear", methods=["POST"])
    @api
    def vault_pdf_escanear():
        clave = f"vault_pdf:{current_user.id}"
        if limitar and not limitar(clave, 20, 600):
            return jsonify(ok=False, error="Demasiados análisis seguidos. Espera unos minutos."), 429
        f = request.files.get("archivo")
        if not f:
            abort(400, description="Elige un archivo PDF")
        datos = f.stream.read(pdf_scan.MAX_BYTES + 1)
        if len(datos) > pdf_scan.MAX_BYTES:
            abort(400, description=f"El archivo supera {pdf_scan.MAX_BYTES // (1024 * 1024)} MB")
        try:
            r = pdf_scan.escanear(datos, f.filename or "", usar_vt=request.form.get("vt") != "0")
        except ValueError as e:
            abort(400, description=str(e))
        # Se registra solo el hash y el veredicto: el archivo no se guarda en ningún lado.
        registrar("vault_pdf_escaneo", "vault", None, f"{r['veredicto']} · sha256 {r['hashes']['sha256'][:16]}…")
        db.session.commit()
        return jsonify(ok=True, resultado=r)

    # ---- Búsqueda y grafo -----------------------------------------------------
    @bp.route("/vault/api/buscar")
    @api
    def vault_buscar():
        q = (request.args.get("q") or "").strip()[:100]
        if len(q) < 2:
            return jsonify(ok=True, resultados=[])
        res = []
        for c in VaultCodigo.query.all():
            cuerpo = descifrar(F, c.cuerpo) or ""
            if coincide(q, c.titulo, c.etiquetas, c.lado, c.lenguaje, cuerpo, descifrar(F, c.notas) if c.notas else ""):
                res.append({"tipo": "codigo", "id": c.id, "titulo": c.titulo, "detalle": c.lado, "linea": _linea(cuerpo, q)})
        for n in VaultNota.query.all():
            cuerpo = descifrar(F, n.cuerpo) or ""
            if coincide(q, n.titulo, n.etiquetas, n.clasificacion, n.tipo, cuerpo):
                res.append({"tipo": "nota", "id": n.id, "titulo": n.titulo, "detalle": n.clasificacion, "linea": _linea(cuerpo, q)})
        for h in VaultHerramienta.query.all():
            cuerpo = descifrar(F, h.cuerpo) or ""
            if coincide(q, h.nombre, h.etiquetas, h.categoria, h.nivel, cuerpo):
                res.append({"tipo": "herramienta", "id": h.id, "titulo": h.nombre, "detalle": h.categoria, "linea": _linea(cuerpo, q)})
        for x in VaultHallazgo.query.all():
            acc, rta = descifrar(F, x.accion) or "", descifrar(F, x.resultado) or ""
            if coincide(q, x.titulo, x.etiquetas, x.tipo, x.donde, x.autor, acc, rta):
                res.append({"tipo": "hallazgo", "id": x.id, "titulo": x.titulo, "detalle": f"{x.tipo} · {x.donde}" if x.donde else x.tipo,
                            "linea": _linea(acc + "\n" + rta, q)})
        for t in VaultTecnologia.query.all():
            cuerpo = descifrar(F, t.cuerpo) or ""
            if coincide(q, t.nombre, t.etiquetas, t.categoria, t.origen, t.estado, t.plataformas, cuerpo):
                res.append({"tipo": "tecnologia", "id": t.id, "titulo": t.nombre, "detalle": t.categoria, "linea": _linea(cuerpo, q)})
        return jsonify(ok=True, resultados=res[:100])

    @bp.route("/vault/api/grafo")
    @api
    def vault_grafo():
        nodos, por_titulo = [], {}
        elementos = [("nota", n.id, n.titulo, n.cuerpo) for n in VaultNota.query.all()] + \
                    [("codigo", c.id, c.titulo, c.cuerpo) for c in VaultCodigo.query.all()] + \
                    [("herramienta", h.id, h.nombre, h.cuerpo) for h in VaultHerramienta.query.all()] + \
                    [("hallazgo", x.id, x.titulo, "\n".join([descifrar(F, x.accion) or "", descifrar(F, x.resultado) or "", f"[[{x.enlace}]]" if x.enlace else ""]))
                     for x in VaultHallazgo.query.all()] + \
                    [("tecnologia", t.id, t.nombre, t.cuerpo) for t in VaultTecnologia.query.all()]
        for tipo, i, titulo, _c in elementos:
            nodos.append({"id": f"{tipo}:{i}", "tipo": tipo, "titulo": titulo})
            por_titulo.setdefault(titulo.strip().lower(), f"{tipo}:{i}")
        aristas = []
        for tipo, i, _t, cuerpo in elementos:
            plano = cuerpo if tipo == "hallazgo" else descifrar(F, cuerpo)      # los hallazgos ya vienen en claro
            for t in enlaces_wiki(plano):
                destino = por_titulo.get(t.lower())
                if destino and destino != f"{tipo}:{i}":
                    aristas.append({"de": f"{tipo}:{i}", "a": destino})
        return jsonify(ok=True, nodos=nodos, aristas=aristas)

    return bp


def _linea(cuerpo, q):
    """Primera línea del contenido que contiene alguna palabra de la búsqueda (para mostrar el contexto)."""
    palabras = [w for w in q.lower().split() if w]
    for linea in (cuerpo or "").splitlines():
        if any(w in linea.lower() for w in palabras):
            return linea.strip()[:160]
    return ""