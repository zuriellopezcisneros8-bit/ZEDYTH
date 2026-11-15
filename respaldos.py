"""respaldos.py — Respaldo REAL de la base del panel (Neon/PostgreSQL) hacia Cloudflare R2.

Qué hace:
  * Cada BACKUP_CADA_HORAS (24) saca un volcado de la base: con `pg_dump` si existe y es compatible; si no,
    un volcado lógico propio en JSON comprimido (funciona sin binarios, también a través del pooler de Neon).
  * Lo cifra (si hay BACKUP_KEY), lo sube a R2 con SU PROPIO token y confirma el tamaño en el bucket.
  * Guarda en la tabla respaldo_panel: resultado, tamaño, hash SHA-256, método, duración y quién lo pidió.
  * Verifica el respaldo (descarga, compara el hash y comprueba que el archivo se pueda leer). Es una
    verificación de INTEGRIDAD, no una restauración completa en una rama de Neon.
  * Retiene los últimos BACKUP_RETENER respaldos buenos y borra los más viejos del bucket.
  * Avisa (notificación + push) si falla, si no está configurado o si el último bueno tiene más de 36 h.
  * Antes de reescribir planes (aplicar_fichas) saca un respaldo y, si no puede, NO reescribe.

Variables de entorno (Render):
  BACKUP_R2_ACCOUNT_ID, BACKUP_R2_ACCESS_KEY_ID, BACKUP_R2_SECRET_ACCESS_KEY, BACKUP_R2_BUCKET
        Token de R2 EXCLUSIVO para respaldos (permiso Object Read & Write sobre un bucket solo para esto).
  BACKUP_R2_PREFIJO   carpeta dentro del bucket (por defecto "panel/")
  BACKUP_KEY          clave Fernet para cifrar el respaldo antes de subirlo (muy recomendado: el volcado trae
                      todos los datos de clientes y los hashes de contraseñas). Se genera igual que LLAVES_MASTER.
                      GUÁRDALA FUERA de Render: sin ella el respaldo cifrado no se puede abrir.
  BACKUP_DATABASE_URL conexión DIRECTA a Neon (sin "-pooler") para pg_dump. Si falta se usa DATABASE_URL.
  BACKUP_CADA_HORAS (24) · BACKUP_RETENER (30) · BACKUP_VERIFICAR_DIAS (7)
  FICHAS_SIN_RESPALDO=1  permite aplicar_fichas aunque no se pueda respaldar antes (no recomendado).
"""
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import date, datetime, timedelta
from decimal import Decimal
from functools import wraps
import base64

from flask import Blueprint, render_template, redirect, url_for, abort, request, Response
from flask_login import current_user

CADA_HORAS = int(os.environ.get("BACKUP_CADA_HORAS", "24"))
RETENER = int(os.environ.get("BACKUP_RETENER", "30"))
VERIFICAR_DIAS = int(os.environ.get("BACKUP_VERIFICAR_DIAS", "7"))
ATRASO_HORAS = 36
MAX_CIFRAR_MB = 150          # Fernet trabaja en memoria: por encima de esto se pide otro método
_api = {}
_ocupado = threading.Lock()


# --- utilidades puras (se pueden probar sin base de datos) --------------------------------------------
def _serializar(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return str(o)
    if isinstance(o, (bytes, bytearray, memoryview)):
        return {"b64": base64.b64encode(bytes(o)).decode()}
    return str(o)


def _sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloque)
    return h.hexdigest()


def _validar_jsonl(ruta):
    """Lee un volcado JSON comprimido y devuelve (tablas, filas). Lanza ValueError si está dañado."""
    tablas, filas = {}, 0
    with gzip.open(ruta, "rt", encoding="utf-8") as f:
        for n, linea in enumerate(f, 1):
            o = json.loads(linea)
            if "columnas" in o:
                tablas[o["tabla"]] = 0
            elif "r" in o:
                if o["t"] not in tablas:
                    raise ValueError(f"fila de una tabla sin cabecera (línea {n})")
                tablas[o["t"]] += 1
                filas += 1
    if not tablas:
        raise ValueError("el volcado no contiene tablas")
    return tablas, filas


def _cifrar_archivo(origen, destino, clave):
    from cryptography.fernet import Fernet
    if os.path.getsize(origen) > MAX_CIFRAR_MB * 1024 * 1024:
        raise ValueError(f"el volcado pasa de {MAX_CIFRAR_MB} MB y no se puede cifrar en memoria; usa pg_dump y cifra aparte")
    with open(origen, "rb") as f:
        datos = f.read()
    with open(destino, "wb") as f:
        f.write(Fernet(clave).encrypt(datos))


def _descifrar_archivo(origen, destino, clave):
    from cryptography.fernet import Fernet
    with open(origen, "rb") as f:
        datos = f.read()
    with open(destino, "wb") as f:
        f.write(Fernet(clave).decrypt(datos))


def _cfg():
    c = {k: (os.environ.get(f"BACKUP_R2_{k}") or "").strip() for k in ("ACCOUNT_ID", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY", "BUCKET")}
    if not all(c.values()):
        return None
    c["PREFIJO"] = (os.environ.get("BACKUP_R2_PREFIJO") or "panel/").strip().lstrip("/")
    if c["PREFIJO"] and not c["PREFIJO"].endswith("/"):
        c["PREFIJO"] += "/"
    return c


def _s3(c):
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url=f"https://{c['ACCOUNT_ID']}.r2.cloudflarestorage.com",
                        aws_access_key_id=c["ACCESS_KEY_ID"], aws_secret_access_key=c["SECRET_ACCESS_KEY"],
                        config=Config(signature_version="s3v4", region_name="auto", retries={"max_attempts": 3}))


def estado_configuracion():
    return {"r2": _cfg() is not None, "cifrado": bool((os.environ.get("BACKUP_KEY") or "").strip()),
            "pg_dump": shutil.which("pg_dump") is not None, "pg_restore": shutil.which("pg_restore") is not None}


# --- API pública ----------------------------------------------------------------------------------------
def antes_de_cambio(etiqueta):
    """Respaldo síncrono previo a una operación que reescribe datos. Devuelve (ok, mensaje)."""
    return _api["sincrono"](etiqueta)


def revisar():
    """Para el vigilante: lanza el respaldo diario y la verificación cuando toca, y avisa si algo anda mal."""
    try:
        _api["revisar"]()
    except Exception:
        pass


# --- módulo ----------------------------------------------------------------------------------------------
def iniciar(app, db, registrar, avisar):
    bp = Blueprint("respaldos", __name__)

    class RespaldoPanel(db.Model):
        __tablename__ = "respaldo_panel"
        id = db.Column(db.Integer, primary_key=True)
        fecha = db.Column(db.DateTime, default=datetime.utcnow)
        tipo = db.Column(db.String(24))                 # diario | manual | antes_fichas
        metodo = db.Column(db.String(12))               # pg_dump | json | sqlite
        estado = db.Column(db.String(10))               # en curso | ok | error | borrado
        clave = db.Column(db.String(300))               # ruta dentro del bucket
        bytes = db.Column(db.BigInteger)
        sha256 = db.Column(db.String(64))
        cifrado = db.Column(db.Boolean, default=False)
        duracion_s = db.Column(db.Float)
        detalle = db.Column(db.String(300))
        verificado_en = db.Column(db.DateTime)
        verificacion = db.Column(db.String(300))
        creado_por = db.Column(db.String(80))

    estado_tabla = {"ok": False}

    def asegurar():
        if not estado_tabla["ok"]:
            RespaldoPanel.__table__.create(db.engine, checkfirst=True)
            estado_tabla["ok"] = True

    # ---- volcados ----
    def _entorno_pg():
        url = os.environ.get("BACKUP_DATABASE_URL", "").strip()
        u = db.engine.url
        if url:
            from sqlalchemy.engine import make_url
            u = make_url(url)
        env = {**os.environ, "PGHOST": u.host or "", "PGPORT": str(u.port or 5432), "PGUSER": u.username or "",
               "PGPASSWORD": u.password or "", "PGDATABASE": u.database or "",
               "PGSSLMODE": (u.query.get("sslmode") if u.query else None) or "require"}
        return env

    def _dump_pg(destino):
        r = subprocess.run(["pg_dump", "-Fc", "--no-owner", "--no-privileges", "-f", destino], env=_entorno_pg(),
                           capture_output=True, text=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError("pg_dump: " + (r.stderr or "falló").strip().splitlines()[-1][:200])

    def _dump_json(destino):
        from sqlalchemy import inspect as sa_inspect
        insp = sa_inspect(db.engine)
        with db.engine.connect() as conn:
            conn = conn.execution_options(isolation_level="REPEATABLE READ", stream_results=True) \
                if db.engine.dialect.name == "postgresql" else conn
            with gzip.open(destino, "wt", encoding="utf-8") as f:
                for t in sorted(insp.get_table_names()):
                    cols = [c["name"] for c in insp.get_columns(t)]
                    f.write(json.dumps({"tabla": t, "columnas": cols}) + "\n")
                    for fila in conn.execute(db.text('SELECT * FROM "%s"' % t.replace('"', '""'))):
                        f.write(json.dumps({"t": t, "r": list(fila)}, default=_serializar) + "\n")

    def _dump_sqlite(destino):
        ruta = db.engine.url.database
        with open(ruta, "rb") as a, gzip.open(destino, "wb") as b:
            shutil.copyfileobj(a, b)

    # ---- ejecutar ----
    def ejecutar(tipo, usuario=None):
        """Hace un respaldo completo. Devuelve (ok, mensaje). Nunca lanza."""
        asegurar()
        c = _cfg()
        if c is None:
            return False, "Faltan las variables BACKUP_R2_* (token de R2 exclusivo para respaldos)."
        if not _ocupado.acquire(blocking=False):
            return False, "Ya hay un respaldo en curso en este proceso."
        t0 = time.time()
        tmp = tempfile.mkdtemp(prefix="zedyth_resp_")
        fila = None
        try:
            hace = datetime.utcnow() - timedelta(minutes=30)
            if RespaldoPanel.query.filter(RespaldoPanel.estado == "en curso", RespaldoPanel.fecha >= hace).first():
                return False, "Otro proceso ya está respaldando."
            fila = RespaldoPanel(tipo=tipo, estado="en curso", creado_por=usuario or "sistema")
            db.session.add(fila)
            db.session.commit()
            dialecto = db.engine.dialect.name
            archivo, metodo, ext, nota = os.path.join(tmp, "volcado"), None, None, ""
            if dialecto == "sqlite":
                _dump_sqlite(archivo); metodo, ext = "sqlite", "sqlite.gz"
            else:
                try:
                    if not shutil.which("pg_dump"):
                        raise RuntimeError("pg_dump no está instalado")
                    _dump_pg(archivo); metodo, ext = "pg_dump", "dump"
                except Exception as e:
                    nota = f"(pg_dump no se pudo usar: {str(e)[:120]}; se usó el volcado JSON)"
                    if os.path.exists(archivo):
                        os.remove(archivo)
                    _dump_json(archivo); metodo, ext = "json", "jsonl.gz"
            subir = archivo
            clave_cifrado = (os.environ.get("BACKUP_KEY") or "").strip()
            if clave_cifrado:
                subir = archivo + ".enc"
                _cifrar_archivo(archivo, subir, clave_cifrado)
                ext += ".enc"
            sha = _sha256(subir)
            tam = os.path.getsize(subir)
            ahora = datetime.utcnow()
            clave = f"{c['PREFIJO']}{ahora:%Y/%m}/zedyth_{ahora:%Y%m%d_%H%M%S}_{tipo}.{ext}"
            s3 = _s3(c)
            s3.upload_file(subir, c["BUCKET"], clave, ExtraArgs={"Metadata": {"sha256": sha, "metodo": metodo, "tipo": tipo}})
            remoto = s3.head_object(Bucket=c["BUCKET"], Key=clave)["ContentLength"]
            if remoto != tam:
                raise RuntimeError(f"el archivo subido pesa {remoto} bytes y el local {tam}")
            fila.estado, fila.metodo, fila.clave, fila.bytes, fila.sha256 = "ok", metodo, clave, tam, sha
            fila.cifrado, fila.duracion_s = bool(clave_cifrado), round(time.time() - t0, 1)
            fila.detalle = (("Cifrado. " if clave_cifrado else "SIN CIFRAR. ") + nota)[:300]
            registrar("respaldo", "RespaldoPanel", fila.id, f"{tipo} · {metodo} · {tam:,} bytes · sha256 {sha[:12]}…", usuario=usuario or "sistema")
            db.session.commit()
            _retener(s3, c)
            return True, f"Respaldo listo ({metodo}, {tam:,} bytes)."
        except Exception as e:
            db.session.rollback()
            msg = str(e)[:280]
            try:
                if fila is not None:
                    f2 = db.session.get(RespaldoPanel, fila.id)
                    f2.estado, f2.detalle, f2.duracion_s = "error", msg, round(time.time() - t0, 1)
                    registrar("respaldo_fallo", "RespaldoPanel", f2.id, f"{tipo} · {msg}", usuario=usuario or "sistema")
                    db.session.commit()
            except Exception:
                db.session.rollback()
            avisar("Respaldo", "El respaldo del panel falló", msg, "/respaldos", urgente=True,
                   clave=f"respaldo-fallo-{datetime.utcnow():%Y%m%d%H}")
            return False, msg
        finally:
            _ocupado.release()
            shutil.rmtree(tmp, ignore_errors=True)

    def _retener(s3, c):
        buenos = RespaldoPanel.query.filter_by(estado="ok").order_by(RespaldoPanel.fecha.desc(), RespaldoPanel.id.desc()).all()
        for viejo in buenos[RETENER:]:
            try:
                s3.delete_object(Bucket=c["BUCKET"], Key=viejo.clave)
                viejo.estado = "borrado"
            except Exception:
                break          # si el token no puede borrar, no insistimos; se ve en la pantalla
        db.session.commit()

    def verificar(fila_id=None, usuario=None):
        """Descarga el respaldo, compara el hash y comprueba que se pueda leer. Devuelve (ok, mensaje)."""
        asegurar()
        c = _cfg()
        if c is None:
            return False, "Faltan las variables BACKUP_R2_*."
        q = RespaldoPanel.query.filter_by(estado="ok")
        fila = db.session.get(RespaldoPanel, fila_id) if fila_id else q.order_by(RespaldoPanel.fecha.desc(), RespaldoPanel.id.desc()).first()
        if fila is None or fila.estado != "ok":
            return False, "No hay un respaldo bueno que verificar."
        tmp = tempfile.mkdtemp(prefix="zedyth_ver_")
        try:
            local = os.path.join(tmp, "bajado")
            _s3(c).download_file(c["BUCKET"], fila.clave, local)
            if _sha256(local) != fila.sha256:
                raise ValueError("el hash del archivo en R2 NO coincide con el registrado")
            abierto = local
            if fila.cifrado:
                clave = (os.environ.get("BACKUP_KEY") or "").strip()
                if not clave:
                    raise ValueError("el respaldo está cifrado y falta BACKUP_KEY")
                abierto = local + ".dec"
                _descifrar_archivo(local, abierto, clave)
            if fila.metodo == "json":
                tablas, filas = _validar_jsonl(abierto)
                detalle = f"{len(tablas)} tablas, {filas:,} filas legibles"
            elif fila.metodo == "pg_dump":
                with open(abierto, "rb") as f:
                    if f.read(5) != b"PGDMP":
                        raise ValueError("el archivo no es un volcado de pg_dump")
                if shutil.which("pg_restore"):
                    r = subprocess.run(["pg_restore", "--list", abierto], capture_output=True, text=True, timeout=300)
                    if r.returncode != 0:
                        raise ValueError("pg_restore no pudo leer el volcado")
                    detalle = f"pg_restore lo lee: {sum(1 for l in r.stdout.splitlines() if 'TABLE DATA' in l)} tablas con datos"
                else:
                    detalle = "formato pg_dump válido (pg_restore no está para listarlo)"
            else:
                with gzip.open(abierto, "rb") as f:
                    if f.read(15) != b"SQLite format 3":
                        raise ValueError("no es una base SQLite")
                detalle = "base SQLite legible"
            fila.verificado_en, fila.verificacion = datetime.utcnow(), "ok · " + detalle
            registrar("respaldo_verificado", "RespaldoPanel", fila.id, detalle, usuario=usuario or "sistema")
            db.session.commit()
            return True, detalle
        except Exception as e:
            db.session.rollback()
            fila = db.session.get(RespaldoPanel, fila.id)
            fila.verificado_en, fila.verificacion = datetime.utcnow(), ("ERROR · " + str(e))[:290]
            registrar("respaldo_verificacion_fallo", "RespaldoPanel", fila.id, str(e)[:200], usuario=usuario or "sistema")
            db.session.commit()
            avisar("Respaldo", "La verificación del respaldo falló", str(e)[:200], "/respaldos", urgente=True,
                   clave=f"respaldo-verif-{fila.id}")
            return False, str(e)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def en_hilo(fn, *a):
        def correr():
            with app.app_context():
                try:
                    fn(*a)
                except Exception as e:
                    app.logger.error("Respaldo en hilo falló: %s", e)
        threading.Thread(target=correr, daemon=True, name="respaldo-panel").start()

    def _revisar():
        asegurar()
        ahora = datetime.utcnow()
        if _cfg() is None:
            avisar("Respaldo", "Los respaldos del panel no están configurados",
                   "Faltan las variables BACKUP_R2_*. Mientras tanto no hay copia de la base.", "/respaldos",
                   urgente=True, clave=f"respaldo-sin-config-{date.today()}")
            return
        ultimo = RespaldoPanel.query.filter_by(estado="ok").order_by(RespaldoPanel.fecha.desc(), RespaldoPanel.id.desc()).first()
        if ultimo is None or ahora - ultimo.fecha >= timedelta(hours=CADA_HORAS):
            if not _ocupado.locked():
                en_hilo(ejecutar, "diario")
        if ultimo is not None and ahora - ultimo.fecha >= timedelta(hours=ATRASO_HORAS):
            avisar("Respaldo", "El último respaldo bueno tiene más de 36 horas",
                   f"Fue el {ultimo.fecha:%d/%m/%Y %H:%M} UTC.", "/respaldos", urgente=True,
                   clave=f"respaldo-atrasado-{date.today()}")
        if ultimo is not None and not _ocupado.locked():
            if ultimo.verificado_en is None or ahora - ultimo.verificado_en >= timedelta(days=VERIFICAR_DIAS):
                en_hilo(verificar, ultimo.id)

    def _sincrono(etiqueta):
        if _cfg() is None:
            return False, "respaldos sin configurar (BACKUP_R2_*)"
        return ejecutar(etiqueta)

    _api.update(revisar=_revisar, sincrono=_sincrono)

    # ---- pantallas ----
    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def solo_admin(f):
        @wraps(f)
        def envoltura(*a, **k):
            if not es_admin():
                abort(403)
            return f(*a, **k)
        return envoltura

    @bp.route("/respaldos")
    @solo_admin
    def index():
        asegurar()
        ahora = datetime.utcnow()
        filas = RespaldoPanel.query.order_by(RespaldoPanel.fecha.desc(), RespaldoPanel.id.desc()).limit(40).all()
        for f in filas:      # un "en curso" de hace más de 30 min es un proceso que murió
            if f.estado == "en curso" and ahora - f.fecha > timedelta(minutes=30):
                f.estado, f.detalle = "error", "El proceso se interrumpió (probablemente un reinicio)."
        db.session.commit()
        ultimo_ok = next((f for f in filas if f.estado == "ok"), None)
        return render_template("respaldos.html", filas=filas, ultimo_ok=ultimo_ok, cfg=estado_configuracion(),
                               horas_desde=((ahora - ultimo_ok.fecha).total_seconds() / 3600) if ultimo_ok else None,
                               cada=CADA_HORAS, retener=RETENER, atraso=ATRASO_HORAS, mensaje=request.args.get("m"))

    @bp.route("/respaldos/ahora", methods=["POST"])
    @solo_admin
    def ahora():
        ok, msg = ejecutar("manual", usuario=current_user.username)
        return redirect(url_for("respaldos.index", m=("OK: " if ok else "ERROR: ") + msg))

    @bp.route("/respaldos/<int:rid>/verificar", methods=["POST"])
    @solo_admin
    def verificar_ruta(rid):
        ok, msg = verificar(rid, usuario=current_user.username)
        return redirect(url_for("respaldos.index", m=("Verificado: " if ok else "ERROR: ") + msg))

    app.register_blueprint(bp)
    return bp
