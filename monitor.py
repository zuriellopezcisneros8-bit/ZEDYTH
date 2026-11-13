"""monitor.py — Monitor de disponibilidad propio (tipo UptimeRobot) para el panel de ZEDYTH.

Registras direcciones (https://...), el servidor las visita cada N minutos y te avisa cuando una se cae o se recupera.

Diseño pensado para NO gastar horas de cómputo de Neon:
  · Los chequeos y su historial reciente viven en memoria. La base NO se toca en cada chequeo.
  · Solo se escribe en la base cuando algo cambia (se cae / se recupera / alta, edición o baja de un sitio)
    y, una vez cada par de horas, el conteo del día (lo llama el vigilante de app.py junto a las alertas).

Seguridad:
  · Solo administradores. Todas las acciones que cambian algo exigen JSON (un formulario ajeno no puede enviarlo).
  · Anti-SSRF: se resuelve el dominio y se rechazan IPs privadas, locales o internas; la conexión se fija a esa IP
    (así no se puede cambiar el destino entre la comprobación y la visita) y NO se siguen redirecciones.
    Para pruebas en tu PC: variable MONITOR_PERMITIR_PRIVADAS=1.

Limitación: corre dentro del mismo servicio. Si ese servicio se apaga o Render lo duerme, no hay quien avise.
Para vigilar al propio servidor sigue usando un monitor externo (UptimeRobot) apuntando a /healthz.
"""
import http.client
import ipaddress
import os
import socket
import ssl
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user

MAX_SITIOS = 40
INTERVALOS = (1, 5, 10, 15, 30, 60)   # minutos permitidos
TIMEOUT_MAX = 20                      # segundos
FALLOS_PARA_CAIDA = 2                 # fallos seguidos para declarar "caído" (evita falsas alarmas)
REINTENTO_S = 30                      # tras un fallo se reintenta pronto, sin esperar todo el intervalo
HIST_MEM = 288                        # últimos resultados que se guardan en memoria por sitio
CONSERVAR_DIAS = 120                  # el conteo diario más viejo se borra
SSL_AVISO_DIAS = 14                   # avisa cuando el certificado vence en menos de estos días
LECTURA_MAX = 65536                   # bytes que se leen del cuerpo si se busca un texto
USER_AGENT = "ZEDYTH-Monitor/1.0"


# --- utilidades puras (sin base de datos: se pueden probar solas) ---------------------------------
def _hoy():
    """Fecha en México (UTC-6): el 'día' del conteo coincide con el del usuario."""
    return (datetime.utcnow() - timedelta(hours=6)).date()


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _dur(seg):
    seg = int(max(seg, 0))
    if seg < 60:
        return f"{seg} s"
    if seg < 3600:
        return f"{seg // 60} min"
    h, m = divmod(seg // 60, 60)
    return f"{h} h {m} min" if h < 48 else f"{h // 24} d {h % 24} h"


def validar_url(url):
    url = str(url or "").strip()
    if len(url) > 300:
        raise ValueError("La dirección es demasiado larga (máximo 300 caracteres).")
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("La dirección debe empezar con https:// (o http://) e incluir el dominio.")
    if p.username or p.password:
        raise ValueError("No pongas usuario ni contraseña dentro de la dirección.")
    try:
        p.port
    except ValueError:
        raise ValueError("El puerto de la dirección no es válido.") from None
    return url


def _entero(v, defecto, minimo, maximo, nombre):
    if v is None or str(v).strip() == "":
        return defecto
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"«{nombre}» debe ser un número entero.") from None
    if not minimo <= n <= maximo:
        raise ValueError(f"«{nombre}» debe estar entre {minimo} y {maximo}.")
    return n


def validar(d):
    """Normaliza y valida lo que llega del formulario. Lanza ValueError con un mensaje claro."""
    url = validar_url(d.get("url"))
    host = urlsplit(url).hostname
    metodo = str(d.get("metodo") or "GET").upper()
    if metodo not in ("GET", "HEAD"):
        raise ValueError("El método debe ser GET o HEAD.")
    texto = str(d.get("texto") or "").strip()[:100]
    if texto and metodo == "HEAD":
        raise ValueError("Para buscar un texto en la página usa el método GET.")
    intervalo = _entero(d.get("intervalo_min"), 5, 1, 1440, "Cada (minutos)")
    if intervalo not in INTERVALOS:
        raise ValueError("«Cada» debe ser " + ", ".join(map(str, INTERVALOS)) + " minutos.")
    cod_min = _entero(d.get("cod_min"), 200, 100, 599, "Código mínimo")
    cod_max = _entero(d.get("cod_max"), 399, 100, 599, "Código máximo")
    if cod_min > cod_max:
        raise ValueError("El código mínimo no puede ser mayor que el máximo.")
    return {"nombre": (str(d.get("nombre") or "").strip() or host)[:80], "url": url, "metodo": metodo,
            "intervalo_min": intervalo, "timeout_s": _entero(d.get("timeout_s"), 10, 1, TIMEOUT_MAX, "Tiempo máximo (s)"),
            "cod_min": cod_min, "cod_max": cod_max, "texto": texto}


def _ip_publica(ip):
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global


def _resolver(host, puerto):
    """Devuelve una IP pública del dominio. Rechaza redes privadas/internas (anti-SSRF)."""
    infos = socket.getaddrinfo(host, puerto, type=socket.SOCK_STREAM)
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise socket.gaierror("sin resultados")
    if os.environ.get("MONITOR_PERMITIR_PRIVADAS") != "1":
        for ip in ips:
            if not _ip_publica(ip):
                raise PermissionError("La dirección apunta a una red privada o interna; solo se vigilan sitios públicos.")
    return ips[0]


class _HttpFijo(http.client.HTTPConnection):
    """HTTP conectado a la IP ya comprobada (no se vuelve a resolver el dominio)."""
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _HttpsFijo(http.client.HTTPSConnection):
    """HTTPS conectado a la IP ya comprobada; el certificado se verifica contra el dominio."""
    def __init__(self, host, port, ip, timeout):
        self._ctx = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._ctx)
        self._ip = ip

    def connect(self):
        crudo = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._ctx.wrap_socket(crudo, server_hostname=self.host)
        except Exception:
            crudo.close()
            raise


def comprobar(cfg):
    """Una visita al sitio. cfg: url, metodo, timeout_s, cod_min, cod_max, texto.
    Devuelve {ok, codigo, ms, error, ssl_dias}. Nunca lanza error."""
    r = {"ok": False, "codigo": None, "ms": None, "error": None, "ssl_dias": None}
    conn = None
    t0 = time.perf_counter()
    try:
        p = urlsplit(cfg["url"])
        https = p.scheme == "https"
        puerto = p.port or (443 if https else 80)
        ip = _resolver(p.hostname, puerto)
        clase = _HttpsFijo if https else _HttpFijo
        conn = clase(p.hostname, puerto, ip, cfg.get("timeout_s", 10))
        ruta = (p.path or "/") + ("?" + p.query if p.query else "")
        conn.request(cfg.get("metodo", "GET"), ruta,
                     headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
        # El certificado se lee ahora: al recibir la respuesta http.client cierra el socket (Connection: close).
        if https and getattr(conn.sock, "getpeercert", None):
            cert = conn.sock.getpeercert() or {}
            if cert.get("notAfter"):
                r["ssl_dias"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        resp = conn.getresponse()
        r["codigo"] = resp.status
        cuerpo = b""
        if cfg.get("texto"):
            cuerpo = resp.read(LECTURA_MAX)
        r["ms"] = round((time.perf_counter() - t0) * 1000)
        r["ok"] = cfg.get("cod_min", 200) <= resp.status <= cfg.get("cod_max", 399)
        if not r["ok"]:
            r["error"] = f"Respondió {resp.status} (se esperaba {cfg.get('cod_min', 200)}-{cfg.get('cod_max', 399)})"
        elif cfg.get("texto") and cfg["texto"].lower() not in cuerpo.decode("utf-8", "ignore").lower():
            r["ok"] = False
            r["error"] = f"No apareció el texto «{cfg['texto']}» en la página"
    except ssl.SSLCertVerificationError as e:
        r["error"] = "Certificado SSL no válido: " + str(getattr(e, "verify_message", "") or e)[:100]
    except ssl.SSLError as e:
        r["error"] = "Error SSL: " + str(e)[:100]
    except PermissionError as e:
        r["error"] = str(e)
    except socket.gaierror:
        r["error"] = "No se encontró el dominio (DNS)"
    except (socket.timeout, TimeoutError):
        r["error"] = f"Sin respuesta en {cfg.get('timeout_s', 10)} s"
    except ConnectionRefusedError:
        r["error"] = "Conexión rechazada"
    except (OSError, http.client.HTTPException) as e:
        r["error"] = (str(e) or e.__class__.__name__)[:150]
    except Exception as e:                       # nada debe tumbar el hilo del monitor
        r["error"] = ("Error interno: " + str(e))[:150]
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    if r["ms"] is None:
        r["ms"] = round((time.perf_counter() - t0) * 1000)
    return r


def aplicar(s, r, ahora):
    """Mete un resultado en el estado del sitio `s` (dict). Devuelve 'caido', 'recuperado' o None.
    Un sitio se declara caído tras FALLOS_PARA_CAIDA fallos seguidos."""
    s["ultimo"], s["codigo"], s["ms"], s["error"] = ahora, r["codigo"], r["ms"], r["error"]
    if r["ssl_dias"] is not None:
        s["ssl_dias"] = r["ssl_dias"]
    s["hist"].append((ahora, bool(r["ok"]), r["ms"]))
    dia, c = _hoy(), s["dia"]
    if c["fecha"] != dia:                         # cambió el día: lo de ayer queda pendiente de guardarse
        if c["n"] and c["sucio"]:
            s["pend"].append(dict(c))
        c.update(fecha=dia, n=0, ok=0, ms=0.0, sucio=False)
    c["n"] += 1
    c["sucio"] = True
    if r["ok"]:
        c["ok"] += 1
        c["ms"] += r["ms"] or 0
    cambio = None
    if r["ok"]:
        s["fallos"] = 0
        if s["estado"] == "abajo":
            cambio = "recuperado"
        if s["estado"] != "arriba":
            s["desde"] = ahora
        s["estado"] = "arriba"
    else:
        s["fallos"] += 1
        if s["fallos"] >= FALLOS_PARA_CAIDA and s["estado"] != "abajo":
            s["estado"], s["desde"], cambio = "abajo", ahora, "caido"
    return cambio


# --- estado compartido y arranque -------------------------------------------------------------------
_api = {"iniciar": lambda: None, "volcar": lambda: None}


def iniciar():
    """Para app.py (before_request): carga los sitios y arranca el hilo. Barata de llamar seguido."""
    _api["iniciar"]()


def volcar():
    """Para el vigilante de app.py: guarda el conteo del día. Solo toca la base si hay algo nuevo."""
    _api["volcar"]()


def crear_blueprint(app, db, registrar, avisar):
    """avisar(tipo, titulo, cuerpo, url, urgente=, clave=) = crear_notificacion de app.py."""
    bp = Blueprint("monitor", __name__)

    class MonitorSitio(db.Model):
        __tablename__ = "monitor_sitio"
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(80), nullable=False)
        url = db.Column(db.String(300), nullable=False)
        metodo = db.Column(db.String(4), default="GET")
        intervalo_min = db.Column(db.Integer, default=5)
        timeout_s = db.Column(db.Integer, default=10)
        cod_min = db.Column(db.Integer, default=200)
        cod_max = db.Column(db.Integer, default=399)
        texto = db.Column(db.String(100))
        activo = db.Column(db.Boolean, default=True)
        estado = db.Column(db.String(10), default="nuevo")
        desde = db.Column(db.DateTime)
        creado = db.Column(db.DateTime, default=datetime.utcnow)

    class MonitorCaida(db.Model):
        __tablename__ = "monitor_caida"
        id = db.Column(db.Integer, primary_key=True)
        sitio_id = db.Column(db.Integer, db.ForeignKey("monitor_sitio.id"), nullable=False, index=True)
        inicio = db.Column(db.DateTime, nullable=False)
        fin = db.Column(db.DateTime)
        motivo = db.Column(db.String(300))

    class MonitorDia(db.Model):
        """Conteo diario por sitio: cuántas visitas y cuántas salieron bien (ms = suma de las correctas)."""
        __tablename__ = "monitor_dia"
        sitio_id = db.Column(db.Integer, db.ForeignKey("monitor_sitio.id"), primary_key=True)
        fecha = db.Column(db.Date, primary_key=True)
        checks = db.Column(db.Integer, default=0)
        ok = db.Column(db.Integer, default=0)
        ms_total = db.Column(db.Float, default=0)

    lock = threading.Lock()
    sitios = {}
    estado = {"listo": False, "intento": 0.0, "limpieza": None}
    pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="monitor")

    def asegurar_tablas():
        for m in (MonitorSitio, MonitorCaida, MonitorDia):
            m.__table__.create(db.engine, checkfirst=True)

    def runtime(f, dia=None):
        return {"id": f.id, "nombre": f.nombre, "url": f.url, "metodo": f.metodo or "GET",
                "intervalo_min": f.intervalo_min or 5, "timeout_s": f.timeout_s or 10,
                "cod_min": f.cod_min or 200, "cod_max": f.cod_max or 399, "texto": f.texto or "",
                "activo": bool(f.activo), "estado": f.estado if f.estado in ("arriba", "abajo") else "nuevo",
                "desde": f.desde, "fallos": 0, "ultimo": None, "codigo": None, "ms": None, "error": None,
                "ssl_dias": None, "ssl_avisado": None, "hist": deque(maxlen=HIST_MEM),
                "dia": dia or {"fecha": _hoy(), "n": 0, "ok": 0, "ms": 0.0, "sucio": False},
                "pend": [], "proximo": 0.0, "en_curso": False}

    def cargar():
        """Lee los sitios y el conteo de hoy (para no empezar de cero si el servicio se reinició)."""
        hoy = _hoy()
        hoy_db = {d.sitio_id: d for d in MonitorDia.query.filter_by(fecha=hoy).all()}
        nuevos = {}
        for f in MonitorSitio.query.all():
            d = hoy_db.get(f.id)
            dia = {"fecha": hoy, "n": d.checks or 0, "ok": d.ok or 0, "ms": float(d.ms_total or 0), "sucio": False} if d else None
            nuevos[f.id] = runtime(f, dia)
        with lock:
            sitios.clear()
            sitios.update(nuevos)

    # --- el hilo que visita los sitios ---------------------------------------------------------
    def persistir(sid, cambio, ahora, nombre, url, error):
        """Escribe en la base SOLO cuando un sitio cambia de estado, y avisa."""
        try:
            with app.app_context():
                f = db.session.get(MonitorSitio, sid)
                if f is None:
                    return
                if cambio == "caido":
                    f.estado, f.desde = "abajo", ahora
                    c = MonitorCaida(sitio_id=sid, inicio=ahora, motivo=(error or "Sin respuesta")[:300])
                    db.session.add(c)
                    db.session.commit()
                    avisar("Monitor", f"Caído: {nombre}", f"{url} · {error or 'Sin respuesta'}", "/monitor",
                           urgente=True, clave=f"monitor-caida-{c.id}")
                else:
                    f.estado, f.desde = "arriba", ahora
                    c = (MonitorCaida.query.filter_by(sitio_id=sid, fin=None)
                         .order_by(MonitorCaida.id.desc()).first())
                    dur = ""
                    if c:
                        c.fin = ahora
                        dur = f"Estuvo caído {_dur((ahora - c.inicio).total_seconds())}."
                    db.session.commit()
                    avisar("Monitor", f"Recuperado: {nombre}", f"{url} · {dur}".strip(" ·"), "/monitor",
                           urgente=True, clave=f"monitor-ok-{c.id if c else sid}-{int(time.time())}")
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            app.logger.error("Monitor: no se pudo guardar el cambio de estado: %s", e)

    def avisar_ssl(sid, nombre, dias):
        try:
            with app.app_context():
                avisar("Vencimiento", f"Certificado SSL por vencer: {nombre}",
                       f"Vence en {dias} día(s)." if dias >= 0 else "El certificado ya venció.", "/monitor",
                       urgente=True, clave=f"monitor-ssl-{sid}-{_hoy()}")
        except Exception as e:
            app.logger.error("Monitor: aviso de SSL: %s", e)

    def ejecutar(sid):
        with lock:
            s = sitios.get(sid)
            if s is None:
                return
            cfg = {k: s[k] for k in ("url", "metodo", "timeout_s", "cod_min", "cod_max", "texto")}
        r = {"ok": False, "codigo": None, "ms": None, "error": "Error interno", "ssl_dias": None}
        try:
            r = comprobar(cfg)
        finally:
            ahora = datetime.utcnow()
            cambio, ssl_aviso = None, None
            with lock:
                s = sitios.get(sid)
                if s is not None:
                    s["en_curso"] = False
                    cambio = aplicar(s, r, ahora)
                    reintento = (not r["ok"]) and s["estado"] != "abajo"
                    s["proximo"] = time.monotonic() + (REINTENTO_S if reintento else s["intervalo_min"] * 60)
                    nombre, url = s["nombre"], s["url"]
                    if r["ssl_dias"] is not None and r["ssl_dias"] <= SSL_AVISO_DIAS and s["ssl_avisado"] != _hoy():
                        s["ssl_avisado"] = _hoy()
                        ssl_aviso = r["ssl_dias"]
            if s is not None:
                if cambio:
                    persistir(sid, cambio, ahora, nombre, url, r["error"])
                if ssl_aviso is not None:
                    avisar_ssl(sid, nombre, ssl_aviso)

    def bucle():
        while True:
            time.sleep(5)
            try:
                ahora = time.monotonic()
                with lock:
                    listos = [s["id"] for s in sitios.values() if s["activo"] and not s["en_curso"] and s["proximo"] <= ahora]
                    for sid in listos:
                        sitios[sid]["en_curso"] = True
                for sid in listos:
                    pool.submit(ejecutar, sid)
            except Exception as e:
                app.logger.error("Monitor: %s", e)

    def _iniciar():
        if estado["listo"] or time.time() - estado["intento"] < 60:
            return
        estado["intento"] = time.time()
        try:
            with app.app_context():
                asegurar_tablas()
                cargar()
            estado["listo"] = True
            threading.Thread(target=bucle, daemon=True, name="monitor-http").start()
        except Exception as e:
            app.logger.warning("Monitor: no se pudo iniciar (se reintenta en 1 min): %s", e)

    def _volcar():
        if not estado["listo"]:
            return
        with lock:
            lotes = []
            for s in sitios.values():
                for d in s["pend"]:
                    lotes.append((s["id"], d))
                if s["dia"]["sucio"]:
                    lotes.append((s["id"], dict(s["dia"])))
        if not lotes:
            return                                  # nada nuevo: no se toca la base (Neon sigue dormido)
        try:
            for sid, d in lotes:
                fila = db.session.get(MonitorDia, (sid, d["fecha"]))
                if fila is None:
                    if db.session.get(MonitorSitio, sid) is None:
                        continue
                    fila = MonitorDia(sitio_id=sid, fecha=d["fecha"])
                    db.session.add(fila)
                fila.checks, fila.ok, fila.ms_total = d["n"], d["ok"], d["ms"]
            hoy = _hoy()
            if estado["limpieza"] != hoy:
                MonitorDia.query.filter(MonitorDia.fecha < hoy - timedelta(days=CONSERVAR_DIAS)).delete()
                estado["limpieza"] = hoy
            db.session.commit()
            with lock:
                for sid, d in lotes:
                    s = sitios.get(sid)
                    if s is None:
                        continue
                    if s["dia"]["fecha"] == d["fecha"] and s["dia"]["n"] == d["n"]:
                        s["dia"]["sucio"] = False
                    s["pend"] = [p for p in s["pend"] if p["fecha"] != d["fecha"]]
        except Exception as e:
            db.session.rollback()
            app.logger.warning("Monitor: no se pudo guardar el conteo diario: %s", e)

    _api["iniciar"], _api["volcar"] = _iniciar, _volcar

    # --- API ------------------------------------------------------------------------------------
    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "") == "admin"

    def negado():
        return jsonify(ok=False, error="Solo administradores."), 403

    def cuerpo():
        if not es_admin():
            return None, negado()
        d = request.get_json(silent=True)
        if not isinstance(d, dict):
            return None, (jsonify(ok=False, error="Solicitud no válida."), 400)
        return d, None

    def publico(s):
        n, ok = s["dia"]["n"], s["dia"]["ok"]
        return {"id": s["id"], "nombre": s["nombre"], "url": s["url"], "metodo": s["metodo"],
                "intervalo_min": s["intervalo_min"], "timeout_s": s["timeout_s"], "cod_min": s["cod_min"],
                "cod_max": s["cod_max"], "texto": s["texto"], "activo": s["activo"], "estado": s["estado"],
                "fallos": s["fallos"], "desde": _iso(s["desde"]), "ultimo": _iso(s["ultimo"]), "codigo": s["codigo"],
                "ms": s["ms"], "error": s["error"], "ssl_dias": s["ssl_dias"],
                "hoy": round(ok * 100 / n, 2) if n else None, "checks_hoy": n,
                "serie": [[1 if o else 0, ms] for (_, o, ms) in list(s["hist"])[-60:]]}

    @bp.route("/monitor")
    def pagina():
        if not es_admin():
            return "Solo administradores.", 403
        return render_template("monitor.html", intervalos=INTERVALOS, timeout_max=TIMEOUT_MAX)

    @bp.route("/api/monitor/estado")
    def api_estado():
        """Lo que hay en memoria. NO consulta la base: se puede llamar cada 30 s sin despertar a Neon."""
        if not es_admin():
            return negado()
        _iniciar()
        with lock:
            lista = sorted((publico(s) for s in sitios.values()), key=lambda x: x["nombre"].lower())
        return jsonify(ok=True, listo=estado["listo"], sitios=lista, ahora=_iso(datetime.utcnow()))

    @bp.route("/api/monitor/resumen")
    def api_resumen():
        """Disponibilidad de 7 y 30 días y últimas caídas (esta sí lee la base)."""
        if not es_admin():
            return negado()
        hoy = _hoy()
        try:
            filas = MonitorDia.query.filter(MonitorDia.fecha >= hoy - timedelta(days=30), MonitorDia.fecha < hoy).all()
            caidas = MonitorCaida.query.order_by(MonitorCaida.inicio.desc()).limit(15).all()
            nombres = {f.id: f.nombre for f in MonitorSitio.query.all()}
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error="No se pudo leer el historial: " + str(e)[:150]), 500
        acum = {}
        for d in filas:
            a = acum.setdefault(d.sitio_id, {"t7": 0, "o7": 0, "t30": 0, "o30": 0, "ms": 0.0, "mo": 0})
            a["t30"] += d.checks or 0
            a["o30"] += d.ok or 0
            a["ms"] += d.ms_total or 0
            a["mo"] += d.ok or 0
            if d.fecha >= hoy - timedelta(days=7):
                a["t7"] += d.checks or 0
                a["o7"] += d.ok or 0
        with lock:                                  # lo de hoy aún puede estar solo en memoria
            for s in sitios.values():
                a = acum.setdefault(s["id"], {"t7": 0, "o7": 0, "t30": 0, "o30": 0, "ms": 0.0, "mo": 0})
                n, ok = s["dia"]["n"], s["dia"]["ok"]
                if s["dia"]["fecha"] == hoy:
                    a["t7"] += n; a["o7"] += ok; a["t30"] += n; a["o30"] += ok; a["ms"] += s["dia"]["ms"]; a["mo"] += ok
        pct = lambda o, t: round(o * 100 / t, 2) if t else None
        res = {str(sid): {"u7": pct(a["o7"], a["t7"]), "u30": pct(a["o30"], a["t30"]),
                          "ms30": round(a["ms"] / a["mo"]) if a["mo"] else None} for sid, a in acum.items()}
        lista = [{"sitio": nombres.get(c.sitio_id, "(eliminado)"), "inicio": _iso(c.inicio), "fin": _iso(c.fin),
                  "motivo": c.motivo, "duracion_s": ((c.fin or datetime.utcnow()) - c.inicio).total_seconds()} for c in caidas]
        return jsonify(ok=True, sitios=res, caidas=lista)

    @bp.route("/api/monitor/probar", methods=["POST"])
    def api_probar():
        """Visita la dirección una vez y dice qué pasó, sin guardar nada (para probar antes de registrar)."""
        d, err = cuerpo()
        if err:
            return err
        try:
            cfg = validar(d)
        except ValueError as e:
            return jsonify(ok=False, error=str(e)), 400
        return jsonify(ok=True, resultado=comprobar(cfg))

    @bp.route("/api/monitor/sitios", methods=["POST"])
    def api_crear():
        d, err = cuerpo()
        if err:
            return err
        try:
            cfg = validar(d)
        except ValueError as e:
            return jsonify(ok=False, error=str(e)), 400
        try:
            asegurar_tablas()
            if MonitorSitio.query.count() >= MAX_SITIOS:
                return jsonify(ok=False, error=f"Máximo {MAX_SITIOS} sitios."), 400
            f = MonitorSitio(**cfg, activo=True, estado="nuevo")
            db.session.add(f)
            db.session.flush()
            registrar("crear", "Monitor", f.id, cfg["url"][:200])
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error="No se pudo guardar: " + str(e)[:150]), 500
        with lock:
            sitios[f.id] = runtime(f)
        _iniciar()
        return jsonify(ok=True, id=f.id)

    @bp.route("/api/monitor/sitios/<int:sid>/editar", methods=["POST"])
    def api_editar(sid):
        d, err = cuerpo()
        if err:
            return err
        try:
            cfg = validar(d)
        except ValueError as e:
            return jsonify(ok=False, error=str(e)), 400
        try:
            f = db.session.get(MonitorSitio, sid)
            if f is None:
                return jsonify(ok=False, error="No existe ese sitio."), 404
            cambio_url = (f.url, f.metodo) != (cfg["url"], cfg["metodo"])
            for k, v in cfg.items():
                setattr(f, k, v)
            if cambio_url:
                f.estado, f.desde = "nuevo", None
            registrar("editar", "Monitor", sid, cfg["url"][:200])
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error="No se pudo guardar: " + str(e)[:150]), 500
        with lock:
            s = sitios.get(sid)
            if s:
                s.update(cfg)
                if cambio_url:
                    s.update(estado="nuevo", desde=None, fallos=0, error=None, codigo=None)
                s["proximo"] = 0.0
        return jsonify(ok=True)

    @bp.route("/api/monitor/sitios/<int:sid>/pausar", methods=["POST"])
    def api_pausar(sid):
        d, err = cuerpo()
        if err:
            return err
        activo = d.get("activo") is True
        try:
            f = db.session.get(MonitorSitio, sid)
            if f is None:
                return jsonify(ok=False, error="No existe ese sitio."), 404
            f.activo = activo
            registrar("reanudar" if activo else "pausar", "Monitor", sid, f.url[:200])
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error="No se pudo guardar: " + str(e)[:150]), 500
        with lock:
            s = sitios.get(sid)
            if s:
                s["activo"] = activo
                s["proximo"] = 0.0
        return jsonify(ok=True)

    @bp.route("/api/monitor/sitios/<int:sid>/revisar", methods=["POST"])
    def api_revisar(sid):
        d, err = cuerpo()
        if err:
            return err
        with lock:
            s = sitios.get(sid)
            if not s:
                return jsonify(ok=False, error="No existe ese sitio."), 404
            s["proximo"] = 0.0
        return jsonify(ok=True)

    @bp.route("/api/monitor/sitios/<int:sid>/eliminar", methods=["POST"])
    def api_eliminar(sid):
        d, err = cuerpo()
        if err:
            return err
        if d.get("confirmar") is not True:
            return jsonify(ok=False, error="Falta la confirmación."), 400
        try:
            f = db.session.get(MonitorSitio, sid)
            if f is None:
                return jsonify(ok=False, error="No existe ese sitio."), 404
            url = f.url
            MonitorCaida.query.filter_by(sitio_id=sid).delete()
            MonitorDia.query.filter_by(sitio_id=sid).delete()
            db.session.delete(f)
            registrar("eliminar", "Monitor", sid, url[:200])
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify(ok=False, error="No se pudo eliminar: " + str(e)[:150]), 500
        with lock:
            sitios.pop(sid, None)
        return jsonify(ok=True)

    return bp
