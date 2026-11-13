import os, ssl, subprocess, threading, time, http.server, socketserver, sys
from collections import deque
from datetime import datetime
import types
fl = types.ModuleType('flask_login'); fl.current_user = None; sys.modules['flask_login'] = fl
import monitor as M

ok_n = 0
def check(cond, msg):
    global ok_n
    print(("OK   " if cond else "FALLA"), msg)
    if not cond: sys.exit(1)
    ok_n += 1

# ---------- validación ----------
v = M.validar({"url": "https://ejemplo.com/healthz", "intervalo_min": "5"})
check(v["nombre"] == "ejemplo.com" and v["metodo"] == "GET" and v["cod_max"] == 399, "validar: valores por defecto")
for malo, por_que in [({"url": "ftp://x.com"}, "esquema ftp"), ({"url": "https://"}, "sin dominio"),
                      ({"url": "https://u:p@x.com"}, "usuario en URL"), ({"url": "https://x.com:99999"}, "puerto inválido"),
                      ({"url": "https://x.com", "intervalo_min": 3}, "intervalo no permitido"),
                      ({"url": "https://x.com", "cod_min": 500, "cod_max": 200}, "rango invertido"),
                      ({"url": "https://x.com", "metodo": "POST"}, "método POST"),
                      ({"url": "https://x.com", "metodo": "HEAD", "texto": "hola"}, "HEAD con texto"),
                      ({"url": "https://x.com", "timeout_s": 99}, "timeout enorme"),
                      ({"url": "https://x.com/" + "a" * 400}, "URL larguísima")]:
    try: M.validar(malo); check(False, "debía rechazar " + por_que)
    except ValueError: check(True, "validar rechaza: " + por_que)

# ---------- anti-SSRF ----------
os.environ.pop("MONITOR_PERMITIR_PRIVADAS", None)
for host in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "::1", "::ffff:10.0.0.1", "172.16.0.1", "100.64.0.1", "0.0.0.0"]:
    try: M._resolver(host, 80); check(False, "debía bloquear " + host)
    except PermissionError: check(True, "bloquea IP interna " + host)
check(M._resolver("8.8.8.8", 443) == "8.8.8.8", "permite IP pública 8.8.8.8")
r = M.comprobar({"url": "http://127.0.0.1:9/", "timeout_s": 2})
check(not r["ok"] and "privada" in r["error"], "comprobar() no visita localhost sin permiso: " + r["error"])

# ---------- servidor local de prueba ----------
os.environ["MONITOR_PERMITIR_PRIVADAS"] = "1"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/lento": time.sleep(3); code, body = 200, b"tarde"
        elif self.path == "/500": code, body = 500, b"error"
        elif self.path == "/404": code, body = 404, b"no"
        elif self.path == "/redir":
            self.send_response(302); self.send_header("Location", "http://127.0.0.1:1/secreto"); self.end_headers(); return
        else: code, body = 200, b"<html>Bienvenido a ZEDYTH, todo en orden</html>"
        self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_HEAD(self):
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
srv = S(("127.0.0.1", 0), H); puerto = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{puerto}"
def c(path="/", **kw): return M.comprobar({"url": base + path, "timeout_s": 5, **kw})

r = c(); check(r["ok"] and r["codigo"] == 200 and r["ms"] is not None, f"GET 200 correcto ({r['ms']} ms)")
r = c("/500"); check(not r["ok"] and r["codigo"] == 500 and "500" in r["error"], "500 se marca como caída: " + r["error"])
r = c("/404", cod_min=200, cod_max=499); check(r["ok"], "rango personalizado 200-499 acepta 404")
r = c("/redir"); check(r["ok"] and r["codigo"] == 302, "redirección NO se sigue (302 cuenta como en línea)")
r = c(texto="todo en orden"); check(r["ok"], "texto esperado encontrado (sin importar mayúsculas)")
r = c(texto="NO EXISTE"); check(not r["ok"] and "texto" in r["error"], "texto ausente => falla: " + r["error"])
r = c(metodo="HEAD"); check(r["ok"] and r["codigo"] == 200, "HEAD funciona")
t = time.time(); r = c("/lento", timeout_s=1); check(not r["ok"] and "1 s" in r["error"] and time.time() - t < 2.5, "timeout: " + r["error"])
r = M.comprobar({"url": "http://127.0.0.1:1/", "timeout_s": 2}); check(not r["ok"] and "rechazada" in r["error"], "puerto cerrado: " + r["error"])
r = M.comprobar({"url": "http://dominio-que-no-existe-zedyth.invalid/", "timeout_s": 2}); check(not r["ok"] and "DNS" in r["error"], "DNS inexistente: " + r["error"])

# ---------- HTTPS: certificado inválido y válido (confiado) ----------
subprocess.run("openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 20 -subj /CN=localhost "
               "-addext subjectAltName=DNS:localhost >/dev/null 2>&1", shell=True, check=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("c.pem", "k.pem")
hs = S(("127.0.0.1", 0), H); hs.socket = ctx.wrap_socket(hs.socket, server_side=True)
hp = hs.server_address[1]; threading.Thread(target=hs.serve_forever, daemon=True).start()
r = M.comprobar({"url": f"https://localhost:{hp}/", "timeout_s": 5})
check(not r["ok"] and "Certificado SSL" in r["error"], "HTTPS autofirmado no confiable => falla: " + r["error"])
os.environ["SSL_CERT_FILE"] = os.path.abspath("c.pem")
r = M.comprobar({"url": f"https://localhost:{hp}/", "timeout_s": 5})
check(r["ok"] and r["codigo"] == 200, "HTTPS con certificado confiable => ok")
check(r["ssl_dias"] in (19, 20), f"días de vencimiento del certificado leídos: {r['ssl_dias']}")

# ---------- máquina de estados ----------
def nuevo(): return {"estado": "nuevo", "fallos": 0, "desde": None, "hist": deque(maxlen=5), "pend": [],
                     "dia": {"fecha": M._hoy(), "n": 0, "ok": 0, "ms": 0.0, "sucio": False}}
OK = {"ok": True, "codigo": 200, "ms": 100, "error": None, "ssl_dias": None}
MAL = {"ok": False, "codigo": 500, "ms": 50, "error": "x", "ssl_dias": None}
s = nuevo(); ahora = datetime.utcnow()
check(M.aplicar(s, OK, ahora) is None and s["estado"] == "arriba", "nuevo + ok => arriba, sin aviso")
check(M.aplicar(s, MAL, ahora) is None and s["estado"] == "arriba" and s["fallos"] == 1, "1 fallo => aún no se declara caído")
check(M.aplicar(s, MAL, ahora) == "caido" and s["estado"] == "abajo", "2 fallos seguidos => caído (avisa una vez)")
check(M.aplicar(s, MAL, ahora) is None, "sigue caído => no repite el aviso")
check(M.aplicar(s, OK, ahora) == "recuperado" and s["estado"] == "arriba" and s["fallos"] == 0, "ok tras caída => recuperado")
s = nuevo(); M.aplicar(s, OK, ahora); M.aplicar(s, MAL, ahora); M.aplicar(s, OK, ahora); M.aplicar(s, MAL, ahora)
check(s["estado"] == "arriba", "fallo suelto entre éxitos no cuenta como caída")
s = nuevo(); M.aplicar(s, MAL, ahora); check(M.aplicar(s, MAL, ahora) == "caido", "sitio nuevo que nunca respondió => caído al 2º fallo")
c_ = s["dia"]; check(c_["n"] == 2 and c_["ok"] == 0 and c_["sucio"], "contadores del día")
# cambio de día: lo de ayer queda pendiente
s = nuevo(); s["dia"].update(fecha=M._hoy().replace(year=2000), n=7, ok=6, ms=600.0, sucio=True)
M.aplicar(s, OK, ahora)
check(len(s["pend"]) == 1 and s["pend"][0]["n"] == 7 and s["dia"]["n"] == 1, "al cambiar de día se conserva lo de ayer para guardarlo")
print(f"\n{ok_n} comprobaciones correctas")
