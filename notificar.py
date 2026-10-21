"""Avisos al dueño cuando Zedith captura un pedido. Telegram y/o correo; ambos opcionales.

Variables de entorno (Render -> Environment):
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID   aviso instantáneo al celular (recomendado)
  SMTP_USER, SMTP_PASS                   correo (Gmail: usa una "contraseña de aplicación")
  AVISO_EMAIL                            a quién llega el correo (por defecto, SMTP_USER)
  SMTP_HOST, SMTP_PORT                   opcionales (por defecto smtp.gmail.com y 465)
Si no hay ninguna configurada, simplemente no avisa.
"""
import logging
import os
import smtplib
import threading
import urllib.parse
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("notificar")


def _telegram(texto):
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat):
        return
    datos = urllib.parse.urlencode({"chat_id": chat.strip(), "text": texto[:3900]}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token.strip()}/sendMessage", data=datos)
    urllib.request.urlopen(req, timeout=10).read()


def _correo(asunto, texto):
    usuario, clave = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
    if not (usuario and clave):
        return
    m = EmailMessage()
    m["Subject"], m["From"] = asunto, usuario
    m["To"] = os.environ.get("AVISO_EMAIL") or usuario
    m.set_content(texto)
    with smtplib.SMTP_SSL(os.environ.get("SMTP_HOST", "smtp.gmail.com"),
                          int(os.environ.get("SMTP_PORT", "465")), timeout=15) as s:
        s.login(usuario, clave.replace(" ", ""))
        s.send_message(m)


def avisar(asunto, texto):
    """Envía en segundo plano para no hacer esperar al visitante; un fallo nunca rompe el chat."""
    def trabajo():
        for nombre, envio in (("Telegram", lambda: _telegram(f"{asunto}\n\n{texto}")),
                              ("correo", lambda: _correo(asunto, texto))):
            try:
                envio()
            except Exception as e:
                log.warning("Aviso por %s falló: %s", nombre, e)
    threading.Thread(target=trabajo, daemon=True).start()
