"""Genera las llaves VAPID para las alertas push. Córrelo UNA vez en tu computadora.

    python generar_vapid.py

Copia las dos llaves en Render -> Environment. La privada es secreta: no la subas a GitHub ni la compartas.
Si algún día cambias estas llaves, hay que volver a activar las alertas en cada dispositivo.
"""
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


k = ec.generate_private_key(ec.SECP256R1())
privada = b64(k.private_numbers().private_value.to_bytes(32, "big"))
publica = b64(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
print("VAPID_PUBLIC_KEY=" + publica)
print("VAPID_PRIVATE_KEY=" + privada)
print("VAPID_CONTACT=mailto:tu-correo@ejemplo.com")
