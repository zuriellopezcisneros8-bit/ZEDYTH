# Sección A: cambios aplicados

Dependencia nueva (agregar a requirements.txt): `Flask-WTF`
(`cryptography` ya la usas.)

## Variables de entorno nuevas (todas opcionales)
| Variable | Para qué |
|---|---|
| PROXY_SALTOS | Saltos de proxy confiables. Render solo = 1 (por defecto en Render). Con Cloudflare delante = 2. |
| REQUIERE_MFA=1 | Obliga a activar TOTP antes de usar el panel. |
| TOTP_KEY | Clave Fernet para cifrar los secretos TOTP. Si falta, se deriva de SECRET_KEY. |
| CSP_MODO=enforce | La CSP empieza solo reportando (consola del navegador). Cambia a enforce cuando no veas avisos. |
| LOGIN_MAX_PAR / LOGIN_MAX_IP | Intentos fallidos permitidos en 15 min (5 por usuario+IP, 20 por IP). |
| FLASK_DEBUG=1 | Solo local. |
| LEGAL_RAZON, LEGAL_DOMICILIO, LEGAL_JURISDICCION | Ponlas ya; mientras falten, el panel muestra una alerta "Legal". |

## Qué cambió
- CSRF: CSRFProtect en todo POST. El token se inyecta solo en formularios y fetch() del panel (sin editar las 35 plantillas). Quedan exentos los endpoints públicos anónimos con límite por IP y el cron con token.
- Cookies: HttpOnly, SameSite=Lax, Secure en Render, sesión de 12 h, protección "strong".
- Login: bloqueo por usuario+IP y por IP (en la base), fallos y bloqueos en Auditoria con IP, `next` solo si empieza con "/" y no con "//", sesión nueva al entrar, TOTP opcional u obligatorio. Página nueva: /cuenta/seguridad.
- Roles: admin / operador / lectura (rol desconocido = lectura). Lectura no puede hacer POST. Rutas destructivas o de precios solo admin (ENDPOINTS_ADMIN). Cuenta desactivada = sesión cerrada. Decorador `@solo_admin` para rutas nuevas.
- Inteligencia.confidencial: solo admin la ve (lista, detalle, vínculos, sugeridos, plataforma) y solo admin cambia la marca.
- Límites en tabla `contador_limite`: Zedith por IP y tope diario, reseñas, configurador y login. Fallan cerrado si la base falla.
- Vigilante: un solo worker por ronda (arrendamiento en la misma tabla).
- Notificacion.clave: se quitan duplicados y se crea índice UNIQUE al arrancar; el insert que choque se ignora.
- IP: ProxyFix y remote_addr; ya no se lee X-Forwarded-For crudo.
- Cabeceras: HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, CSP, no-store en el panel.
- Longitudes: RFC, razón social, nombre comercial, dirección fiscal, correo y teléfono del cliente se rechazan si pasan del límite; el texto libre se sigue recortando.
- debug solo con FLASK_DEBUG=1.

## Pendiente de la sección A (no incluido)
Respaldos reales con pg_dump a R2, Decimal/idempotencia en dinero, y Flask-Migrate.

---

# Dinero (segunda ronda)

## Qué cambió
- **Decimal de punta a punta.** `Dinero = Numeric(14,2)` (hasta 999,999,999,999.99). Al arrancar, en PostgreSQL convierte solas las columnas de `pago`, `plan`, `suscripcion`, `costo_servicio` e `ingreso_plataforma`. En SQLite local no hace falta.
- **Entradas validadas.** `parse_monto` rechaza vacío, texto, NaN/Infinity, negativos, cero y fuera de rango; `parse_pct` limita el descuento a 0–100; las fechas malas dan error 400 en vez de 500.
- **Cobrar sin doble pago.** Cada formulario POST lleva un token de un solo uso (tabla `token_envio`): el doble clic no repite la operación. Además `cobrar` bloquea la fila de la suscripción y exige la fecha de pago que vio quien dio clic (campo `periodo`); si la fecha ya avanzó responde 409 en lugar de cobrar el siguiente periodo. También se impide cobrar dos veces el mismo periodo. Lo mismo aplica a "Marcar pagado" de proveedores.
- **Anulación con contra-asiento.** Nueva ruta `/pagos/<id>/anular` (solo admin, con motivo): agrega un pago negativo ligado al original, que no se borra ni se edita. Un índice único impide anular dos veces. Si fue un cobro de suscripción y nadie movió la fecha después, la fecha de pago regresa al periodo anterior. "Eliminar ingreso" de plataformas ahora también anula con contra-asiento.
- Los totales (cobrado, pagado, finanzas por plataforma) suman los contra-asientos solos, así que quedan netos.
- Los reportes y proyecciones se calculan en float; solo el libro (pagos, ingresos, tarifas) es Decimal.

## Plantillas modificadas
`avisos.html`, `cliente_detalle.html` (columna de anulación) y `plataforma_detalle.html` (botón Anular).

## Notas
- La primera vez que arranque contra Neon hará los `ALTER COLUMN ... TYPE NUMERIC(14,2)`. Haz antes un respaldo manual (rama de Neon).
- Los pagos viejos no tienen `periodo_desde/hasta`: anularlos no mueve la fecha de pago; ajústala a mano si hace falta.
