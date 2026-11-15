#!/usr/bin/env python3
"""restaurar_respaldo.py — Restaura en una base un respaldo del panel en formato JSON (el que genera respaldos.py).

Independiente de la app: solo necesita SQLAlchemy y el driver de la base (psycopg2 para Postgres).
Para archivos .enc hace falta `cryptography`; para r2:// hace falta `boto3`.

IMPORTANTE
  * El respaldo JSON trae los DATOS, no el esquema. La base de destino debe tener ya sus tablas. Forma práctica:
    crea una rama vacía en Neon y arranca la app una vez contra ella para que cree el esquema:
        DATABASE_URL=<destino> FICHAS_SIN_RESPALDO=1 python -c "import app"
    Esa primera carga siembra planes y el usuario admin; por eso se restaura con --vaciar.
  * Por seguridad NUNCA escribe en la base de producción (la de DATABASE_URL / BACKUP_DATABASE_URL) salvo que
    agregues --permitir-produccion.
  * Sin --confirmar solo hace un ensayo: lee el archivo, compara con el esquema del destino y no escribe nada.
  * Todo se escribe en UNA transacción: si algo falla o los conteos no cuadran, no queda nada a medias.
  * Si el respaldo es de pg_dump (empieza con PGDMP) usa pg_restore, no este script.

Uso
  python restaurar_respaldo.py respaldo.jsonl.gz.enc --destino postgresql://usuario:clave@host/db            (ensayo)
  python restaurar_respaldo.py respaldo.jsonl.gz.enc --destino postgresql://... --vaciar --confirmar         (real)
  python restaurar_respaldo.py r2://panel/2026/11/zedyth_...jsonl.gz.enc --destino ... --confirmar
Clave de cifrado: --clave o la variable BACKUP_KEY. Para r2:// se usan las variables BACKUP_R2_*.
"""
import argparse
import base64
import gzip
import json
import os
import sys
import tempfile
from datetime import datetime, date, time as dtime
from decimal import Decimal
from urllib.parse import urlsplit

LOTE = 500


# --- lectura del archivo (sin SQLAlchemy: se puede probar sola) -------------------------------------------
def preparar_archivo(origen, clave, tmp):
    """Devuelve la ruta de un .jsonl.gz legible: baja de R2 y/o descifra según haga falta."""
    ruta = origen
    if origen.startswith("r2://"):
        import boto3
        from botocore.config import Config
        c = {k: (os.environ.get(f"BACKUP_R2_{k}") or "").strip() for k in ("ACCOUNT_ID", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY", "BUCKET")}
        if not all(c.values()):
            sys.exit("Faltan las variables BACKUP_R2_* para bajar de R2.")
        s3 = boto3.client("s3", endpoint_url=f"https://{c['ACCOUNT_ID']}.r2.cloudflarestorage.com",
                          aws_access_key_id=c["ACCESS_KEY_ID"], aws_secret_access_key=c["SECRET_ACCESS_KEY"],
                          config=Config(signature_version="s3v4", region_name="auto"))
        ruta = os.path.join(tmp, "bajado")
        s3.download_file(c["BUCKET"], origen[len("r2://"):], ruta)
        print(f"Descargado de R2: {os.path.getsize(ruta):,} bytes")
    elif not os.path.exists(origen):
        sys.exit(f"No existe el archivo: {origen}")
    with open(ruta, "rb") as f:
        cabecera = f.read(5)
    if cabecera == b"PGDMP":
        sys.exit("Este respaldo es de pg_dump: restáuralo con  pg_restore --no-owner -d <destino> archivo.dump")
    if origen.endswith(".enc") or (cabecera[:2] != b"\x1f\x8b"):          # no es gzip: debe estar cifrado
        if not clave:
            sys.exit("El archivo está cifrado: pasa --clave o define BACKUP_KEY.")
        from cryptography.fernet import Fernet, InvalidToken
        with open(ruta, "rb") as f:
            datos = f.read()
        try:
            claro = Fernet(clave).decrypt(datos)
        except (InvalidToken, ValueError):
            sys.exit("La clave no abre este archivo (¿es la BACKUP_KEY con la que se respaldó?).")
        ruta = os.path.join(tmp, "descifrado.jsonl.gz")
        with open(ruta, "wb") as f:
            f.write(claro)
    return ruta


def leer_cabeceras(ruta):
    """{tabla: {"columnas": [...], "filas": n}} recorriendo el archivo una vez. Lanza ValueError si está dañado."""
    info = {}
    with gzip.open(ruta, "rt", encoding="utf-8") as f:
        for n, linea in enumerate(f, 1):
            o = json.loads(linea)
            if "columnas" in o:
                info[o["tabla"]] = {"columnas": o["columnas"], "filas": 0}
            elif "r" in o:
                if o["t"] not in info:
                    raise ValueError(f"fila de una tabla sin cabecera (línea {n})")
                if len(o["r"]) != len(info[o["t"]]["columnas"]):
                    raise ValueError(f"fila con columnas de más o de menos en «{o['t']}» (línea {n})")
                info[o["t"]]["filas"] += 1
    if not info:
        raise ValueError("el archivo no contiene tablas")
    return info


def filas_de(ruta, tabla, columnas):
    """Genera dicts {columna: valor} de una tabla (una pasada filtrada por prefijo; barato aunque haya muchas tablas)."""
    prefijo = '{"t": ' + json.dumps(tabla) + ', "r": '
    with gzip.open(ruta, "rt", encoding="utf-8") as f:
        for linea in f:
            if linea.startswith(prefijo):
                yield dict(zip(columnas, json.loads(linea)["r"]))


# --- conversión de valores según el tipo real de la columna de destino --------------------------------------
def convertir(valor, tipo, T):
    if valor is None:
        return None
    if isinstance(valor, dict) and set(valor) == {"b64"} and not isinstance(tipo, T.JSON):
        return base64.b64decode(valor["b64"])
    if isinstance(valor, str):
        if isinstance(tipo, T.DateTime):
            return datetime.fromisoformat(valor)
        if isinstance(tipo, T.Date):
            return date.fromisoformat(valor)
        if isinstance(tipo, T.Time):
            return dtime.fromisoformat(valor)
        if isinstance(tipo, T.Float):
            return float(valor)
        if isinstance(tipo, T.Numeric):
            return Decimal(valor)
    return valor


def _misma_base(a, b):
    ua, ub = urlsplit(a), urlsplit(b)
    return (ua.hostname, ua.port or 5432, ua.path.strip("/")) == (ub.hostname, ub.port or 5432, ub.path.strip("/"))


# --- restauración -----------------------------------------------------------------------------------------------
def restaurar(args):
    from sqlalchemy import create_engine, MetaData, text, types as T, func, select

    clave = args.clave or os.environ.get("BACKUP_KEY", "").strip()
    with tempfile.TemporaryDirectory(prefix="zedyth_rest_") as tmp:
        ruta = preparar_archivo(args.archivo, clave, tmp)
        try:
            info = leer_cabeceras(ruta)
        except (ValueError, OSError, json.JSONDecodeError) as e:
            sys.exit(f"El archivo está dañado: {e}")
        total = sum(v["filas"] for v in info.values())
        print(f"Respaldo legible: {len(info)} tablas, {total:,} filas.")

        if not args.permitir_produccion:
            for var in ("DATABASE_URL", "BACKUP_DATABASE_URL"):
                prod = (os.environ.get(var) or "").strip()
                if prod and _misma_base(args.destino, prod):
                    sys.exit(f"El destino es la base de PRODUCCIÓN ({var}). Restaura en una rama de prueba, "
                             f"o agrega --permitir-produccion si de verdad quieres sobrescribirla.")

        url = args.destino.replace("postgres://", "postgresql://", 1)
        engine = create_engine(url)
        meta = MetaData()
        meta.reflect(bind=engine)
        faltan = sorted(t for t in info if t not in meta.tables)
        if faltan:
            sys.exit("El destino no tiene estas tablas (crea el esquema primero, ver la cabecera del script): " + ", ".join(faltan))
        extra = sorted(t for t in meta.tables if t not in info)
        if extra:
            print("Aviso: el respaldo no trae estas tablas y quedarán como están: " + ", ".join(extra))
        orden = [t for t in meta.sorted_tables if t.name in info]          # padres antes que hijos

        problemas = []
        for t in orden:
            nuevas = [c for c in info[t.name]["columnas"] if c not in t.c]
            if nuevas:
                problemas.append(f"{t.name}: el destino no tiene las columnas {nuevas}")
        if problemas:
            sys.exit("El esquema del destino no coincide con el respaldo:\n  " + "\n  ".join(problemas))

        with engine.connect() as conn:
            ocupadas = {}
            for t in orden:
                n = conn.execute(select(func.count()).select_from(t)).scalar()
                if n:
                    ocupadas[t.name] = n
        print("\nTabla".ljust(34) + "en respaldo".rjust(13) + "en destino".rjust(13))
        for t in orden:
            print(f"  {t.name}".ljust(33) + f"{info[t.name]['filas']:>13,}{ocupadas.get(t.name, 0):>13,}")
        if ocupadas and not args.vaciar:
            sys.exit("\nEl destino ya tiene datos en las tablas marcadas arriba. Usa --vaciar para borrarlas antes de restaurar "
                     "(solo en una base de prueba).")
        if not args.confirmar:
            print("\nENSAYO: todo coincide y no se escribió nada. Agrega --confirmar para restaurar de verdad.")
            return

        with engine.begin() as conn:                                        # una sola transacción
            if args.vaciar:
                for t in reversed(orden):                                    # hijos antes que padres
                    conn.execute(t.delete())
            for t in orden:
                cols = info[t.name]["columnas"]
                lote = []
                for fila in filas_de(ruta, t.name, cols):
                    lote.append({c: convertir(v, t.c[c].type, T) for c, v in fila.items()})
                    if len(lote) >= LOTE:
                        conn.execute(t.insert(), lote)
                        lote = []
                if lote:
                    conn.execute(t.insert(), lote)
            if engine.dialect.name == "postgresql":                          # que los próximos INSERT no choquen con ids ya usados
                for t in orden:
                    pk = list(t.primary_key.columns)
                    if len(pk) == 1 and isinstance(pk[0].type, T.Integer):
                        seq = conn.execute(text("SELECT pg_get_serial_sequence(:t, :c)"),
                                           {"t": f'"{t.name}"', "c": pk[0].name}).scalar()
                        if seq:
                            col = pk[0].name.replace('"', '""')
                            conn.execute(text(f'SELECT setval(:s, COALESCE((SELECT MAX("{col}") FROM "{t.name}"), 1), '
                                               f'(SELECT MAX("{col}") FROM "{t.name}") IS NOT NULL)'), {"s": seq})
            malas = []
            for t in orden:                                                  # verificación antes de confirmar
                n = conn.execute(select(func.count()).select_from(t)).scalar()
                if n != info[t.name]["filas"]:
                    malas.append(f"{t.name}: respaldo {info[t.name]['filas']:,} ≠ destino {n:,}")
            if malas:
                raise RuntimeError("Los conteos no cuadran, se cancela todo:\n  " + "\n  ".join(malas))
        print(f"\nRESTAURACIÓN COMPLETA: {total:,} filas en {len(orden)} tablas; conteos verificados.")


def main():
    ap = argparse.ArgumentParser(description="Restaura un respaldo JSON del panel de ZEDYTH.")
    ap.add_argument("archivo", help="ruta local (.jsonl.gz o .jsonl.gz.enc) o r2://ruta/en/el/bucket")
    ap.add_argument("--destino", required=True, help="URL de la base de destino (postgresql://… o sqlite:///…)")
    ap.add_argument("--clave", help="clave Fernet si el archivo está cifrado (o variable BACKUP_KEY)")
    ap.add_argument("--vaciar", action="store_true", help="borra los datos de las tablas del destino antes de restaurar")
    ap.add_argument("--confirmar", action="store_true", help="sin esto solo hace un ensayo y no escribe nada")
    ap.add_argument("--permitir-produccion", action="store_true", help="permite escribir en la base de DATABASE_URL (peligroso)")
    restaurar(ap.parse_args())


if __name__ == "__main__":
    main()
