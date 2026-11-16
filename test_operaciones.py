"""Pruebas de operaciones.py y del formato de CPU/RAM. Sin red ni base de datos. Ejecutar: python -m unittest test_operaciones -v"""
import sys
import types
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace as NS

try:
    import flask_login  # noqa: F401
except ImportError:             # solo para poder probar fuera del proyecto
    m = types.ModuleType("flask_login")
    m.current_user = NS(is_authenticated=False)
    sys.modules["flask_login"] = m

import jinja2
import operaciones as op
import render_panel as rp


def aviso(tipo, titulo, urgente=False, leida=False, minutos=0):
    return NS(tipo=tipo, titulo=titulo, urgente=urgente, leida=leida, hora=datetime(2026, 11, 15, 12, 0) - timedelta(minutes=minutos))


class PruebasPorcentaje(unittest.TestCase):
    def test_uso_pequeno_ya_no_parece_cero(self):
        self.assertEqual(rp._pct(0), "0%")
        self.assertEqual(rp._pct(0.04), "<0.1%")
        self.assertEqual(rp._pct(0.3), "0.3%")
        self.assertEqual(rp._pct(9.96), "10.0%")
        self.assertEqual(rp._pct(22.4), "22%")
        self.assertEqual(rp._pct(None), "—")

    def test_texto_cpu_con_decimales(self):
        c = rp._calc({("r", "i"): [0.00045, 0.0004]}, {("r", "i"): [0.15]}, "r")
        self.assertEqual(rp._txt_cpu(c), "0.3% de 0.15 CPU · pico 1 h: 0.3%")


class PruebasAgrupar(unittest.TestCase):
    def test_junta_repetidos_y_ordena_por_prioridad(self):
        filas = [aviso("Monitor", "Caído: web", urgente=True, minutos=1),
                 aviso("Cobro", "Cobro próximo", leida=True, minutos=2),
                 aviso("Monitor", "Caído: web", urgente=True, minutos=3),
                 aviso("Vencimiento", "SSL por vencer", minutos=4)]
        g = op.agrupar(filas)
        self.assertEqual([x["n"].titulo for x in g], ["Caído: web", "SSL por vencer", "Cobro próximo"])
        self.assertEqual(g[0]["veces"], 2)
        self.assertEqual(g[0]["sin_leer"], 2)
        self.assertTrue(g[0]["urgente"])
        self.assertEqual(g[0]["n"].hora, filas[0].hora)       # muestra el más reciente
        self.assertEqual(g[0]["primera"], filas[2].hora)      # y desde cuándo empezó

    def test_lista_vacia(self):
        self.assertEqual(op.agrupar([]), [])


class PruebasUtiles(unittest.TestCase):
    def test_enlaces_peligrosos_se_descartan(self):
        self.assertEqual(op.enlace_seguro("javascript:alert(1)"), "")
        self.assertEqual(op.enlace_seguro("data:text/html,x"), "")
        self.assertEqual(op.enlace_seguro("//evil.com"), "")
        self.assertEqual(op.enlace_seguro(""), "")
        self.assertEqual(op.enlace_seguro(None), "")
        self.assertEqual(op.enlace_seguro("https://dashboard.render.com"), "https://dashboard.render.com")

    def test_conversion_de_zona(self):
        d = datetime(2026, 11, 17, 20, 0)
        self.assertEqual(op.a_local(op.a_utc(d)), d)
        if op.UTC_OFFSET == -6:
            self.assertEqual(op.a_utc(d), datetime(2026, 11, 18, 2, 0))     # el aviso de Render: 8 pm CST = 2:00 UTC

    def test_api_sin_registrar_no_rompe(self):
        op._api.clear()
        self.assertFalse(op.silenciado("Monitor"))
        self.assertIsNone(op.mantenimiento_activo())
        self.assertEqual(op.revisar(), 0)


class PruebasPlantillas(unittest.TestCase):
    """Las tres plantillas deben compilar y mostrarse con datos de ejemplo (con una base mínima en lugar de base.html)."""

    def entorno(self):
        import os
        carpeta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        base = jinja2.DictLoader({"base.html": "{% block content %}{% endblock %}"})
        return jinja2.Environment(loader=jinja2.ChoiceLoader([base, jinja2.FileSystemLoader(carpeta)]), autoescape=True)

    def test_mantenimientos(self):
        m = NS(id=1, proveedor="Render", titulo="Infra", inicio=datetime(2026, 11, 18, 2), fin=datetime(2026, 11, 18, 5), afecta="Reinicios", notas=None)
        h = self.entorno().get_template("mantenimientos.html").render(
            en_curso=[], proximos=[m], pasados=[], proveedores=op.PROVEEDORES, a_local=op.a_local,
            pre={k: "" for k in ("proveedor", "titulo", "inicio", "fin", "afecta")}, utc_offset=-6, estatus=op.ESTADO_ESTATUS, mensaje="creado")
        self.assertIn("Render", h)
        self.assertIn("17/11/2026 20:00", h)

    def test_atajos(self):
        h = self.entorno().get_template("atajos.html").render(
            grupos={"Hosting": [{"nombre": "Render", "proveedor": "Render", "url": "https://dashboard.render.com"}]},
            faltan=[{"proveedor": "Neon", "url": "https://console.neon.tech"}],
            plataformas=[{"id": 1, "nombre": "Zmarthket", "sitio": "https://zmarthket.onrender.com", "repo": "", "stack": "Python"}],
            estatus=op.ESTADO_ESTATUS, total=1)
        self.assertIn("Abrir consola", h)
        self.assertIn("Zmarthket", h)

    def test_notificaciones(self):
        n = aviso("Monitor", "Caído: web", urgente=True)
        n.url, n.cuerpo, n.entregada, n.intentos = "/monitor", "x", False, 0
        g = op.agrupar([n, n])
        h = self.entorno().get_template("notificaciones.html").render(
            filas=[n], grupos=g, vista="todas", cuentas={"todas": 2, "criticas": 2, "avisos": 0, "sinleer": 2}, tipos=["Monitor"],
            silencios=[{"tipo": "Cobro", "hasta": datetime(2026, 11, 15, 18)}], dispositivos=[], configurado=True, problema="")
        self.assertIn("×2", h)
        self.assertIn("Crítica", h)
        self.assertIn("Silenciado", h)


if __name__ == "__main__":
    unittest.main()
