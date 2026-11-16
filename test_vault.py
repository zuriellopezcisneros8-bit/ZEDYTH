"""Pruebas de vault.py (lógica pura, sin base de datos ni red). Ejecutar: python -m unittest test_vault -v"""
import sys
import types
import unittest
from datetime import datetime
from types import SimpleNamespace as NS

try:
    import flask_login  # noqa: F401
except ImportError:             # solo para poder probar fuera del proyecto
    m = types.ModuleType("flask_login")
    m.current_user = NS(is_authenticated=False)
    sys.modules["flask_login"] = m

import vault


class PruebasCifrado(unittest.TestCase):
    def test_ida_y_vuelta_y_no_queda_en_claro(self):
        f = vault._fernet("secreto-de-prueba-largo-largo-largo")
        t = vault.cifrar(f, "nmap -sV 10.0.0.5 # contraseña: ñandú")
        self.assertNotIn("nmap", t)
        self.assertEqual(vault.descifrar(f, t), "nmap -sV 10.0.0.5 # contraseña: ñandú")

    def test_clave_distinta_no_descifra(self):
        t = vault.cifrar(vault._fernet("clave-uno-clave-uno-clave-uno-1234"), "dato")
        self.assertIsNone(vault.descifrar(vault._fernet("clave-dos-clave-dos-clave-dos-1234"), t))
        self.assertIsNone(vault.descifrar(vault._fernet("x" * 40), "no es un token"))

    def test_cifrado_distinto_cada_vez(self):
        f = vault._fernet("secreto-de-prueba-largo-largo-largo")
        self.assertNotEqual(vault.cifrar(f, "a"), vault.cifrar(f, "a"))


class PruebasTexto(unittest.TestCase):
    def test_wiki_links(self):
        self.assertEqual(vault.enlaces_wiki("ver [[Auditoría API Zmarthket]] y [[auditoría api zmarthket]] y [[Otra]] [[ ]] [[a\nb]]"),
                         ["Auditoría API Zmarthket", "Otra"])
        self.assertEqual(vault.enlaces_wiki(None), [])

    def test_etiquetas(self):
        self.assertEqual(vault.limpiar_etiquetas("#WAF, waf; Red Team\n  bypass  ,,"), ["WAF", "Red Team", "bypass"])
        self.assertEqual(len(vault.limpiar_etiquetas(",".join(str(i) for i in range(40)))), 15)

    def test_busqueda_todas_las_palabras(self):
        self.assertTrue(vault.coincide("nmap puertos", "Escaneo", "red", "nmap -p- TARGET  # todos los puertos"))
        self.assertFalse(vault.coincide("nmap sqlmap", "x", "nmap -p-"))
        self.assertFalse(vault.coincide("", "algo"))

    def test_informe_markdown(self):
        md = vault.informe_markdown("Hallazgo XSS", "CONFIDENCIAL", "Finding", ["xss", "web"], "# Reporte de vulnerabilidad\n\n## Impacto\nAlto",
                                    "Edgar", datetime(2026, 11, 15))
        self.assertTrue(md.startswith("# Hallazgo XSS\n"))
        self.assertIn("**Clasificación:** CONFIDENCIAL", md)
        self.assertIn("2026-11-15", md)
        self.assertIn("**Etiquetas:** xss, web", md)
        self.assertEqual(md.count("# Reporte de vulnerabilidad"), 0)      # no repite el título de la plantilla
        self.assertIn("## Impacto", md)

    def test_nombre_archivo_seguro(self):
        self.assertEqual(vault.nombre_archivo("../../etc/passwd Auditoría"), "etc_passwd_Auditor_a")
        self.assertEqual(vault.nombre_archivo("///"), "informe")


class PruebasCatalogos(unittest.TestCase):
    def test_metodologias_completas(self):
        self.assertEqual(set(vault.CHECKLISTS), set(vault.METODOLOGIAS))
        self.assertEqual(len(vault.CHECKLISTS["OWASP Top 10"]), 10)
        self.assertEqual(len(vault.CHECKLISTS["PTES"]), 7)
        self.assertEqual(len(vault.CHECKLISTS["MITRE ATT&CK"]), 14)

    def test_claves_unicas_y_validas(self):
        for met in vault.METODOLOGIAS:
            claves = vault.claves_checklist(met)
            total = sum(len(i) for _c, _t, i in vault.CHECKLISTS[met])
            self.assertEqual(len(claves), total, met)
        self.assertIn("A01.0", vault.claves_checklist("OWASP Top 10"))
        self.assertNotIn("A01.99", vault.claves_checklist("OWASP Top 10"))
        self.assertEqual(vault.claves_checklist("inventada"), set())

    def test_plantillas_y_constantes(self):
        self.assertEqual(set(vault.PLANTILLAS), {"Recon", "Finding", "CTF"})
        self.assertTrue(set(vault.PLANTILLAS) <= set(vault.TIPOS_NOTA))
        self.assertIn("Severidad (CVSS)", vault.PLANTILLAS["Finding"])
        self.assertEqual(vault.LADOS, ("OFFENSIVE", "DEFENSIVE"))
        self.assertEqual(len(vault.CLASIFICACIONES), 4)
        self.assertEqual(vault.catalogo_para_cliente()["PTES"][0]["codigo"], "1")

    def test_linea_de_contexto(self):
        self.assertEqual(vault._linea("uno\n  dos nmap tres\ncuatro", "NMAP"), "dos nmap tres")
        self.assertEqual(vault._linea("uno", "zzz"), "")


if __name__ == "__main__":
    unittest.main()
