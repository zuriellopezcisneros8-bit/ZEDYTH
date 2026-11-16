"""Pruebas de render_panel con una API de Render simulada (no usa red). Ejecutar: python -m unittest test_render_panel -v"""
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from unittest import mock

try:                                   # en un equipo sin Flask-Login las pruebas de lógica igual corren
    import flask_login  # noqa: F401
except ImportError:
    _m = types.ModuleType("flask_login")
    _m.current_user = None
    sys.modules["flask_login"] = _m

import ajustes
import render_panel as rp

AHORA = datetime.now(timezone.utc)
ISO = lambda h: (AHORA - timedelta(hours=h)).isoformat().replace("+00:00", "Z")


def _svc(i, nombre, repo="", url="", tipo="web_service", plan="free", susp="not_suspended"):
    return {"cursor": f"c{i}", "service": {"id": f"srv-{i}", "name": nombre, "type": tipo, "suspended": susp, "repo": repo,
            "branch": "main", "autoDeploy": "yes", "dashboardUrl": f"https://dashboard.render.com/web/srv-{i}",
            "serviceDetails": {"plan": plan, "region": "oregon", "url": url}}}


def _dep(i, estado, horas=1, msg="fix\ndetalle"):
    return [{"cursor": "d", "deploy": {"id": f"dep-{i}", "status": estado, "commit": {"message": msg},
                                       "createdAt": ISO(horas), "finishedAt": ISO(horas)}}]


# Llave A (usuario 1) ve 2 workspaces; llave B (usuario 2) ve 1 workspace y además el workspace "Zed" repetido.
DATOS = {
    ("A", "/owners"): [{"cursor": "o1", "owner": {"id": "own-1", "name": "Zed"}}, {"cursor": "o2", "owner": {"id": "own-2", "name": "Equipo"}}],
    ("B", "/owners"): [{"cursor": "o3", "owner": {"id": "own-3", "name": "Cliente"}}, {"cursor": "o1", "owner": {"id": "own-1", "name": "Zed"}}],
    ("A", "/services", "own-1"): [_svc(1, "zmarthket-api", repo="https://github.com/zed/zmarthket", url="https://zmarthket-api.onrender.com"),
                                  _svc(2, "pos-web", url="https://pos.onrender.com")],
    ("A", "/services", "own-2"): [_svc(3, "tienda", plan="starter", susp="suspended")],
    ("B", "/services", "own-3"): [_svc(4, "otro-saas", repo="git@github.com:zed/otro.git")],
    ("B", "/services", "own-1"): [_svc(1, "zmarthket-api")],     # duplicado: debe contarse una sola vez
}
DEPLOYS = {"srv-1": _dep(1, "build_failed"), "srv-2": _dep(2, "live"), "srv-4": _dep(4, "build_in_progress")}


def falso_get(ruta, llave, params=None):
    p = params or {}
    if ruta == "/owners":
        return DATOS[(llave, "/owners")]
    if ruta == "/services":
        return DATOS[(llave, "/services", p.get("ownerId"))]
    if ruta.endswith("/deploys"):
        sid = ruta.split("/")[2]
        if sid == "srv-3":
            raise AssertionError("no se debe pedir deploy de un servicio suspendido")
        return DEPLOYS.get(sid, [])
    raise AssertionError(ruta)


class PruebasRender(unittest.TestCase):
    def setUp(self):
        rp._cache.update(t=0.0, datos=None, cargando=False)
        self.p1 = mock.patch.object(rp, "_get", falso_get)
        self.p2 = mock.patch.object(ajustes, "valor", lambda n, d="": {"RENDER_API_KEY": "A", "RENDER_API_KEY_2": "B"}.get(n, d))
        self.p1.start(); self.p2.start()

    def tearDown(self):
        self.p1.stop(); self.p2.stop()

    def test_varias_cuentas_y_sin_duplicados(self):
        d = rp.datos()
        self.assertEqual(len(d["llaves"]), 2)
        self.assertEqual(sorted(s["id"] for s in d["servicios"]), ["srv-1", "srv-2", "srv-3", "srv-4"])
        self.assertEqual({c["nombre"] for c in d["cuentas"]}, {"Zed", "Equipo", "Cliente"})
        self.assertFalse(d["errores"])

    def test_estados(self):
        por = {s["id"]: s for s in rp.datos()["servicios"]}
        self.assertEqual(por["srv-1"]["estado"], "Deploy fallido")
        self.assertEqual(por["srv-2"]["estado"], "En línea")
        self.assertEqual(por["srv-3"]["estado"], "Suspendido")
        self.assertEqual(por["srv-4"]["estado"], "Desplegando")
        self.assertEqual(por["srv-1"]["deploy"]["commit"], "fix")          # solo la 1.ª línea del commit

    def test_aviso_horas_gratis(self):
        zed = {c["nombre"]: c for c in rp.datos()["cuentas"]}["Zed"]       # 2 web gratis en la misma cuenta
        self.assertEqual(zed["gratis_web"], 2)
        self.assertIn("750", zed["aviso"])

    def test_vinculos_por_repo_url_y_nombre(self):
        sv = rp.datos()["servicios"]
        mk = lambda **k: NS(nombre=k.get("nombre", "X"), repo_url=k.get("repo", ""), url_produccion=k.get("url", ""))
        self.assertEqual([s["id"] for s in rp.vincular(mk(repo="https://github.com/Zed/zmarthket.git/"), sv)], ["srv-1"])
        self.assertEqual([s["id"] for s in rp.vincular(mk(url="https://www.pos.onrender.com/panel"), sv)], ["srv-2"])
        self.assertEqual([s["id"] for s in rp.vincular(mk(nombre="Otro SaaS"), sv)], ["srv-4"])
        self.assertEqual([s["id"] for s in rp.vincular(mk(repo="https://github.com/zed/otro"), sv)], ["srv-4"])   # git@ vs https
        self.assertEqual(rp.vincular(mk(nombre="Nada que ver"), sv), [])

    def test_alertas_sin_repetir_y_solo_recientes(self):
        enviados = []
        notificar = lambda tipo, titulo, cuerpo, url, urgente, clave: enviados.append((titulo, clave))
        rp.alertar(rp.datos(), notificar)
        claves = [c for _, c in enviados]
        self.assertTrue(any(c.startswith("render-fallo-srv-1-dep-1") for c in claves))     # deploy fallido reciente
        self.assertTrue(any(c.startswith("render-susp-srv-3-") for c in claves))           # suspendido
        self.assertEqual(len(claves), len(set(claves)))
        # deploy fallido VIEJO (3 días): no avisa
        DEPLOYS["srv-1"] = _dep(1, "build_failed", horas=72)
        try:
            enviados.clear(); rp.invalidar(); rp.alertar(rp.datos(), notificar)
            self.assertFalse(any("render-fallo" in c for _, c in enviados))
        finally:
            DEPLOYS["srv-1"] = _dep(1, "build_failed")

    def test_llave_mala_no_tumba_a_la_otra(self):
        def get(ruta, llave, params=None):
            if llave == "B":
                raise RuntimeError(rp.MOTIVOS[401])
            return falso_get(ruta, llave, params)
        with mock.patch.object(rp, "_get", get):
            d = rp.datos(forzar=True)
        self.assertEqual(len(d["servicios"]), 3)
        self.assertEqual(sum(1 for i in d["llaves"] if i["error"]), 1)
        self.assertIn("rechazada", d["errores"][0])
        ok, msg = False, ""
        with mock.patch.object(rp, "_get", get):
            ok, msg = rp.probar()
        self.assertFalse(ok); self.assertIn("1 de 2", msg)

    def test_la_llave_nunca_sale(self):
        import json
        self.assertNotIn('"A"', json.dumps(rp.datos()))
        self.assertTrue(all(i["final"].startswith("····") for i in rp.datos()["llaves"]))

    def test_sin_llaves(self):
        with mock.patch.object(ajustes, "valor", lambda n, d="": d):
            self.assertIsNone(rp.datos())
            self.assertFalse(rp.por_proyecto(NS())["conectado"])

    def test_pantalla_de_plataforma_no_espera_a_render(self):
        with mock.patch.object(rp, "_leer_en_segundo_plano") as bg:
            r = rp.por_proyecto(NS(nombre="x", repo_url="", url_produccion="", subdominios=[]))
        self.assertTrue(r["pendiente"]); bg.assert_called_once()


if __name__ == "__main__":
    unittest.main()
