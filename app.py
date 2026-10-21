import os
import shutil
import calendar
import re
from datetime import date, datetime, timedelta
from urllib.parse import quote
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import zedith
import notificar

app = Flask(__name__)
# Recuerda cambiar esta clave en producción
app.config['SECRET_KEY'] = 'cambia-esto-por-una-clave-larga-y-segura-en-produccion'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zedyth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dinero como número (pesos). En PostgreSQL se podrá pasar a Decimal sin tocar el resto.
Dinero = db.Numeric(10, 2, asdecimal=False)


# --- MODELOS ---------------------------------------------------------------
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    rol = db.Column(db.String(20), default="admin")
    activo = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(60), unique=True, nullable=False)
    precio = db.Column(Dinero, nullable=True)          # None = por definir
    a_medida = db.Column(db.Boolean, default=False)
    descripcion = db.Column(db.String(120))
    incluye = db.Column(db.Text, default="")           # elementos separados por |
    destacado = db.Column(db.Boolean, default=False)


class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_comercial = db.Column(db.String(200), nullable=False)
    razon_social = db.Column(db.String(200))
    rfc = db.Column(db.String(20))
    direccion_fiscal = db.Column(db.String(300))
    contacto = db.Column(db.String(100), nullable=False)   # correo principal
    contacto_nombre = db.Column(db.String(120))
    telefono = db.Column(db.String(30))
    membresia_actual = db.Column(db.String(60), default="Ninguna")
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    proyectos = db.relationship('Proyecto', backref='cliente', lazy=True)
    suscripcion = db.relationship('Suscripcion', backref='cliente', uselist=False)
    pagos = db.relationship('Pago', backref='cliente', lazy=True)


class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    estado = db.Column(db.String(20), default="Desarrollo")  # Desarrollo, Activo, Mantenido, Suspendido
    repo_url = db.Column(db.String(300))
    rama_produccion = db.Column(db.String(60), default="main")
    carpeta_local = db.Column(db.String(300))   # ruta de la carpeta del proyecto en tu equipo
    boveda_ref = db.Column(db.String(300))      # referencia a tu gestor de contraseñas (NO guardar llaves aquí)
    stack = db.Column(db.String(200))
    dominio_registrador = db.Column(db.String(200))
    frontend_plataforma = db.Column(db.String(100))
    backend_plataforma = db.Column(db.String(100))
    bd_storage = db.Column(db.String(200))
    ia_cuentas = db.Column(db.String(300))   # solo nombre de cuenta/ubicación; no guardar llaves en claro
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    costos = db.relationship('CostoServicio', backref='proyecto', lazy=True)


class Suscripcion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), unique=True, nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=False)
    tarifa = db.Column(Dinero, default=0)               # lo que se le cobra al cliente
    fecha_corte = db.Column(db.Date)
    proxima_fecha_pago = db.Column(db.Date)
    estado_cobro = db.Column(db.String(20), default="Al corriente")  # Al corriente, Pendiente, Atrasado
    periodicidad = db.Column(db.String(12), default="Mensual")      # Mensual, Trimestral, Anual
    descuento_pct = db.Column(db.Float, default=0)                  # descuento por pagar por periodo largo

    @property
    def meses(self):
        return MESES.get(self.periodicidad, 1)

    @property
    def monto_periodo(self):
        """Lo que se cobra en cada periodo (tarifa mensual x meses, menos descuento)."""
        return round((self.tarifa or 0) * self.meses * (1 - (self.descuento_pct or 0) / 100), 2)

    plan = db.relationship('Plan')


class Pago(db.Model):
    """Dinero que el cliente le paga a ZEDYTH."""
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    monto = db.Column(Dinero, nullable=False)
    fecha = db.Column(db.Date, default=date.today)
    concepto = db.Column(db.String(200))
    metodo = db.Column(db.String(50))
    estado = db.Column(db.String(20), default="Pagado")


class CostoServicio(db.Model):
    """Dinero que ZEDYTH le paga a proveedores por los servicios de un proyecto."""
    id = db.Column(db.Integer, primary_key=True)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    proveedor = db.Column(db.String(100), nullable=False)   # Vercel, Render, Cloudinary...
    concepto = db.Column(db.String(200))
    monto_mensual = db.Column(Dinero, default=0)           # equivalente mensual (para calcular ganancia)
    periodicidad = db.Column(db.String(12), default="Mensual")
    monto_periodo = db.Column(Dinero)                      # lo que realmente pagas en cada periodo
    ultimo_pago = db.Column(db.Date)
    proxima_fecha_pago = db.Column(db.Date)


class Auditoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(80), default="sistema")   # Ahora guarda al usuario activo
    accion = db.Column(db.String(50), nullable=False)
    entidad = db.Column(db.String(50))
    entidad_id = db.Column(db.Integer)
    detalle = db.Column(db.String(300))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)


class Vencimiento(db.Model):
    """Dominios, certificados SSL, hosting y otros servicios que caducan."""
    id = db.Column(db.Integer, primary_key=True)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    tipo = db.Column(db.String(20), default="Dominio")      # Dominio, SSL, Hosting, Otro
    nombre = db.Column(db.String(200), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    notas = db.Column(db.String(300))
    proyecto = db.relationship('Proyecto', backref='vencimientos')


class Respaldo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    fecha = db.Column(db.Date, default=date.today)
    tipo = db.Column(db.String(30), default="Base de datos")  # Base de datos, Código, Archivos
    ubicacion = db.Column(db.String(300))
    resultado = db.Column(db.String(20), default="Correcto")  # Correcto, Falló
    proyecto = db.relationship('Proyecto', backref='respaldos')


class Incidente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    fecha = db.Column(db.Date, default=date.today)
    titulo = db.Column(db.String(200), nullable=False)
    gravedad = db.Column(db.String(10), default="Media")    # Baja, Media, Alta, Crítica
    descripcion = db.Column(db.Text)
    resolucion = db.Column(db.Text)
    estado = db.Column(db.String(12), default="Abierto")    # Abierto, Resuelto
    proyecto = db.relationship('Proyecto', backref='incidentes')


class ChecklistSeg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    clave = db.Column(db.String(30), nullable=False)
    cumplido = db.Column(db.Boolean, default=False)
    revisado = db.Column(db.Date)
    __table_args__ = (db.UniqueConstraint('proyecto_id', 'clave'),)
    proyecto = db.relationship('Proyecto', backref='checks')


class Lead(db.Model):
    """Pedido o prospecto capturado por Zedith (la IA de la web pública)."""
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)
    contacto = db.Column(db.String(150), nullable=False)
    negocio = db.Column(db.String(200))
    sistema = db.Column(db.String(200))
    funciones = db.Column(db.Text)
    presupuesto = db.Column(db.String(100))
    plazo = db.Column(db.String(100))
    resumen = db.Column(db.Text)
    estado = db.Column(db.String(20), default="Nuevo")     # Nuevo, Contactado, Cerrado, Descartado
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)


# --- FUNCIONES DE SOPORTE Y CONFIGURACIÓN GLOBAL ---------------------------

class ProyectoPublico(db.Model):
    """Proyecto que se muestra en la web pública (no expone datos privados del cliente)."""
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    categoria = db.Column(db.String(80), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    tecnologias = db.Column(db.String(200))
    visible = db.Column(db.Boolean, default=True)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    resenas = db.relationship('Resena', backref='proyecto', lazy=True, cascade='all, delete-orphan')


class Resena(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto_publico.id'), nullable=False)
    nombre = db.Column(db.String(80), nullable=False)
    calificacion = db.Column(db.Integer, nullable=False)   # 1 a 5
    comentario = db.Column(db.Text, nullable=False)
    aprobada = db.Column(db.Boolean, default=False)         # nada se publica sin tu aprobación
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)


def registrar(accion, entidad, entidad_id=None, detalle=""):
    usuario_actual = current_user.username if current_user.is_authenticated else "sistema"
    db.session.add(Auditoria(usuario=usuario_actual, accion=accion, entidad=entidad, entidad_id=entidad_id, detalle=detalle))


def dinero(v):
    return f"${(v or 0):,.0f}"


MESES = {"Mensual": 1, "Trimestral": 3, "Anual": 12}
DIAS_AVISO = 7   # cuántos días antes de la fecha empieza a avisarte


def sumar_meses(d, n):
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def migrar_sqlite():
    """Agrega columnas nuevas a una base SQLite existente sin perder datos."""
    if db.engine.dialect.name != "sqlite":
        return
    nuevas = {
        "proyecto": [("carpeta_local", "VARCHAR(300)"), ("boveda_ref", "VARCHAR(300)")],
        "suscripcion": [("periodicidad", "VARCHAR(12) DEFAULT 'Mensual'"), ("descuento_pct", "FLOAT DEFAULT 0")],
        "costo_servicio": [("periodicidad", "VARCHAR(12) DEFAULT 'Mensual'"), ("monto_periodo", "NUMERIC(10,2)"),
                           ("ultimo_pago", "DATE")],
    }
    for tabla, cols in nuevas.items():
        existentes = {r[1] for r in db.session.execute(db.text(f"PRAGMA table_info({tabla})"))}
        for nombre, tipo in cols:
            if nombre not in existentes:
                db.session.execute(db.text(f"ALTER TABLE {tabla} ADD COLUMN {nombre} {tipo}"))
    db.session.commit()


PLANES_INICIALES = [
    ("ZEDYTH Essential", 900, False, "Solo Infraestructura", "Dominio y Hosting|Base de datos y almacenamiento", False),
    ("ZEDYTH Care", 1800, False, "Solo Mantenimiento", "Actualización de dependencias|Monitoreo", False),
    ("ZEDYTH CyberShield", 1500, False, "Ciberseguridad pura", "Respaldos|Bóveda de credenciales|Auditoría de seguridad", False),
    ("ZEDYTH Core", 2500, False, "Infra + Mantenimiento", "Dominio y Hosting|Base de datos y almacenamiento|Actualización de dependencias|Monitoreo", True),
    ("ZEDYTH Business", 3800, False, "Infra + Mantenimiento + Ciberseguridad", "Todo lo de Core|Respaldos, bóveda y auditoría de seguridad", False),
    ("ZEDYTH Evolution", 5500, False, "Cobertura total + bolsa de horas", "Todo lo de Business|Bolsa de 4 horas al mes para cambios estéticos menores", False),
    ("ZEDYTH All-Inclusive Premium", 9000, True, "Soporte VIP y Desarrollo", "Soporte VIP|Infraestructura y seguridad totales|Desarrollo activo de nuevas funciones", False),
]


def sembrar_planes():
    for n, p, am, d, inc, dest in PLANES_INICIALES:
        plan = Plan.query.filter_by(nombre=n).first() or Plan(nombre=n)
        plan.precio, plan.a_medida, plan.descripcion, plan.incluye, plan.destacado = p, am, d, inc, dest
        db.session.add(plan)
    db.session.commit()

def sembrar_usuario_admin():
    if not Usuario.query.first():
        admin = Usuario(username="admin", nombre="Administrador Principal")
        admin.set_password("ZedythAdmin2026")  # Cambia esto en el primer login
        db.session.add(admin)
        db.session.commit()

# Inicialización de la DB
with app.app_context():
    db.create_all()
    migrar_sqlite()
    sembrar_planes()
    sembrar_usuario_admin()

# --- SEGURIDAD Y PROTECCIÓN DE RUTAS ---------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))

def respaldo_automatico_db():
    db_path = 'zedyth.db'
    backup_dir = 'respaldos_panel'
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        
    hoy = date.today().isoformat()
    backup_file = os.path.join(backup_dir, f"zedyth_{hoy}.db")
    
    if not os.path.exists(backup_file) and os.path.exists(db_path):
        shutil.copy2(db_path, backup_file)

@app.before_request
def inicializacion_y_seguridad():
    # 1. Respaldo automático diario
    if not hasattr(app, 'respaldo_hoy') or app.respaldo_hoy != date.today():
        respaldo_automatico_db()
        app.respaldo_hoy = date.today()
        
    # 2. Proteger todo el panel, excepto el login y los estáticos
    if not current_user.is_authenticated and request.endpoint not in RUTAS_PUBLICAS:
        return redirect(url_for('login', next=request.url))


# --- RUTAS DE AUTENTICACIÓN ------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Usuario.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.activo:
                return "Cuenta inactiva. Contacta soporte.", 403
            
            login_user(user)
            registrar("login", "Usuario", user.id, "Inicio de sesión exitoso")
            db.session.commit()
            return redirect(request.args.get('next') or url_for('index'))
            
        return "Credenciales inválidas. Intenta nuevamente.", 401
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    registrar("logout", "Usuario", current_user.id, "Cierre de sesión")
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))


# --- RUTAS PRINCIPALES -----------------------------------------------------
@app.route('/panel')
def index():
    clientes = Cliente.query.order_by(Cliente.id.desc()).all()
    ingresos = sum(x.monto_periodo / x.meses for x in Suscripcion.query.all())
    stats = {
        "clientes_activos": len(clientes),
        "proyectos_desarrollo": Proyecto.query.filter_by(estado="Desarrollo").count(),
        "ingresos_mensuales": dinero(ingresos),
    }
    planes = Plan.query.order_by(Plan.id).all()
    return render_template('admin_index.html', stats=stats, clientes=clientes, planes=planes)


@app.route('/nuevo_cliente', methods=['POST'])
def nuevo_cliente():
    membresia = request.form.get('membresia')
    nuevo = Cliente(
        nombre_comercial=request.form.get('nombre_comercial'),
        contacto=request.form.get('contacto'),
        membresia_actual=membresia or "Ninguna",
    )
    db.session.add(nuevo)
    db.session.flush()  # para obtener nuevo.id

    plan = Plan.query.filter_by(nombre=membresia).first()
    if plan:
        db.session.add(Suscripcion(cliente_id=nuevo.id, plan_id=plan.id, tarifa=plan.precio or 0))
    registrar("crear", "Cliente", nuevo.id, f"{nuevo.nombre_comercial} · {membresia}")
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/membresias')
def membresias():
    planes = []
    for p in Plan.query.order_by(Plan.id).all():
        if p.destacado:
            color, btn = "var(--accent-purple)", "var(--accent-purple)"
        elif p.a_medida:
            color, btn = "var(--border-color)", "var(--text-primary)"
        else:
            color, btn = "var(--border-color)", "var(--card-bg)"
        planes.append({
            "nombre": p.nombre,
            "precio": (f"Desde {dinero(p.precio)}" if p.a_medida and p.precio else "A medida" if p.a_medida
                       else dinero(p.precio) if p.precio else "Por definir"),
            "desc": p.descripcion,
            "incluye": [i for i in (p.incluye or "").split("|") if i],
            "color": color,
            "btn": btn,
        })
    return render_template('membresias.html', planes=planes)


# --- CLIENTES --------------------------------------------------------------
CAMPOS_CLIENTE = ["nombre_comercial", "razon_social", "rfc", "direccion_fiscal",
                  "contacto", "contacto_nombre", "telefono"]
CAMPOS_PROYECTO = ["nombre", "estado", "repo_url", "rama_produccion", "stack", "dominio_registrador",
                   "frontend_plataforma", "backend_plataforma", "bd_storage", "ia_cuentas", "carpeta_local", "boveda_ref"]


def campo(nombre):
    return (request.form.get(nombre) or "").strip()


def campo_fecha(nombre):
    v = campo(nombre)
    return date.fromisoformat(v) if v else None


@app.route('/clientes')
def clientes():
    q = (request.args.get('q') or "").strip()
    consulta = Cliente.query
    if q:
        like = f"%{q}%"
        consulta = consulta.filter(db.or_(Cliente.nombre_comercial.ilike(like),
                                          Cliente.contacto.ilike(like), Cliente.rfc.ilike(like)))
    return render_template('clientes.html', clientes=consulta.order_by(Cliente.nombre_comercial).all(), q=q)


@app.route('/clientes/nuevo', methods=['GET', 'POST'])
@app.route('/clientes/<int:cid>/editar', methods=['GET', 'POST'])
def cliente_form(cid=None):
    cliente = db.get_or_404(Cliente, cid) if cid else None
    if request.method == 'POST':
        nuevo = cliente is None
        if nuevo:
            cliente = Cliente()
            db.session.add(cliente)
        for c in CAMPOS_CLIENTE:
            setattr(cliente, c, campo(c))
        plan = db.session.get(Plan, int(campo('plan_id'))) if campo('plan_id') else None
        cliente.membresia_actual = plan.nombre if plan else "Ninguna"
        db.session.flush()
        if plan:
            sus = cliente.suscripcion or Suscripcion(cliente_id=cliente.id)
            sus.plan_id = plan.id
            sus.tarifa = float(campo('tarifa') or plan.precio or 0)
            sus.fecha_corte = campo_fecha('fecha_corte')
            sus.proxima_fecha_pago = campo_fecha('proxima_fecha_pago')
            sus.estado_cobro = campo('estado_cobro') or "Al corriente"
            sus.periodicidad = campo('periodicidad') or "Mensual"
            sus.descuento_pct = float(campo('descuento_pct') or 0)
            db.session.add(sus)
        registrar("crear" if nuevo else "editar", "Cliente", cliente.id, cliente.nombre_comercial)
        db.session.commit()
        return redirect(url_for('cliente_detalle', cid=cliente.id))
    return render_template('cliente_form.html', cliente=cliente, planes=Plan.query.order_by(Plan.id).all())


@app.route('/clientes/<int:cid>')
def cliente_detalle(cid):
    c = db.get_or_404(Cliente, cid)
    pagos = sorted(c.pagos, key=lambda p: (p.fecha or date.min, p.id), reverse=True)
    costos = sum(k.monto_mensual or 0 for p in c.proyectos for k in p.costos)
    tarifa = c.suscripcion.tarifa if c.suscripcion else 0
    resumen = {"tarifa": dinero(tarifa), "costos": dinero(costos), "ganancia": dinero(tarifa - costos),
               "pagado": dinero(sum(p.monto for p in pagos if p.estado == "Pagado"))}
    return render_template('cliente_detalle.html', c=c, pagos=pagos, resumen=resumen, hoy=date.today().isoformat())


@app.route('/clientes/<int:cid>/proyecto', methods=['POST'])
def proyecto_nuevo(cid):
    c = db.get_or_404(Cliente, cid)
    p = Proyecto(cliente_id=c.id, **{k: campo(k) for k in CAMPOS_PROYECTO})
    p.estado = p.estado or "Desarrollo"
    p.rama_produccion = p.rama_produccion or "main"
    db.session.add(p)
    db.session.flush()
    registrar("crear", "Proyecto", p.id, f"{p.nombre} · cliente {c.nombre_comercial}")
    db.session.commit()
    return redirect(url_for('cliente_detalle', cid=c.id))


@app.route('/proyectos/<int:pid>/costo', methods=['POST'])
def costo_nuevo(pid):
    p = db.get_or_404(Proyecto, pid)
    per = campo('periodicidad') if campo('periodicidad') in MESES else "Mensual"
    monto = float(campo('monto') or 0)
    k = CostoServicio(proyecto_id=p.id, proveedor=campo('proveedor'), concepto=campo('concepto'),
                      periodicidad=per, monto_periodo=monto, monto_mensual=round(monto / MESES[per], 2),
                      proxima_fecha_pago=campo_fecha('proxima_fecha_pago'))
    db.session.add(k)
    db.session.flush()
    registrar("crear", "CostoServicio", k.id, f"{k.proveedor} · proyecto {p.nombre}")
    db.session.commit()
    return redirect(url_for('cliente_detalle', cid=p.cliente_id))


@app.route('/clientes/<int:cid>/pago', methods=['POST'])
def pago_nuevo(cid):
    c = db.get_or_404(Cliente, cid)
    pago = Pago(cliente_id=c.id, monto=float(campo('monto') or 0), fecha=campo_fecha('fecha') or date.today(),
                concepto=campo('concepto'), metodo=campo('metodo'), estado=campo('estado') or "Pagado")
    db.session.add(pago)
    db.session.flush()
    registrar("crear", "Pago", pago.id, f"{dinero(pago.monto)} · {c.nombre_comercial}")
    db.session.commit()
    return redirect(url_for('cliente_detalle', cid=c.id))


# --- COBROS, PAGOS Y AVISOS ---------------------------------------------------
@app.route('/clientes/<int:cid>/cobrar', methods=['POST'])
def cobrar(cid):
    c = db.get_or_404(Cliente, cid)
    s = c.suscripcion
    if s:
        pago = Pago(cliente_id=c.id, monto=s.monto_periodo, fecha=date.today(), metodo=campo('metodo'),
                    concepto=f"Cobro {s.periodicidad.lower()} · {s.plan.nombre}", estado="Pagado")
        db.session.add(pago)
        s.proxima_fecha_pago = sumar_meses(s.proxima_fecha_pago or date.today(), s.meses)
        s.estado_cobro = "Al corriente"
        db.session.flush()
        registrar("cobro", "Pago", pago.id, f"{dinero(pago.monto)} · {c.nombre_comercial}")
        db.session.commit()
    return redirect(request.referrer or url_for('cliente_detalle', cid=c.id))


@app.route('/costos/<int:kid>/pagar', methods=['POST'])
def pagar_costo(kid):
    k = db.get_or_404(CostoServicio, kid)
    k.ultimo_pago = date.today()
    k.proxima_fecha_pago = sumar_meses(k.proxima_fecha_pago or date.today(), MESES.get(k.periodicidad, 1))
    registrar("pago_proveedor", "CostoServicio", k.id, f"{k.proveedor} · {dinero(k.monto_periodo or k.monto_mensual)}")
    db.session.commit()
    return redirect(request.referrer or url_for('cliente_detalle', cid=k.proyecto.cliente_id))


def _limite():
    return date.today() + timedelta(days=DIAS_AVISO)


def texto_cobro(a):
    c = a["cliente"]
    nombre = c.contacto_nombre or c.nombre_comercial
    if a["dias"] < 0:
        cuando = f"venció el {a['fecha']:%d/%m/%Y}"
    elif a["dias"] == 0:
        cuando = "vence hoy"
    else:
        cuando = f"vence el {a['fecha']:%d/%m/%Y} (en {a['dias']} días)"
    return (f"Hola {nombre}, te escribimos de ZEDYTH. El pago {a['periodicidad'].lower()} de tu plan "
            f"{a['plan']} por {dinero(a['monto'])} {cuando}. ¿Nos confirmas cuando lo realices? Gracias.")


def calcular_avisos():
    hoy = date.today()
    por_cobrar, por_pagar = [], []
    for s in Suscripcion.query.filter(Suscripcion.proxima_fecha_pago.isnot(None),
                                      Suscripcion.proxima_fecha_pago <= _limite()).all():
        a = {"cliente": s.cliente, "plan": s.plan.nombre, "fecha": s.proxima_fecha_pago, "monto": s.monto_periodo,
             "periodicidad": s.periodicidad, "dias": (s.proxima_fecha_pago - hoy).days}
        txt = texto_cobro(a)
        tel = re.sub(r"\D", "", s.cliente.telefono or "")
        tel = "52" + tel if len(tel) == 10 else tel
        a["wa"] = f"https://wa.me/{tel}?text={quote(txt)}" if tel else None
        a["mail"] = f"mailto:{s.cliente.contacto}?subject={quote('Recordatorio de pago ZEDYTH')}&body={quote(txt)}"
        por_cobrar.append(a)
    for k in CostoServicio.query.filter(CostoServicio.proxima_fecha_pago.isnot(None),
                                        CostoServicio.proxima_fecha_pago <= _limite()).all():
        por_pagar.append({"id": k.id, "proveedor": k.proveedor, "concepto": k.concepto, "proyecto": k.proyecto,
                          "fecha": k.proxima_fecha_pago, "monto": k.monto_periodo or k.monto_mensual,
                          "periodicidad": k.periodicidad, "dias": (k.proxima_fecha_pago - hoy).days})
    por_cobrar.sort(key=lambda a: a["fecha"])
    por_pagar.sort(key=lambda a: a["fecha"])
    return por_cobrar, por_pagar


@app.context_processor
def inyectar_avisos():
    n = (Suscripcion.query.filter(Suscripcion.proxima_fecha_pago.isnot(None),
                                  Suscripcion.proxima_fecha_pago <= _limite()).count()
         + CostoServicio.query.filter(CostoServicio.proxima_fecha_pago.isnot(None),
                                      CostoServicio.proxima_fecha_pago <= _limite()).count()
         + len(alertas_seguridad()))
    return {"n_avisos": n, "n_leads": Lead.query.filter_by(estado="Nuevo").count()}


@app.route('/avisos')
def avisos():
    por_cobrar, por_pagar = calcular_avisos()
    return render_template('avisos.html', por_cobrar=por_cobrar, por_pagar=por_pagar, dias_aviso=DIAS_AVISO,
                           seguridad=alertas_seguridad())


# --- REPOSITORIOS ------------------------------------------------------------
@app.route('/repositorios')
def repositorios():
    q = (request.args.get('q') or "").strip()
    estado = request.args.get('estado') or ""
    consulta = Proyecto.query.join(Cliente)
    if estado:
        consulta = consulta.filter(Proyecto.estado == estado)
    if q:
        like = f"%{q}%"
        consulta = consulta.filter(db.or_(Proyecto.nombre.ilike(like), Cliente.nombre_comercial.ilike(like),
                                          Proyecto.stack.ilike(like)))
    return render_template('repositorios.html', proyectos=consulta.order_by(Proyecto.nombre).all(), q=q, estado=estado)


@app.route('/proyectos/<int:pid>/editar', methods=['GET', 'POST'])
def proyecto_form(pid):
    p = db.get_or_404(Proyecto, pid)
    if request.method == 'POST':
        for k in CAMPOS_PROYECTO:
            setattr(p, k, campo(k))
        p.estado = p.estado or "Desarrollo"
        registrar("editar", "Proyecto", p.id, p.nombre)
        db.session.commit()
        return redirect(url_for('cliente_detalle', cid=p.cliente_id))
    return render_template('proyecto_form.html', p=p)


# --- CIBERSEGURIDAD ----------------------------------------------------------
DIAS_VENCIMIENTO = 30   # avisar de dominios/SSL que caducan en este plazo
DIAS_RESPALDO = 7       # avisar si un proyecto activo lleva más días sin respaldo correcto
CHECKLIST = [
    ("2fa", "Verificación en dos pasos en GitHub, hosting y correo"),
    ("deps", "Dependencias actualizadas"),
    ("llaves", "Llaves y tokens rotados en el último año"),
    ("env", "Secretos fuera del código (variables de entorno)"),
    ("https", "HTTPS activo en el dominio"),
    ("restore", "Restauración de un respaldo probada"),
]
RENOVACION = {"Dominio": 12, "SSL": 3, "Hosting": 12, "Otro": 12}   # meses que suma "Renovado"


def ultimo_respaldo(p):
    return max((r.fecha for r in p.respaldos if r.resultado == "Correcto" and r.fecha), default=None)


def alertas_seguridad():
    hoy = date.today()
    alertas = []
    for v in Vencimiento.query.filter(Vencimiento.fecha <= hoy + timedelta(days=DIAS_VENCIMIENTO)).all():
        alertas.append({"proyecto": v.proyecto, "tipo": "Vencimiento", "detalle": f"{v.tipo}: {v.nombre}",
                        "fecha": v.fecha, "dias": (v.fecha - hoy).days, "vid": v.id})
    for p in Proyecto.query.filter(Proyecto.estado.in_(["Activo", "Mantenido"])).all():
        ult = ultimo_respaldo(p)
        if ult is None:
            alertas.append({"proyecto": p, "tipo": "Respaldo", "detalle": "Sin respaldos registrados", "fecha": None, "dias": -9999})
        elif (hoy - ult).days > DIAS_RESPALDO:
            alertas.append({"proyecto": p, "tipo": "Respaldo", "detalle": f"Último respaldo hace {(hoy - ult).days} días",
                            "fecha": ult, "dias": -(hoy - ult).days})
    alertas.sort(key=lambda a: (a["tipo"] != "Vencimiento", a["dias"]))
    return alertas


@app.route('/ciberseguridad')
def ciberseguridad():
    hoy = date.today()
    filas = []
    for p in Proyecto.query.order_by(Proyecto.nombre).all():
        ult = ultimo_respaldo(p)
        filas.append({"p": p, "ult": ult, "dias": (hoy - ult).days if ult else None,
                      "hechos": sum(1 for c in p.checks if c.cumplido),
                      "abiertos": sum(1 for i in p.incidentes if i.estado == "Abierto"),
                      "prox": min(p.vencimientos, key=lambda v: v.fecha, default=None)})
    alertas = alertas_seguridad()
    total = len(filas) * len(CHECKLIST)
    stats = {"vencimientos": sum(1 for a in alertas if a["tipo"] == "Vencimiento"),
             "sin_respaldo": sum(1 for a in alertas if a["tipo"] == "Respaldo"),
             "incidentes": sum(f["abiertos"] for f in filas),
             "cumplimiento": f"{round(100 * sum(f['hechos'] for f in filas) / total)}%" if total else "—"}
    return render_template('ciberseguridad.html', filas=filas, stats=stats, total_items=len(CHECKLIST),
                           dias_respaldo=DIAS_RESPALDO)


@app.route('/proyectos/<int:pid>/seguridad')
def proyecto_seguridad(pid):
    p = db.get_or_404(Proyecto, pid)
    marcados = {c.clave: c for c in p.checks}
    return render_template('proyecto_seguridad.html', p=p, checklist=CHECKLIST, marcados=marcados,
                           vencimientos=sorted(p.vencimientos, key=lambda v: v.fecha),
                           respaldos=sorted(p.respaldos, key=lambda r: (r.fecha or date.min, r.id), reverse=True)[:10],
                           incidentes=sorted(p.incidentes, key=lambda i: (i.estado != "Abierto", -(i.fecha or date.min).toordinal())),
                           hoy=date.today().isoformat(), tipos=list(RENOVACION))


def _volver(pid):
    return redirect(url_for('proyecto_seguridad', pid=pid))


@app.route('/proyectos/<int:pid>/checklist', methods=['POST'])
def guardar_checklist(pid):
    p = db.get_or_404(Proyecto, pid)
    existentes = {c.clave: c for c in p.checks}
    for clave, _ in CHECKLIST:
        c = existentes.get(clave) or ChecklistSeg(proyecto_id=p.id, clave=clave)
        c.cumplido = ("c_" + clave) in request.form
        c.revisado = date.today()
        db.session.add(c)
    registrar("revisar", "Checklist", p.id, p.nombre)
    db.session.commit()
    return _volver(pid)


@app.route('/proyectos/<int:pid>/vencimiento', methods=['POST'])
def vencimiento_nuevo(pid):
    p = db.get_or_404(Proyecto, pid)
    tipo = campo('tipo') if campo('tipo') in RENOVACION else "Otro"
    v = Vencimiento(proyecto_id=p.id, tipo=tipo, nombre=campo('nombre'), fecha=campo_fecha('fecha'), notas=campo('notas'))
    db.session.add(v)
    db.session.flush()
    registrar("crear", "Vencimiento", v.id, f"{v.tipo} {v.nombre} · {p.nombre}")
    db.session.commit()
    return _volver(pid)


@app.route('/vencimientos/<int:vid>/renovar', methods=['POST'])
def vencimiento_renovar(vid):
    v = db.get_or_404(Vencimiento, vid)
    v.fecha = sumar_meses(max(v.fecha, date.today()), RENOVACION.get(v.tipo, 12))
    registrar("renovar", "Vencimiento", v.id, f"{v.tipo} {v.nombre} → {v.fecha}")
    db.session.commit()
    return redirect(request.referrer or url_for('proyecto_seguridad', pid=v.proyecto_id))


@app.route('/proyectos/<int:pid>/respaldo', methods=['POST'])
def respaldo_nuevo(pid):
    p = db.get_or_404(Proyecto, pid)
    r = Respaldo(proyecto_id=p.id, fecha=campo_fecha('fecha') or date.today(), tipo=campo('tipo') or "Base de datos",
                 ubicacion=campo('ubicacion'), resultado=campo('resultado') or "Correcto")
    db.session.add(r)
    db.session.flush()
    registrar("crear", "Respaldo", r.id, f"{r.tipo} · {r.resultado} · {p.nombre}")
    db.session.commit()
    return _volver(pid)


@app.route('/proyectos/<int:pid>/incidente', methods=['POST'])
def incidente_nuevo(pid):
    p = db.get_or_404(Proyecto, pid)
    i = Incidente(proyecto_id=p.id, fecha=campo_fecha('fecha') or date.today(), titulo=campo('titulo'),
                  gravedad=campo('gravedad') or "Media", descripcion=campo('descripcion'))
    db.session.add(i)
    db.session.flush()
    registrar("crear", "Incidente", i.id, f"{i.gravedad} · {i.titulo} · {p.nombre}")
    db.session.commit()
    return _volver(pid)


@app.route('/incidentes/<int:iid>/resolver', methods=['POST'])
def incidente_resolver(iid):
    i = db.get_or_404(Incidente, iid)
    i.estado, i.resolucion = "Resuelto", campo('resolucion')
    registrar("resolver", "Incidente", i.id, i.titulo)
    db.session.commit()
    return _volver(i.proyecto_id)


# --- FINANZAS ----------------------------------------------------------------
MES_ES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]


def proyectar(items, inicio):
    fin = sumar_meses(inicio, 12)
    totales = [0.0] * 12
    for fecha, paso, monto in items:
        d = fecha
        if d < inicio:
            totales[0] += monto
            while d < inicio:
                d = sumar_meses(d, paso)
        while d < fin:
            totales[(d.year - inicio.year) * 12 + d.month - inicio.month] += monto
            d = sumar_meses(d, paso)
    return totales


@app.route('/finanzas')
def finanzas():
    hoy = date.today()
    inicio = date(hoy.year, hoy.month, 1)
    filas = []
    for c in Cliente.query.order_by(Cliente.nombre_comercial).all():
        s = c.suscripcion
        ingreso = (s.monto_periodo / s.meses) if s else 0
        costo = sum(k.monto_mensual or 0 for p in c.proyectos for k in p.costos)
        vencido = s.monto_periodo if s and s.proxima_fecha_pago and s.proxima_fecha_pago < hoy else 0
        filas.append({"c": c, "s": s, "ingreso": ingreso, "costo": costo, "ganancia": ingreso - costo, "vencido": vencido,
                      "margen": round(100 * (ingreso - costo) / ingreso) if ingreso else None})
    filas.sort(key=lambda f: f["ganancia"], reverse=True)

    ingresos = sum(f["ingreso"] for f in filas)
    costos = sum(f["costo"] for f in filas)
    vencido = sum(f["vencido"] for f in filas)
    cobrado = db.session.query(db.func.coalesce(db.func.sum(Pago.monto), 0)).filter(
        Pago.estado == "Pagado", Pago.fecha >= inicio).scalar()

    entradas = [(x.proxima_fecha_pago, x.meses, x.monto_periodo) for x in Suscripcion.query.all()
                if x.proxima_fecha_pago and x.monto_periodo]
    salidas = [(k.proxima_fecha_pago, MESES.get(k.periodicidad, 1), k.monto_periodo or k.monto_mensual or 0)
               for k in CostoServicio.query.all() if k.proxima_fecha_pago]
    ent, sal = proyectar(entradas, inicio), proyectar(salidas, inicio)
    proy = []
    for i in range(12):
        m = sumar_meses(inicio, i)
        proy.append({"mes": f"{MES_ES[m.month - 1]} {m.year}", "ent": ent[i], "sal": sal[i], "neto": ent[i] - sal[i]})
    maximo = max([p["ent"] for p in proy] + [p["sal"] for p in proy] + [1])
    sin_fecha = (Suscripcion.query.filter(Suscripcion.proxima_fecha_pago.is_(None)).count()
                 + CostoServicio.query.filter(CostoServicio.proxima_fecha_pago.is_(None)).count())

    stats = {"ingresos": dinero(ingresos), "costos": dinero(costos), "ganancia": dinero(ingresos - costos),
             "margen": f"{round(100 * (ingresos - costos) / ingresos)}%" if ingresos else "—",
             "vencido": dinero(vencido), "cobrado": dinero(cobrado)}
    return render_template('finanzas.html', stats=stats, filas=filas, proy=proy, maximo=maximo,
                           totales={"ent": sum(ent), "sal": sum(sal)}, sin_fecha=sin_fecha)



# --- WEB PÚBLICA -----------------------------------------------------------
# Únicas rutas que se pueden abrir sin iniciar sesión.
RUTAS_PUBLICAS = {'login', 'static', 'inicio', 'resena_enviar', 'demo_pos', 'equipo_yo', 'salir_equipo', 'zedith_chat'}
# Datos de contacto (WhatsApp con lada de país, sin "+" ni espacios).
CONTACTO = {"whatsapp": "524427972122", "telefono": "442 797 2122", "tel_link": "+524427972122",
            "email": "zedythtechnologies@gmail.com"}
_intentos_resena = {}   # ip -> [fechas]; límite simple anti-spam


@app.route('/')
def inicio():
    vitrina = []
    for p in ProyectoPublico.query.filter_by(visible=True).order_by(ProyectoPublico.id.desc()).all():
        ok = sorted((r for r in p.resenas if r.aprobada), key=lambda r: r.id, reverse=True)
        prom = round(sum(r.calificacion for r in ok) / len(ok), 1) if ok else None
        vitrina.append({"p": p, "prom": prom, "n": len(ok), "recientes": ok[:3]})
    return render_template('public.html', planes=Plan.query.order_by(Plan.id).all(), vitrina=vitrina,
                           contacto=CONTACTO, gracias=request.args.get('gracias'), año=date.today().year)


@app.route('/demo-pos')
def demo_pos():
    """Punto de venta de prueba: corre 100% en el navegador, no toca tu base de datos."""
    return render_template('demo_pos.html', contacto=CONTACTO)

@app.route('/api/equipo/yo')
def equipo_yo():
    """Simula el endpoint de sesión para el demo_pos."""
    if current_user.is_authenticated:
        return {"ok": True, "logueado": True, "nombre": current_user.nombre}
    return {"ok": True, "logueado": False, "nombre": "Cajero Demo"}

@app.route('/salir-equipo')
def salir_equipo():
    """Simula la salida del equipo en el demo_pos."""
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('demo_pos'))

@app.route('/proyectos-publicos/<int:pid>/resena', methods=['POST'])
def resena_enviar(pid):
    p = db.get_or_404(ProyectoPublico, pid)
    destino = url_for('inicio') + '#proyectos'
    ahora = datetime.utcnow()
    ip = request.remote_addr or '-'
    recientes = [t for t in _intentos_resena.get(ip, []) if ahora - t < timedelta(hours=1)]
    nombre = request.form.get('nombre', '').strip()[:80]
    comentario = request.form.get('comentario', '').strip()[:600]
    try:
        cal = int(request.form.get('calificacion', 0))
    except ValueError:
        cal = 0
    # "web" es un campo trampa para bots; deben llenarse los datos y respetarse el límite por hora
    if request.form.get('web') or len(recientes) >= 3 or not nombre or not 1 <= cal <= 5 or len(comentario) < 5:
        return redirect(destino)
    _intentos_resena[ip] = recientes + [ahora]
    db.session.add(Resena(proyecto_id=p.id, nombre=nombre, calificacion=cal, comentario=comentario))
    db.session.commit()
    return redirect(url_for('inicio', gracias=1) + '#proyectos')


@app.route('/resenas', methods=['GET', 'POST'])
def resenas_admin():
    if request.method == 'POST' and request.form.get('nombre'):
        p = ProyectoPublico(nombre=request.form['nombre'].strip(), categoria=request.form['categoria'].strip(),
                            descripcion=request.form['descripcion'].strip(),
                            tecnologias=request.form.get('tecnologias', '').strip() or None)
        db.session.add(p)
        db.session.flush()
        registrar("crear", "ProyectoPublico", p.id, p.nombre)
        db.session.commit()
        return redirect(url_for('resenas_admin'))
    return render_template('resenas_admin.html',
                           pendientes=Resena.query.filter_by(aprobada=False).order_by(Resena.id).all(),
                           proyectos=ProyectoPublico.query.order_by(ProyectoPublico.id.desc()).all())


@app.route('/resenas/<int:rid>/<accion>', methods=['POST'])
def resena_moderar(rid, accion):
    r = db.get_or_404(Resena, rid)
    if accion == 'aprobar':
        r.aprobada = True
    elif accion == 'borrar':
        db.session.delete(r)
    registrar(accion, "Resena", rid, "Moderación de reseña")
    db.session.commit()
    return redirect(url_for('resenas_admin'))


@app.route('/proyectos-publicos/<int:pid>/visibilidad', methods=['POST'])
def proyecto_publico_toggle(pid):
    p = db.get_or_404(ProyectoPublico, pid)
    p.visible = not p.visible
    db.session.commit()
    return redirect(url_for('resenas_admin'))

# --- ZEDITH (IA de la web pública) -----------------------------------------
_zed_ip = {}                       # ip -> [fechas]; límite por visitante
_zed_dia = {"fecha": None, "n": 0}  # tope global diario: protege tu cuota y tu dinero
ZED_MAX_IP = int(os.environ.get("ZEDITH_MAX_IP", "20"))      # mensajes por IP cada 10 min
ZED_MAX_DIA = int(os.environ.get("ZEDITH_MAX_DIA", "1500"))  # mensajes por día (por proceso)


def _ip_cliente():
    return (request.headers.get('X-Forwarded-For', request.remote_addr or '-').split(',')[0].strip()) or '-'


def hechos_zedith():
    """Datos reales del negocio que Zedith puede citar como prueba social. Nada inventado."""
    prom = db.session.query(db.func.avg(Resena.calificacion)).filter(Resena.aprobada.is_(True)).scalar()
    return {
        "planes": [(p.nombre, p.precio, p.a_medida, p.descripcion) for p in Plan.query.order_by(Plan.id).all()],
        "resenas": Resena.query.filter_by(aprobada=True).count(),
        "promedio": round(prom, 1) if prom else None,
        "proyectos": ProyectoPublico.query.filter_by(visible=True).count(),
        "cupo": os.environ.get("ZEDITH_CUPO_MES"),
        "promo": os.environ.get("ZEDITH_PROMO"),
        "promo_hasta": os.environ.get("ZEDITH_PROMO_HASTA"),
    }


def guardar_pedido(p):
    """Guarda (o actualiza, si es el mismo contacto en la última hora) el pedido que armó Zedith.
    Devuelve (lead, es_nuevo)."""
    recorte = lambda k, n: (p.get(k) or "").strip()[:n] or None
    contacto = recorte("contacto", 150)
    lead = Lead.query.filter(Lead.contacto == contacto,
                             Lead.creado_en >= datetime.utcnow() - timedelta(hours=1)).first()
    es_nuevo = lead is None
    lead = lead or Lead(contacto=contacto)
    lead.nombre = recorte("nombre", 120) or "Sin nombre"
    lead.negocio, lead.sistema = recorte("negocio", 200), recorte("sistema", 200)
    lead.funciones, lead.presupuesto = recorte("funciones", 1000), recorte("presupuesto", 100)
    lead.plazo, lead.resumen = recorte("plazo", 100), recorte("resumen", 1500)
    db.session.add(lead)
    db.session.flush()
    registrar("pedido", "Lead", lead.id, f"{lead.nombre} · {lead.sistema or lead.negocio or ''}")
    db.session.commit()
    return lead, es_nuevo


@app.route('/api/zedith', methods=['POST'])
def zedith_chat():
    datos = request.get_json(silent=True) or {}
    mensajes = datos.get('mensajes')
    if not isinstance(mensajes, list) or not mensajes:
        return {"error": "mensajes requeridos"}, 400

    ahora, hoy = datetime.utcnow(), date.today()
    ip = _ip_cliente()
    recientes = [t for t in _zed_ip.get(ip, []) if ahora - t < timedelta(minutes=10)]
    if _zed_dia["fecha"] != hoy:
        _zed_dia.update(fecha=hoy, n=0)
    if len(recientes) >= ZED_MAX_IP or _zed_dia["n"] >= ZED_MAX_DIA:
        return {"error": "límite alcanzado"}, 429
    _zed_ip[ip] = recientes + [ahora]
    _zed_dia["n"] += 1

    try:
        r = zedith.responder(mensajes, hechos_zedith())
    except zedith.ZedithError as e:
        app.logger.warning("Zedith no respondió: %s", e)
        return {"error": "no disponible"}, 503

    wa = None
    if r["pedido"]:
        lead, es_nuevo = guardar_pedido(r["pedido"])
        if es_nuevo:   # un solo aviso por pedido, aunque la conversación siga
            notificar.avisar(
                f"Nuevo pedido en ZEDYTH: {lead.nombre}",
                f"Cliente: {lead.nombre}\nContacto: {lead.contacto}\nNegocio: {lead.negocio or '-'}\n"
                f"Sistema: {lead.sistema or '-'}\nFunciones: {lead.funciones or '-'}\n"
                f"Presupuesto: {lead.presupuesto or '-'} · Plazo: {lead.plazo or '-'}\n\n"
                f"{lead.resumen or ''}\n\nVer en el panel: {request.host_url}leads")
        texto = (f"Hola, soy {lead.nombre}. Armé mi pedido con Zedith:\n{lead.resumen or lead.sistema or lead.negocio or ''}"
                 f"\nContacto: {lead.contacto}")
        wa = f"https://wa.me/{CONTACTO['whatsapp']}?text={quote(texto)}"
    return {"reply": r["reply"], "wa": wa}


@app.route('/leads')
def leads():
    filas = Lead.query.order_by(Lead.id.desc()).limit(200).all()
    for l in filas:
        l.hora = l.creado_en - timedelta(hours=6)          # hora centro de México
        if "@" in (l.contacto or ""):
            l.enlace = f"mailto:{l.contacto}"
        else:
            tel = re.sub(r"\D", "", l.contacto or "")
            tel = "52" + tel if len(tel) == 10 else tel
            l.enlace = f"https://wa.me/{tel}" if len(tel) >= 10 else None
    return render_template('leads.html', leads=filas)


@app.route('/leads/<int:lid>/estado', methods=['POST'])
def lead_estado(lid):
    l = db.get_or_404(Lead, lid)
    nuevo = campo('estado')
    if nuevo in ("Nuevo", "Contactado", "Cerrado", "Descartado"):
        l.estado = nuevo
        registrar("estado", "Lead", l.id, nuevo)
        db.session.commit()
    return redirect(url_for('leads'))


if __name__ == '__main__':
    # host='0.0.0.0' permite que otros dispositivos en tu WiFi accedan a la PC
    # ssl_context='adhoc' genera un HTTPS temporal (necesario para usar la cámara en móviles)
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context='adhoc')