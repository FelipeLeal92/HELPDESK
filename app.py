from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify, send_from_directory, Response, stream_with_context
from datetime import timedelta, datetime
import secrets
import string
import hashlib
import os
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
import queue
import json
from collections import defaultdict
from werkzeug.utils import secure_filename
from sqlalchemy.orm import aliased
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import re
from models import db, User, Ticket, TicketResponse, Attachment, Log, Setting, TicketType, TicketStatus

app = Flask(__name__, static_folder='static', template_folder='templates')

# SECRET_KEY via ambiente; em prod é obrigatório
secret = os.environ.get('SECRET_KEY')
if not secret:
    secret = secrets.token_hex(32) if (os.environ.get('FLASK_ENV') == 'development') else None
if secret is None:
    raise RuntimeError("SECRET_KEY não definido em produção")
app.secret_key = secret
app.permanent_session_lifetime = timedelta(days=7)

# Confiar em proxy reverso (X-Forwarded-Proto/Host)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Banco de dados
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Fallback para SQLite local se DATABASE_URL não estiver definido
if not database_url:
    sqlite_path = os.path.join(os.path.dirname(__file__), 'helpdesk.db')
    database_url = f"sqlite:///{sqlite_path}"

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configs de sessão/segurança e limite global de upload
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,  # 50MB global
    PREFERRED_URL_SCHEME='https'
)

db.init_app(app)

# Garantir que as tabelas sejam criadas ao iniciar o app
with app.app_context():
    try:
        db.create_all()
        print("Banco de dados inicializado com sucesso.")
    except Exception as e:
        print(f"Erro ao inicializar banco de dados: {str(e)}")

# Uploads configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'xls', 'xlsx', 'csv'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Logging padronizado
logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)



# Funções auxiliares - definidas antes de serem usadas
def format_date(dt_value):
    """Formata data e hora para formato ISO com timezone"""
    if dt_value is None:
        return None
    
    if hasattr(dt_value, 'isoformat'):
        # Garantir que inclua timezone se disponível
        iso_str = dt_value.isoformat()
        if 'T' in iso_str and '.' in iso_str:
            # Formato: 2025-09-13T16:49:01.635780+00:00
            return iso_str
        elif 'T' in iso_str:
            # Formato: 2025-09-13T16:49:01+00:00
            return iso_str
        else:
            return str(dt_value)
    else:
        return str(dt_value)





def allowed_file(filename: str) -> bool:
    """Check allowed extensions for uploaded files."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def _get_setting(key: str) -> str:
    """Obtém valor de configuração via ORM Setting."""
    s = db.session.get(Setting, key)
    return s.value if s else ''

def send_telegram_notification(message, event_type='general'):
    """Envia notificação via Telegram usando ORM (Setting)."""
    try:
        telegram_settings = {
            'telegram_bot_token': _get_setting('telegram_bot_token'),
            'telegram_group_id': _get_setting('telegram_group_id'),
            'telegram_topic_new_tickets': _get_setting('telegram_topic_new_tickets'),
            'telegram_topic_messages': _get_setting('telegram_topic_messages'),
            'telegram_topic_assignments': _get_setting('telegram_topic_assignments'),
            'telegram_topic_closed': _get_setting('telegram_topic_closed'),
            'telegram_topic_cancelled': _get_setting('telegram_topic_cancelled')
        }

        bot_token = telegram_settings['telegram_bot_token']
        group_id = telegram_settings['telegram_group_id']

        # Determina o tópico de acordo com o evento
        topic_id = None
        if event_type == 'created' and telegram_settings['telegram_topic_new_tickets']:
            topic_id = telegram_settings['telegram_topic_new_tickets']
        elif event_type == 'assigned' and telegram_settings['telegram_topic_assignments']:
            topic_id = telegram_settings['telegram_topic_assignments']
        elif event_type in ['status_changed', 'response_admin', 'response_user'] and telegram_settings['telegram_topic_messages']:
            topic_id = telegram_settings['telegram_topic_messages']
        elif event_type in ['resolved', 'closed'] and telegram_settings['telegram_topic_closed']:
            topic_id = telegram_settings['telegram_topic_closed']
        elif event_type == 'cancelled' and telegram_settings['telegram_topic_cancelled']:
            topic_id = telegram_settings['telegram_topic_cancelled']
        elif event_type == 'reopened' and telegram_settings['telegram_topic_new_tickets']:
            topic_id = telegram_settings['telegram_topic_new_tickets']

        if not bot_token or not group_id:
            print("Configurações do Telegram não encontradas")
            return False

        import requests
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            'chat_id': group_id,
            'text': message,
            'parse_mode': 'HTML'
        }

        if topic_id:
            try:
                data['message_thread_id'] = int(topic_id)
            except Exception:
                pass

        response = requests.post(url, data=data, timeout=10)
        if response.status_code == 200:
            print(f"Telegram notification sent: {message[:50]}...")
            return True
        else:
            print(f"Erro ao enviar Telegram: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        print(f"Erro ao enviar notificação Telegram: {str(e)}")
        return False

def send_email(to_email, subject, body):
    # This is a placeholder function
    # In production, configure with real SMTP settings
    print(f"Email enviado para {to_email}: {subject}")
    print(f"Conteúdo: {body}")
    return True

def send_sms(to_number: str, message: str):
    # Integrate with an SMS provider (e.g., Twilio) in production
    if not to_number:
        return False
    print(f"SMS enviado para {to_number}: {message}")
    return True

# --- Simple in-memory event hub for Server-Sent Events (SSE) ---
user_event_queues = defaultdict(list)  # user_id -> list[queue.Queue]

def push_event(user_id: int, payload: dict):
    """Push a JSON-serializable payload to all active SSE streams for a user."""
    if not user_id:
        return
    print(f"Pushing event to user {user_id}: {payload}")
    message = json.dumps(payload, ensure_ascii=False)
    for q in list(user_event_queues.get(user_id, [])):
        try:
            q.put_nowait(message)
        except Exception:
            pass

def ensure_schema_and_password_hash():
    """Garante defaults em settings e migra senhas para hash via ORM.
    Não altera schema diretamente (usar Alembic para isso em produção).
    """
    try:
        # Defaults de settings via ORM
        defaults = [
            ('company_name', 'LogVerse'),
            ('support_email', 'suporte@logverse.com'),
            ('support_phone', '(11) 1234-5678'),
            ('telegram_bot_token', ''),
            ('telegram_group_id', ''),
            ('telegram_topic_new_tickets', ''),
            ('telegram_topic_messages', ''),
            ('telegram_topic_assignments', ''),
            ('telegram_topic_closed', ''),
            ('telegram_topic_cancelled', '')
        ]
        for k, v in defaults:
            if not db.session.get(Setting, k):
                db.session.add(Setting(key=k, value=v))

        # Migrar senhas para hash sha256 se necessário
        users = db.session.execute(db.select(User.id, User.password)).all()
        for uid, pwd in users:
            pwd = pwd or ''
            is_hex64 = isinstance(pwd, str) and len(pwd) == 64 and all(c in '0123456789abcdef' for c in pwd.lower())
            if not is_hex64:
                u = db.session.get(User, uid)
                if u:
                    u.password = hash_password(pwd)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao garantir schema: {str(e)}")


#Helper centralizado
def run_query(query, params=None, fetchone=False, fetchall=False, commit=False, dict_cursor=False):
    """Compat wrapper para executar SQL via SQLAlchemy. Mantém interface usada no projeto.
    Evitar uso em novo código; preferir ORM puro.
    """
    try:
        # Usa text() para SQL parametrizado. Params pode ser tupla/lista (posicional) ou dict (nomeado)
        # Convert %s placeholders to :p0, :p1... for SQLAlchemy when params is positional
        stmt = text(re.sub(r"%s", lambda m, c=iter(range(9999)): f":p{next(c)}", query)) if isinstance(params, (list, tuple)) else text(query)
        bind_params = {}
        if isinstance(params, (list, tuple)):
            bind_params = {f"p{i}": v for i, v in enumerate(params)}
        elif isinstance(params, dict):
            bind_params = params

        result = db.session.execute(stmt, bind_params)

        data = None
        if fetchone:
            row = result.fetchone()
            if row is not None:
                try:
                    data = dict(row._mapping)
                except Exception:
                    data = row
        elif fetchall:
            rows = result.fetchall()
            try:
                data = [dict(r._mapping) for r in rows]
            except Exception:
                data = rows

        if commit:
            db.session.commit()
        return data
    except Exception as error:
        db.session.rollback()
        print(f"Erro ao executar query: {error}")
        raise


# Helper to notify user on ticket events
def notify_user_ticket_update(user_id: int, ticket: dict, event_type: str):
    """Send Telegram/SMS/push based on user preferences for ticket updates (ORM)."""
    try:
        user = db.session.get(User, user_id)
        if not user:
            return

        # Telegram notification (replaces email)
        if bool(user.email_updates):
            ticket_id = ticket.get('id', '')
            ticket_type = ticket.get('type', '')
            priority = ticket.get('priority', '')
            subject = ticket.get('subject', ticket.get('description', ''))[:50]
            user_name = user.name or 'Usuário'

            # Format message for Telegram
            if event_type == 'created':
                message = f"\U0001F4E8 <b>Novo Chamado Criado</b>\n\n"
            elif event_type == 'assigned':
                message = f"\U0001F464 <b>Chamado Atribuído</b>\n\n"
            elif event_type == 'status_changed':
                message = f"\U0001F504 <b>Status Atualizado</b>\n\n"
            elif event_type == 'reopened':
                message = f"\U0001F513 <b>Chamado Reaberto</b>\n\n"
            else:
                message = f"\U0001F4E7 <b>Atualização do Chamado</b>\n\n"

            message += f"<b>ID:</b> #{ticket_id}\n"
            message += f"<b>Usuário:</b> {user_name}\n"
            message += f"<b>Tipo:</b> {ticket_type}\n"
            message += f"<b>Prioridade:</b> {priority}\n"
            message += f"<b>Assunto:</b> {subject}\n"
            message += f"<b>Evento:</b> {event_type}"

            try:
                send_telegram_notification(message, event_type)
            except Exception as e:
                print(f"Erro ao enviar Telegram: {str(e)}")

        # SMS (only if urgent)
        if user.sms_urgent and ticket.get('priority') == 'Urgente' and user.phone:
            try:
                sms_body = f"[URGENTE] Chamado #{ticket.get('id')} - {event_type}"
                send_sms(user.phone, sms_body)
            except Exception as e:
                print(f"Erro ao enviar SMS: {str(e)}")

        # Push via SSE
        if bool(user.push_realtime):
            push_event(user_id, {
                'type': 'ticket_update',
                'event': event_type,
                'ticket': {
                    'id': ticket.get('id'),
                    'type': ticket.get('type'),
                    'priority': ticket.get('priority'),
                    'subject': ticket.get('subject', ''),
                    'status': ticket.get('status', 'Aberto')
                }
            })
    except Exception as e:
        print(f"Erro na notificação: {str(e)}")


def log_event(user_id, message, ticket_id=None):
    """Registra um evento no log do usuário, opcionalmente relacionado a um ticket."""
    try:
        log = Log(user_id=user_id, message=message, ticket_id=ticket_id)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Erro ao logar evento: {str(e)}")
        db.session.rollback()


# Rotas da aplicação
@app.before_request
def enforce_https():
    # Se não estiver em produção, pular o redirecionamento
    if app.debug or os.environ.get('FLASK_ENV') == 'development':
        return
    
    if request.scheme != 'https':
        url = request.url.replace('http://', 'https://')
        return redirect(url)

# Headers de segurança
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self';"
    )
    return resp

# Health check
@app.get('/healthz')
def healthz():
    return {'status': 'ok'}, 200

bootstrap_done = False

@app.before_request
def _bootstrap():
    global bootstrap_done
    if not bootstrap_done:
        try:
            ensure_schema_and_password_hash()
            bootstrap_done = True
        except Exception as e:
            logging.getLogger(__name__).error(f'Bootstrap error: {e}')

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html')

def _validate_login_data(form):
    """Valida os dados de login. Retorna (email, password, remember) ou (None, None, None) se inválido."""
    email = form.get('email')
    password = form.get('password')
    remember = 'remember' in form
    if not email or not password:
        flash('Email e senha são obrigatórios.', 'error')
        return None, None, None
    return email, password, remember

def _authenticate_user(email, password):
    """Autentica o usuário. Retorna os dados do usuário ou None se a autenticação falhar."""
    user = User.query.filter_by(email=email).first()
    if user and user.password == hash_password(password):
        return user
    return None

def _create_user_session(user):
    """Cria a sessão para o usuário (aceita dict ou modelo ORM)."""
    # Extrai campos de forma resiliente para dict ou objeto ORM
    role = getattr(user, 'role', None)
    if role is None and isinstance(user, dict):
        role = user.get('role')
    role = role or 'user'

    uid = getattr(user, 'id', None)
    if uid is None and isinstance(user, dict):
        uid = user.get('id')

    email = getattr(user, 'email', None)
    if email is None and isinstance(user, dict):
        email = user.get('email')

    name = getattr(user, 'name', None)
    if name is None and isinstance(user, dict):
        name = user.get('name')

    is_admin = role in ['admin', 'manager']

    session['user_id'] = uid
    session['user_email'] = email
    session['user_name'] = name or 'Usuário'
    session['user_role'] = role
    session['is_admin'] = is_admin
    session.permanent = True

@app.route('/login', methods=['POST'])
def login():
    """
    Processa a tentativa de login do usuário.
    """
    if request.method == 'GET':
        return redirect(url_for('index'))

    email, password, remember = _validate_login_data(request.form)
    if not email:
        return redirect(url_for('index'))

    user = _authenticate_user(email, password)

    if user:
        _create_user_session(user)
        redirect_to = 'admin_dashboard' if session['is_admin'] else 'user_dashboard'
        resp = make_response(redirect(url_for(redirect_to)))
        if remember:
            resp.set_cookie('remember_me', 'true', max_age=app.permanent_session_lifetime.total_seconds())
            resp.set_cookie('remembered_email', email, max_age=app.permanent_session_lifetime.total_seconds())
        else:
            resp.set_cookie('remember_me', '', expires=0)
            resp.set_cookie('remembered_email', '', expires=0)
        return resp
    else:
        flash('Email ou senha incorretos.', 'error')
        return redirect(url_for('index'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' in session and (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return render_template('dashboard-admin.html', user_email=session['user_email'])
    else:
        return redirect(url_for('index'))

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' in session and not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return render_template('dashboard-user.html', user_email=session['user_email'])
    else:
        return redirect(url_for('index'))

def _validate_recover_data(form):
    """Valida os dados de recuperação de senha. Retorna (email, new_password) ou (None, None) se inválido."""
    email = form.get('email')
    new_password = form.get('new-password')
    confirm_password = form.get('confirm-password')

    if not email or not new_password:
        flash('Todos os campos são obrigatórios.', 'error')
        return None, None
    
    if new_password != confirm_password:
        flash('As senhas não coincidem.', 'error')
        return None, None
        
    return email, new_password

def _update_user_password(email, new_password):
    """Atualiza a senha do usuário no banco de dados. Retorna True se o usuário foi encontrado e a senha atualizada, False caso contrário."""
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = hash_password(new_password)
        db.session.commit()
        return True
    return False

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    """
    Processa a recuperação de senha do usuário.
    """
    if request.method == 'GET':
        return render_template('recover.html')

    email, new_password = _validate_recover_data(request.form)
    if not email:
        return redirect(url_for('recover'))

    if _update_user_password(email, new_password):
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Email não encontrado.', 'error')
        return redirect(url_for('recover'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('is_admin', None)
    session.pop('user_role', None) # Garante que a role seja limpa
    
    # Apenas limpa a sessão, não os cookies de "lembrar-me"
    resp = make_response(redirect(url_for('index')))
    return resp

# API routes for AJAX requests
@app.route('/api/logs', methods=['GET'])
def get_logs():
    """
    Retorna os logs para o usuário logado.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    logs = Log.query.filter_by(user_id=session['user_id']).order_by(Log.created_at.desc()).all()
    
    formatted_logs = []
    for log in logs:
        log_dict = {
            'id': log.id,
            'user_id': log.user_id,
            'ticket_id': log.ticket_id,
            'message': log.message,
            'is_read': log.is_read,
            'created_at': format_date(log.created_at)
        }
        formatted_logs.append(log_dict)
        
    return jsonify(formatted_logs)

@app.route('/api/logs/<int:log_id>/read', methods=['PUT'])
def mark_log_as_read(log_id):
    """
    Marca um log como lido.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    log = Log.query.filter_by(id=log_id, user_id=session['user_id']).first()
    if log:
        log.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Log não encontrado.'}), 404

@app.route('/api/notifications/stream')
def notifications_stream():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    uid = session['user_id']
    print(f"User {uid} connected to SSE stream.")
    q = queue.Queue()
    user_event_queues[uid].append(q)
    def gen():
        # Initial hello event
        yield f"data: {json.dumps({'type': 'hello', 'message': 'connected'})}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=20)
                    print(f"Sending message to user {uid}: {msg}")
                    yield f"data: {msg}\n\n"
                except Exception:
                    # Heartbeat to keep connection alive
                    yield ": ping\n\n"
        finally:
            # Cleanup on disconnect
            try:
                user_event_queues[uid].remove(q)
                print(f"User {uid} disconnected from SSE stream.")
            except ValueError:
                pass
    headers = {'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    return Response(stream_with_context(gen()), headers=headers)

# Help Center config (persisted in settings table)
default_help_center_config = {
    'topCards': [
        { 'title': 'Chat 1', 'desc': 'Fale com o suporte', 'icon': 'chat' },
        { 'title': 'Chat 2', 'desc': 'Fale com o suporte', 'icon': 'chat' },
        { 'title': 'Telefone', 'desc': '0800 123 4567', 'icon': 'phone' },
        { 'title': 'Email', 'desc': 'suporte@empresa.com', 'icon': 'mail' }
    ],
    'faq': [
        { 'q': 'Como abro um novo chamado?', 'a': 'Vá até a seção "Abrir Chamado", preencha os campos obrigatórios (tipo, classificação, assunto e descrição) e clique em "Enviar Chamado".' },
        { 'q': 'Qual o prazo de resposta para meu chamado?', 'a': 'Em geral respondemos em até 24 horas úteis. Chamados com prioridade "Urgente" recebem tratamento prioritária.' },
        { 'q': 'Como acompanho o status do meu chamado?', 'a': 'Use a seção "Meus Chamados" para ver a listagem e clique em "Ver" para detalhes, anexos e histórico.' },
        { 'q': 'Posso cancelar um chamado aberto?', 'a': 'Caso ainda não tenha sido atendido, solicite o cancelamento respondendo ao ticket ou abrindo um novo solicitando o fechamento.' },
        { 'q': 'Como altero minhas informações de contato?', 'a': 'Na aba "Configurações", em "Perfil", atualize seu nome, e-mail e telefone e clique em "Salvar Alterações".' }
    ],
    'contacts': [
        { 'name': 'Atendimento 1', 'number': '5551999999999' },
        { 'name': 'Atendimento 2', 'number': '5551888888888' }
    ]
}


@app.route('/api/help-center', methods=['GET', 'PUT'])
def api_help_center():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if request.method == 'GET':
        setting = Setting.query.filter_by(key='help_center').first()
        if not setting or not setting.value:
            return jsonify(default_help_center_config)
        try:
            value = json.loads(setting.value)
            return jsonify(value)
        except Exception:
            return jsonify(default_help_center_config)
            
    # PUT
    if not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Forbidden'}), 403
        
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400
        
    if not isinstance(payload, dict):
        return jsonify({'error': 'Invalid payload'}), 400
        
    setting = Setting.query.filter_by(key='help_center').first()
    if not setting:
        setting = Setting(key='help_center', value=json.dumps(payload, ensure_ascii=False))
        db.session.add(setting)
    else:
        setting.value = json.dumps(payload, ensure_ascii=False)
        
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/tickets', methods=['GET'])
def api_get_tickets():
    """
    Retorna uma lista de tickets.
    - Administradores e gerentes veem todos os tickets.
    - Usuários veem apenas os seus próprios tickets.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        Assignee = aliased(User)
        if session.get('is_admin') or session.get('user_role') in ['admin', 'manager']:
            tickets_query = db.session.query(
                Ticket, 
                User.name.label('user_name'), 
                Assignee.name.label('assigned_to_name')
            ).join(User, Ticket.user_id == User.id).outerjoin(
                Assignee, Ticket.assigned_to == Assignee.id
            ).order_by(Ticket.created_at.desc())
        else:
            tickets_query = db.session.query(
                Ticket, 
                User.name.label('user_name'), 
                Assignee.name.label('assigned_to_name')
            ).join(User, Ticket.user_id == User.id).outerjoin(
                Assignee, Ticket.assigned_to == Assignee.id
            ).filter(Ticket.user_id == session['user_id']).order_by(Ticket.created_at.desc())

        tickets = tickets_query.all()
        
        formatted_tickets = []
        for ticket, user_name, assigned_to_name in tickets:
            ticket_dict = {
                'id': ticket.id,
                'type': ticket.type,
                'priority': ticket.priority,
                'subject': ticket.subject,
                'status': ticket.status,
                'user_name': user_name,
                'assigned_to_name': assigned_to_name,
                'created_at': format_date(ticket.created_at),
                'updated_at': format_date(ticket.updated_at),
            }
            formatted_tickets.append(ticket_dict)
        
        return jsonify(formatted_tickets)
        
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao carregar os tickets: {str(e)}'}), 500

@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
def api_get_ticket(ticket_id):
    """
    Retorna os detalhes de um ticket específico, incluindo anexos.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        ticket = run_query(
            "SELECT t.*, u.name AS user_name, a.name AS assigned_to_name "
            "FROM tickets t "
            "LEFT JOIN users u ON t.user_id = u.id "
            "LEFT JOIN users a ON t.assigned_to = a.id "
            "WHERE t.id = %s",
            (ticket_id,),
            fetchone=True,
            dict_cursor=True
        )

        if not ticket:
            return jsonify({'error': 'Ticket não encontrado.'}), 404

        # Apenas o dono do ticket ou um admin/manager pode ver os detalhes
        if not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'] or ticket['user_id'] == session['user_id']):
            return jsonify({'error': 'Você não tem permissão para ver este ticket.'}), 403

        attachments = run_query(
            "SELECT id, filename, filepath, filesize, uploaded_at FROM attachments WHERE ticket_id = %s ORDER BY uploaded_at DESC",
            (ticket_id,),
            fetchall=True,
            dict_cursor=True
        )

        ticket_dict = dict(ticket)
        ticket_dict['created_at'] = format_date(ticket_dict.get('created_at'))
        ticket_dict['updated_at'] = format_date(ticket_dict.get('updated_at'))
        ticket_dict['closed_at'] = format_date(ticket_dict.get('closed_at'))
        
        ticket_dict['attachments'] = [
            {
                'id': a['id'],
                'filename': a['filename'],
                'url': url_for('uploaded_file', filename=a['filepath']),
                'filesize': a['filesize'],
                'uploaded_at': format_date(a['uploaded_at'])
            } for a in attachments
        ]
        
        return jsonify(ticket_dict)
        
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao buscar os detalhes do ticket: {str(e)}'}), 500






def _validate_ticket_data(data):
    """Valida os dados do ticket. Retorna (True, "") se válido, ou (False, "mensagem de erro") se inválido."""
    type_ = data.get('type')
    priority = data.get('priority')
    description = data.get('description')
    if not type_ or not priority or not description:
        return False, "Campos obrigatórios (tipo, prioridade, descrição) ausentes."
    return True, ""

def _insert_ticket_in_db(data):
    """
    Insere um novo ticket no banco de dados.
    
    Args:
        data (dict): Dicionário contendo os dados do ticket.
        
    Returns:
        int: O ID do ticket recém-criado.
    """
    type_ = data.get('type')
    priority = data.get('priority')
    subject = data.get('subject', '')
    description = data.get('description')
    user_id = session['user_id']

    # A query é a mesma para PostgreSQL, então não precisamos de lógica condicional aqui.
    # O `run_query` já lida com a conversão de placeholders se necessário.
    row = run_query(
        "INSERT INTO tickets (user_id, type, priority, subject, description, status, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id",
        (user_id, type_, priority, subject, description, 'Aberto'),
        fetchone=True,
        commit=True
    )
    return row.get('id') if isinstance(row, dict) else (row[0] if row else None)

def _handle_attachments(ticket_id, files):
    """
    Processa e salva os anexos de um ticket.
    
    Args:
        ticket_id (int): O ID do ticket ao qual os anexos pertencem.
        files (list): Lista de arquivos enviados.
        
    Raises:
        ValueError: Se um arquivo for muito grande ou tiver uma extensão não permitida.
    """
    for f in files:
        if f and allowed_file(f.filename):
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(0)
            if size > MAX_FILE_SIZE:
                raise ValueError(f'Arquivo muito grande: {f.filename}. O limite é de 10MB por arquivo.')

            original = secure_filename(f.filename)
            unique_name = f"{ticket_id}_{secrets.token_hex(4)}_{original}"
            save_path = os.path.join(UPLOAD_FOLDER, unique_name)
            f.save(save_path)
            filesize = os.path.getsize(save_path)

            attachment = Attachment(ticket_id=ticket_id, filename=original, filepath=unique_name, filesize=filesize)
            db.session.add(attachment)
            db.session.commit()
        elif f:
            raise ValueError(f'Extensão de arquivo não permitida: {f.filename}')

def _notify_ticket_creation(ticket_id):
    """
    Envia notificações (log, push, Telegram) para a criação de um novo ticket.
    
    Args:
        ticket_id (int): O ID do ticket recém-criado.
    """
    ticket = run_query("SELECT * FROM tickets WHERE id = %s", (ticket_id,), fetchone=True, dict_cursor=True)

    if ticket:
        ticket_dict = dict(ticket)
        # Formatar datas para serialização JSON
        for key in ['created_at', 'updated_at', 'closed_at']:
            if key in ticket_dict:
                ticket_dict[key] = format_date(ticket_dict[key])

        # Notifica o usuário que criou o ticket
        log_event(ticket['user_id'], f"Novo ticket criado: {ticket['subject']}", ticket_id)
        notify_user_ticket_update(ticket['user_id'], ticket_dict, 'created')

        # Notifica os administradores
        admins = run_query("SELECT id FROM users WHERE role IN ('admin', 'manager')", fetchall=True, dict_cursor=True)
        for admin in admins:
            log_event(admin['id'], f"Novo ticket #{ticket_id} criado por {session['user_name']}", ticket_id)
            push_event(admin['id'], {
                'type': 'ticket_update',
                'event': 'created',
                'ticket': ticket_dict
            })

        # Envia notificação Telegram para o grupo
        try:
            user_name = session.get('user_name', 'Usuário')
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            ticket_subject = ticket['subject'] if ticket['subject'] else ticket['description'][:50]

            telegram_message = (
                "\U0001F4E8 <b>Novo Chamado Criado</b>\n\n"
                f"<b>ID:</b> #{ticket_id}\n"
                f"<b>Usuário:</b> {user_name}\n"
                f"<b>Tipo:</b> {ticket_type}\n"
                f"<b>Prioridade:</b> {ticket_priority}\n"
                f"<b>Assunto:</b> {ticket_subject}\n"
                f"<b>Descrição:</b> {ticket['description'][:500]}{'...' if len(ticket['description']) > 500 else ''}"
            )
            send_telegram_notification(telegram_message, 'created')
        except Exception as e:
            print(f"Erro ao enviar notificação Telegram de criação: {str(e)}")

@app.route('/api/tickets', methods=['POST'])
def api_create_ticket():
    """
    Cria um novo ticket.
    Esta rota lida com requisições 'multipart/form-data' (para suportar anexos) e 'application/json'.
    A lógica foi refatorada em funções auxiliares para maior clareza.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado. Por favor, faça o login.'}), 401

    try:
        if 'multipart/form-data' in request.content_type:
            data = request.form
            files = request.files.getlist('attachments')
        else:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400
            files = []

        is_valid, error_message = _validate_ticket_data(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400

        ticket_id = _insert_ticket_in_db(data)

        if files:
            _handle_attachments(ticket_id, files)

        _notify_ticket_creation(ticket_id)

        return jsonify({'success': True, 'ticket_id': ticket_id}), 201

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Ocorreu um erro inesperado ao criar o chamado. Detalhes: {str(e)}'}), 500

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Serve uploaded files
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)


# Admin API routes
@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    stats = run_query("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status IN ('Aberto', 'Em Andamento', 'Pendente')) AS open,
            COUNT(*) FILTER (WHERE status IN ('Resolvido', 'Fechado', 'Concluído', 'Finalizado')) AS resolved
        FROM tickets
    """, fetchone=True, dict_cursor=True) or {'total': 0, 'open': 0, 'resolved': 0}

    return jsonify({
            'total': stats['total'],
            'open': stats['open'],
            'resolved': stats['resolved'],
        
        'success': True
    })

@app.route('/api/admin/tickets/recent', methods=['GET'])
def api_admin_tickets_recent():
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    tickets = run_query("""
        SELECT t.*, 
               u.name AS user_name, 
               a.name AS assigned_to_name
        FROM tickets t
        LEFT JOIN users u ON t.user_id = u.id
        LEFT JOIN users a ON t.assigned_to = a.id
        ORDER BY t.created_at DESC
        LIMIT 10
    """, fetchall=True, dict_cursor=True)

    formatted = []
    for t in tickets:
        td = dict(t)
        td['created_at'] = format_date(td.get('created_at'))
        td['updated_at'] = format_date(td.get('updated_at'))
        td['closed_at'] = format_date(td.get('closed_at'))
        formatted.append(td)

    return jsonify(formatted)


@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    users = run_query("""
        SELECT id, 
               name, 
               email, 
               phone,
               COALESCE(role, CASE WHEN is_admin = TRUE THEN 'admin' ELSE 'user' END) AS role,
               created_at
        FROM users
        ORDER BY created_at DESC
    """, fetchall=True, dict_cursor=True)

    formatted_users = []
    for u in users:
        u_dict = dict(u)
        u_dict['created_at'] = format_date(u_dict.get('created_at'))
        formatted_users.append(u_dict)

    return jsonify(formatted_users)


@app.route('/api/admin/users', methods=['POST'])
def api_admin_create_user():
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    role = data.get('role', 'user')
    if role not in ['user', 'manager', 'admin']:
        role = 'user'
    is_admin_value = True if role in ['admin', 'manager'] else False

    try:
        run_query("""
            INSERT INTO users (name, email, password, phone, role, is_admin)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            data['name'],
            data['email'],
            hash_password(data['password']),
            data.get('phone', ''),
            role,
            is_admin_value
        ), commit=True)
        return jsonify({'success': True})
    except IntegrityError:
        return jsonify({'error': 'Email já existe'}), 400


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def api_admin_update_user(user_id):
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    role = data.get('role', 'user')
    if role not in ['user', 'manager', 'admin']:
        role = 'user'
    is_admin_value = True if role in ['admin', 'manager'] else False

    try:
        if 'password' in data and data['password']:
            run_query("""
                UPDATE users
                SET name = %s, email = %s, phone = %s, role = %s, is_admin = %s, password = %s
                WHERE id = %s
            """, (
                data['name'],
                data['email'],
                data.get('phone', ''),
                role,
                is_admin_value,
                hash_password(data['password']),
                user_id
            ), commit=True)
        else:
            run_query("""
                UPDATE users
                SET name = %s, email = %s, phone = %s, role = %s, is_admin = %s
                WHERE id = %s
            """, (
                data['name'],
                data['email'],
                data.get('phone', ''),
                role,
                is_admin_value,
                user_id
            ), commit=True)
        return jsonify({'success': True})
    except IntegrityError:
        return jsonify({'error': 'Email já existe'}), 400


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def api_admin_delete_user(user_id):
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    run_query("DELETE FROM users WHERE id = %s", (user_id,), commit=True)
    return jsonify({'success': True})


# User Settings (Profile/Security/Notifications)
@app.route('/api/user/settings', methods=['GET'])
def api_user_get_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = run_query("""
        SELECT id, name, email, phone, role,
                COALESCE(email_updates, TRUE)  AS email_updates,
                COALESCE(sms_urgent, FALSE)    AS sms_urgent,
                COALESCE(push_realtime, TRUE)  AS push_realtime
        FROM users

        WHERE id = %s
    """, (session['user_id'],), fetchone=True, dict_cursor=True)

    if not user:
        return jsonify({'error': 'Not found'}), 404

    u_dict = dict(user)
    u_dict['created_at'] = format_date(u_dict.get('created_at'))

    return jsonify(u_dict)


@app.route('/api/user/settings/profile', methods=['PUT'])
def api_user_update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()

    if not name or not email:
        return jsonify({'error': 'Nome e email são obrigatórios'}), 400

    try:
        run_query("""
            UPDATE users
            SET name = %s, email = %s, phone = %s
            WHERE id = %s
        """, (name, email, phone, session['user_id']), commit=True)
        return jsonify({'success': True})
    except IntegrityError:
        return jsonify({'error': 'Email já existe'}), 400


@app.route('/api/user/settings/security', methods=['PUT'])
def api_user_update_security():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    current = data.get('current_password', '')
    new = data.get('new_password', '')
    confirm = data.get('confirm_password', '')

    if not new or new != confirm:
        return jsonify({'error': 'Nova senha e confirmação não conferem'}), 400

    # Busca senha atual
    user = run_query(
        "SELECT password FROM users WHERE id = %s",
        (session['user_id'],),
        fetchone=True,
        dict_cursor=True
    )

    if not user or user['password'] != hash_password(current):
        return jsonify({'error': 'Senha atual inválida'}), 400

    # Atualiza senha
    run_query(
        "UPDATE users SET password = %s WHERE id = %s",
        (hash_password(new), session['user_id']),
        commit=True
    )

    return jsonify({'success': True})


@app.route('/api/user/settings/notifications', methods=['PUT'])
def api_user_update_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    email_updates = True if data.get('email_updates') else False
    sms_urgent = True if data.get('sms_urgent') else False
    push_realtime = True if data.get('push_realtime') else False

    run_query("""
        UPDATE users
        SET email_updates = %s, sms_urgent = %s, push_realtime = %s
        WHERE id = %s
    """, (email_updates, sms_urgent, push_realtime, session['user_id']), commit=True)

    return jsonify({'success': True})


def _check_status_update_permissions(ticket, status):
    """Verifica se o usuário tem permissão para atualizar o status do ticket."""
    if status in ['Resolvido', 'Fechado', 'Rejeitado'] and ticket['assigned_to']:
        if session['user_id'] != ticket['assigned_to']:
            return False, "Somente o administrador responsável por este chamado pode finalizá-lo."
    return True, ""

def _update_ticket_status_in_db(ticket_id, status, user_id):
    """Atualiza o status de um ticket no banco de dados."""
    run_query(
        "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
        (status, ticket_id),
        commit=True
    )
    if status in ['Resolvido', 'Fechado', 'Rejeitado']:
        run_query(
            "UPDATE tickets SET closed_at = NOW(), closed_by = %s WHERE id = %s",
            (user_id, ticket_id),
            commit=True
        )

def _notify_status_update(ticket_id, status):
    """Envia notificações sobre a atualização de status do ticket."""
    ticket = run_query("SELECT * FROM tickets WHERE id = %s", (ticket_id,), fetchone=True, dict_cursor=True)
    if ticket:
        event_type = 'status_changed'
        if status in ['Resolvido', 'Fechado']:
            event_type = 'closed'
            log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi concluído.", ticket_id)
        elif status == 'Cancelado':
            event_type = 'cancelled'
            log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi cancelado.", ticket_id)
        else:
            log_event(ticket['user_id'], f"O status do seu ticket #{ticket_id} foi alterado para {status}.", ticket_id)

        notify_user_ticket_update(ticket['user_id'], dict(ticket), event_type)

@app.route('/api/admin/tickets/<int:ticket_id>/status', methods=['PUT'])
def api_admin_update_ticket_status(ticket_id):
    """
    Atualiza o status de um ticket.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        data = request.get_json()
        status = data.get('status')
        if not status:
            return jsonify({'error': 'O novo status é obrigatório.'}), 400

        ticket = run_query("SELECT * FROM tickets WHERE id = %s", (ticket_id,), fetchone=True, dict_cursor=True)
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado.'}), 404

        has_permission, error_message = _check_status_update_permissions(ticket, status)
        if not has_permission:
            return jsonify({'error': error_message}), 403

        _update_ticket_status_in_db(ticket_id, status, session['user_id'])
        _notify_status_update(ticket_id, status)

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao atualizar o status do ticket: {str(e)}'}), 500


@app.route('/api/tickets/<int:ticket_id>/responses', methods=['GET'])
def api_get_ticket_responses(ticket_id):
    """
    Retorna as respostas de um ticket específico.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        ticket = run_query("SELECT user_id FROM tickets WHERE id = %s", (ticket_id,), fetchone=True, dict_cursor=True)
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado.'}), 404

        if not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'] or ticket['user_id'] == session['user_id']):
            return jsonify({'error': 'Você não tem permissão para ver as respostas deste ticket.'}), 403

        responses = run_query(
            "SELECT tr.id, tr.message, tr.created_at, u.name AS user_name, u.is_admin AS is_admin "
            "FROM ticket_responses tr JOIN users u ON tr.user_id = u.id "
            "WHERE tr.ticket_id = %s ORDER BY tr.created_at ASC",
            (ticket_id,),
            fetchall=True,
            dict_cursor=True
        )

        formatted_responses = []
        for r in responses:
            r_dict = dict(r)
            r_dict['created_at'] = format_date(r_dict.get('created_at'))
            formatted_responses.append(r_dict)

        return jsonify(formatted_responses)

    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao buscar as respostas do ticket: {str(e)}'}), 500


def _validate_response_data(data):
    """Valida os dados da resposta. Retorna (True, "") se válido, ou (False, "mensagem de erro") se inválido."""
    message = data.get('message', '').strip()
    if not message:
        return False, "A mensagem não pode estar vazia."
    return True, ""

def _check_response_permissions(ticket, is_staff):
    """Verifica se o usuário tem permissão para responder ao ticket."""
    is_owner = (ticket['user_id'] == session['user_id'])
    assigned_to = ticket['assigned_to']

    # Se é admin/staff
    if is_staff:
        # Se o ticket não está atribuído a ninguém, nenhum admin pode responder
        if not assigned_to:
            return False, "Este ticket precisa ser atribuído a um administrador antes que possa ser respondido."
        # Se está atribuído, só o admin atribuído pode responder
        elif session['user_id'] != assigned_to:
            return False, "Somente o administrador designado pode responder a este ticket."
    # Se não é admin nem dono, não pode responder
    elif not is_owner:
        return False, "Você não tem permissão para responder a este ticket."
    return True, ""

def _insert_response_in_db(ticket_id, user_id, message):
    """Insere uma nova resposta no banco de dados."""
    response_row = run_query(
        "INSERT INTO ticket_responses (ticket_id, user_id, message) VALUES (%s, %s, %s) RETURNING id",
        (ticket_id, user_id, message),
        fetchone=True,
        commit=True
    )
    return response_row.get('id') if isinstance(response_row, dict) else (response_row[0] if response_row else None)

def _notify_ticket_response(ticket, response_message, is_staff):
    """Envia notificações para uma nova resposta no ticket."""
    ticket_id = ticket['id']
    # Criar versão serializável do ticket para JSON
    serializable_ticket = dict(ticket)
    for key in ['created_at', 'updated_at', 'closed_at']:
        if key in serializable_ticket:
            serializable_ticket[key] = format_date(serializable_ticket[key])

    if is_staff:
        log_event(ticket['user_id'], f"O suporte respondeu ao seu ticket #{ticket_id}.", ticket_id)
        notify_user_ticket_update(ticket['user_id'], serializable_ticket, 'response_admin')
    else:
        staff_users = run_query("SELECT id FROM users WHERE is_admin = TRUE OR role IN ('admin', 'manager')", fetchall=True, dict_cursor=True)
        for staff in staff_users:
            log_event(staff['id'], f"Nova resposta do usuário no ticket #{ticket_id}", ticket_id)
            push_event(staff['id'], {'type': 'ticket_update', 'event': 'response_user', 'ticket': serializable_ticket})

        try:
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            assigned_user = run_query("SELECT name FROM users WHERE id = %s", (ticket['assigned_to'],), fetchone=True, dict_cursor=True)
            assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user else None
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            
            telegram_message = f"\U0001F4E8 <b>Nova Resposta do Usuário</b>\n\n"
            telegram_message += f"<b>ID:</b> #{ticket_id}\n"
            telegram_message += f"<b>Usuário:</b> {user_name}\n"
            if assignee:
                telegram_message += f"<b>Admin Atribuído:</b> {assignee}\n"
            telegram_message += f"<b>Tipo:</b> {ticket_type}\n"
            telegram_message += f"<b>Prioridade:</b> {ticket_priority}\n"
            telegram_message += f"<b>Mensagem:</b> {response_message[:500]}{'...' if len(response_message) > 500 else ''}"
            
            send_telegram_notification(telegram_message, 'response_user')
        except Exception as e:
            print(f"Erro ao enviar notificação de resposta do usuário: {str(e)}")

@app.route('/api/tickets/<int:ticket_id>/responses', methods=['POST'])
def api_create_ticket_response(ticket_id):
    """
    Adiciona uma nova resposta a um ticket.
    A lógica foi refatorada em funções auxiliares para maior clareza.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado. Por favor, faça o login.'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400

        is_valid, error_message = _validate_response_data(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400

        ticket = run_query("SELECT t.*, u.name AS user_name FROM tickets t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = %s", (ticket_id,), fetchone=True, dict_cursor=True)
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado.'}), 404

        is_staff = (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'])
        has_permission, error_message = _check_response_permissions(ticket, is_staff)
        if not has_permission:
            return jsonify({'error': error_message}), 403

        # Lock simples: prevenir envios simultâneos do mesmo usuário
        lock_key = f"response_lock_{session['user_id']}_{ticket_id}"
        if lock_key in session:
            return jsonify({'error': 'Envio em andamento. Aguarde.'}), 429
        session[lock_key] = True

        try:
            # Verificar duplicação: qualquer resposta do usuário neste ticket nos últimos 2 segundos
            if 'sqlite' in database_url:
                time_condition = "datetime('now', '-2 seconds')"
            else:
                time_condition = "NOW() - INTERVAL '2 seconds'"
            recent_response = run_query(
                f"SELECT id FROM ticket_responses WHERE ticket_id = %s AND user_id = %s AND created_at > {time_condition}",
                (ticket_id, session['user_id']),
                fetchone=True
            )
            if recent_response:
                return jsonify({'error': 'Aguarde alguns segundos antes de enviar outra mensagem.'}), 429

            response_id = _insert_response_in_db(ticket_id, session['user_id'], data['message'])

            _notify_ticket_response(ticket, data['message'], is_staff)

            created_at_formatted = format_date(ticket.get('created_at'))
            return jsonify({
                'success': True,
                'response_id': response_id,
                'ticket_created_at': created_at_formatted
            }), 201

        finally:
            # Remover lock após processamento
            session.pop(lock_key, None)

    except Exception as e:
        import traceback
        traceback.print_exc()
        # Remover lock em caso de erro
        session.pop(lock_key, None)
        return jsonify({'error': f'Ocorreu um erro inesperado ao adicionar a resposta. Detalhes: {str(e)}'}), 500



# Admin General Settings API
@app.route('/api/admin/settings', methods=['GET'])
def api_admin_get_settings():
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    rows = run_query(
        "SELECT key, value FROM settings",
        fetchall=True,
        dict_cursor=True
    )

    data = {row['key']: row['value'] for row in rows}

    return jsonify({
        'company_name': data.get('company_name', ''),
        'support_email': data.get('support_email', ''),
        'support_phone': data.get('support_phone', ''),
        'telegram_bot_token': data.get('telegram_bot_token', ''),
        'telegram_group_id': data.get('telegram_group_id', ''),
        'telegram_topic_new_tickets': data.get('telegram_topic_new_tickets', ''),
        'telegram_topic_messages': data.get('telegram_topic_messages', ''),
        'telegram_topic_assignments': data.get('telegram_topic_assignments', ''),
        'telegram_topic_closed': data.get('telegram_topic_closed', ''),
        'telegram_topic_cancelled': data.get('telegram_topic_cancelled', '')
    })


@app.route('/api/admin/settings', methods=['PUT'])
def api_admin_update_settings():
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    allowed_keys = {
        'company_name', 'support_email', 'support_phone',
        'telegram_bot_token', 'telegram_group_id',
        'telegram_topic_new_tickets', 'telegram_topic_messages',
        'telegram_topic_assignments', 'telegram_topic_closed',
        'telegram_topic_cancelled'
    }

    # Filtra apenas as chaves permitidas que foram enviadas
    filtered_items = [(k, str(data[k])) for k in allowed_keys if k in data]

    if not filtered_items:
        return jsonify({'error': 'Nenhuma chave válida enviada'}), 400

    # Monta a cláusula VALUES dinamicamente
    values_sql = ", ".join(["(%s, %s)"] * len(filtered_items))
    params = [item for pair in filtered_items for item in pair]  # flatten

    run_query(f"""
        INSERT INTO settings (key, value)
        VALUES {values_sql}
        ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value
    """, params, commit=True)

    return jsonify({'success': True})


@app.route('/api/admin/telegram/test', methods=['POST'])
def api_test_telegram():
    """Testa a conexão com o bot do Telegram"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    bot_token = data.get('bot_token', '').strip()
    group_id = data.get('group_id', '').strip()

    if not bot_token or not group_id:
        return jsonify({'error': 'Token do bot e ID do grupo são obrigatórios'}), 400

    import requests

    try:
        # Testa o token do bot
        bot_resp = requests.get(f"https://api.telegram.org/bot{bot_token}/getMe", timeout=10)
        bot_data = bot_resp.json() if bot_resp.ok else {}

        if not bot_resp.ok or not bot_data.get('ok'):
            return jsonify({
                'success': False,
                'error': 'Token do bot inválido ou bot não encontrado'
            }), 400

        bot_name = bot_data.get('result', {}).get('username', 'Bot')

        # Envia mensagem de teste para o grupo
        test_message = (
            "\U0001F916 <b>Teste de Conexão</b>\n\n"
            f"Bot <b>@{bot_name}</b> conectado com sucesso!\n"
            "Sistema HelpDesk configurado."
        )

        msg_resp = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data={'chat_id': group_id, 'text': test_message, 'parse_mode': 'HTML'},
            timeout=10
        )
        msg_data = msg_resp.json() if msg_resp.ok else {}

        if not msg_resp.ok or not msg_data.get('ok'):
            return jsonify({
                'success': False,
                'error': f"Erro ao enviar mensagem: {msg_data.get('description', 'Verifique o ID do grupo e se o bot foi adicionado.')}"
            }), 400

        return jsonify({
            'success': True,
            'message': f'Conexão testada com sucesso! Bot @{bot_name} pode enviar mensagens para o grupo.'
        })

    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Erro de conexão: {e}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': f'Erro interno: {e}'}), 500


@app.route('/api/admin/administrators', methods=['GET'])
def api_get_administrators():
    """API endpoint para listar administradores disponíveis para atribuição de tickets"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    print("=== BUSCANDO ADMINISTRADORES ===")

    try:
        administrators = run_query("""
            SELECT id, name, email
            FROM users
            WHERE role IN ('admin', 'manager')
            ORDER BY name
        """, fetchall=True, dict_cursor=True)

        print(f"Encontrados {len(administrators)} administradores:")
        for admin in administrators:
            print(f"  - {admin['name']} (ID: {admin['id']})")

        return jsonify(administrators)

    except Exception as e:
        print(f"Erro ao buscar administradores: {str(e)}")
        return jsonify({'error': 'Erro interno ao buscar administradores'}), 500


def _validate_assignment_data(data):
    """Valida os dados de atribuição. Retorna o ID do usuário ou None se inválido."""
    assigned_to = data.get('assigned_to')
    if not assigned_to:
        return None, "ID do administrador é obrigatório."
    return assigned_to, ""

def _get_and_validate_ticket_for_assignment(ticket_id):
    """Busca e valida o ticket para atribuição."""
    ticket = run_query("SELECT t.*, u.name AS user_name FROM tickets t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = %s", (ticket_id,), fetchone=True, dict_cursor=True)
    if not ticket:
        return None, "Ticket não encontrado."
    return ticket, ""

def _get_and_validate_assignee(assigned_to_id):
    """Busca e valida o usuário para o qual o ticket será atribuído."""
    assignee = run_query("SELECT id, name, email FROM users WHERE id = %s AND role IN ('admin', 'manager')", (assigned_to_id,), fetchone=True, dict_cursor=True)
    if not assignee:
        return None, "Usuário não é um administrador ou gerente."
    return assignee, ""

def _assign_ticket_in_db(ticket_id, assigned_to_id):
    """Atribui o ticket no banco de dados."""
    run_query("UPDATE tickets SET assigned_to = %s, updated_at = NOW() WHERE id = %s", (assigned_to_id, ticket_id), commit=True)

def _notify_assignment(ticket, assignee):
    """Envia notificações de atribuição de ticket."""
    ticket_id = ticket['id']
    assignee_id = assignee['id']
    assignee_name = assignee['name']
    
    log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi atribuído ao administrador {assignee_name}.", ticket_id)
    log_event(assignee_id, f"Você foi designado para o ticket #{ticket_id}.", ticket_id)

    try:
        user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
        ticket_type = ticket['type'] if ticket['type'] else 'N/A'
        ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
        ticket_subject = ticket['subject'] if ticket['subject'] else (
            ticket['description'][:50] if ticket['description'] else 'N/A'
        )

        assignment_message = (
            "\U0001F464 <b>Chamado Atribuído</b>\n\n"
            f"<b>ID:</b> #{ticket_id}\n"
            f"<b>Responsável:</b> {assignee_name}\n"
            f"<b>Tipo:</b> {ticket_type}\n"
            f"<b>Prioridade:</b> {ticket_priority}\n"
            f"<b>Assunto:</b> {ticket_subject}\n"
            f"<b>Usuário:</b> {user_name}"
        )
        send_telegram_notification(assignment_message, 'assigned')
    except Exception as e:
        print(f"Erro ao enviar notificação de atribuição: {str(e)}")

    notify_user_ticket_update(ticket['user_id'], dict(ticket), 'assigned')
    push_event(assignee_id, {
        'type': 'ticket_update',
        'event': 'assigned_to_you',
        'ticket': {
            'id': ticket['id'],
            'subject': ticket['subject'],
            'priority': ticket['priority']
        }
    })

@app.route('/api/admin/tickets/<int:ticket_id>/assign', methods=['PUT'])
def api_admin_assign_ticket(ticket_id):
    """
    Atribui um ticket a um administrador ou gerente.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400

        assigned_to_id, error_message = _validate_assignment_data(data)
        if not assigned_to_id:
            return jsonify({'error': error_message}), 400

        ticket, error_message = _get_and_validate_ticket_for_assignment(ticket_id)
        if not ticket:
            return jsonify({'error': error_message}), 404

        assignee, error_message = _get_and_validate_assignee(assigned_to_id)
        if not assignee:
            return jsonify({'error': error_message}), 400

        _assign_ticket_in_db(ticket_id, assigned_to_id)
        _notify_assignment(ticket, assignee)

        updated_ticket = run_query("SELECT id, subject, priority, created_at, updated_at, closed_at FROM tickets WHERE id = %s", (ticket_id,), fetchone=True, dict_cursor=True)

        if updated_ticket:
            updated_ticket = dict(updated_ticket)
            updated_ticket['created_at'] = format_date(updated_ticket.get('created_at'))
            updated_ticket['updated_at'] = format_date(updated_ticket.get('updated_at'))
            updated_ticket['closed_at'] = format_date(updated_ticket.get('closed_at'))

        return jsonify({
            'success': True,
            'assigned_to': assignee['name'],
            'message': f"Ticket atribuído para {assignee['name']}",
            'ticket': updated_ticket
        })

    except Exception as e:
        print(f"Erro ao atribuir ticket: {str(e)}")
        return jsonify({'error': 'Erro interno ao atribuir ticket'}), 500


def _cancel_ticket_in_db(ticket_id):
    """Cancela um ticket no banco de dados."""
    run_query("UPDATE tickets SET status = 'Cancelado', updated_at = NOW() WHERE id = %s", (ticket_id,), commit=True)

def _notify_cancellation(ticket):
    """Envia notificações de cancelamento de ticket."""
    ticket_id = ticket['id']
    manager_name = session.get('user_name', 'Gerente')
    log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi cancelado pelo gerente {manager_name}.", ticket_id)
    notify_user_ticket_update(ticket['user_id'], dict(ticket), 'cancelled')

    try:
        user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
        ticket_type = ticket['type'] if ticket['type'] else 'N/A'
        ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
        ticket_subject = ticket['subject'] if ticket['subject'] else (
            ticket['description'][:50] if ticket['description'] else 'N/A'
        )

        cancel_message = (
            "\U0000274C <b>Chamado Cancelado</b>\n\n"
            f"<b>ID:</b> #{ticket_id}\n"
            f"<b>Cancelado por:</b> {manager_name}\n"
            f"<b>Usuário:</b> {user_name}\n"
            f"<b>Tipo:</b> {ticket_type}\n"
            f"<b>Prioridade:</b> {ticket_priority}\n"
            f"<b>Assunto:</b> {ticket_subject}"
        )
        send_telegram_notification(cancel_message, 'cancelled')
    except Exception as e:
        print(f"Erro ao enviar notificação de cancelamento: {str(e)}")

@app.route('/api/admin/tickets/<int:ticket_id>/cancel', methods=['PUT'])
def api_admin_cancel_ticket(ticket_id):
    """
    Cancela um ticket (apenas gerentes).
    """
    if 'user_id' not in session or session.get('user_role') != 'manager':
        return jsonify({'error': 'Apenas gerentes podem cancelar tickets'}), 403

    print(f"=== CANCELAMENTO DO TICKET {ticket_id} ===")

    try:
        # Buscar ticket com nome do usuário
        ticket = run_query("""
            SELECT t.*, u.name AS user_name
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        """, (ticket_id,), fetchone=True, dict_cursor=True)

        if not ticket:
            print(f"ERRO: Ticket {ticket_id} não encontrado")
            return jsonify({'error': 'Ticket não encontrado'}), 404

        # Verificar se já está cancelado
        if ticket['status'] == 'Cancelado':
            print(f"ERRO: Ticket {ticket_id} já está cancelado")
            return jsonify({'error': 'Ticket já está cancelado'}), 400

        _cancel_ticket_in_db(ticket_id)
        _notify_cancellation(ticket)

        # Buscar ticket atualizado para retorno com datas formatadas
        updated_ticket = run_query("""
            SELECT id, subject, priority, status, created_at, updated_at, closed_at
            FROM tickets
            WHERE id = %s
        """, (ticket_id,), fetchone=True, dict_cursor=True)

        if updated_ticket:
            updated_ticket = dict(updated_ticket)
            updated_ticket['created_at'] = format_date(updated_ticket.get('created_at'))
            updated_ticket['updated_at'] = format_date(updated_ticket.get('updated_at'))
            updated_ticket['closed_at'] = format_date(updated_ticket.get('closed_at'))

        return jsonify({
            'success': True,
            'message': f"Ticket #{ticket_id} cancelado com sucesso",
            'ticket': updated_ticket
        })

    except Exception as e:
        print(f"Erro ao cancelar ticket: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

def _reopen_ticket_in_db(ticket_id):
    """Reabre um ticket no banco de dados."""
    run_query("UPDATE tickets SET status = 'Aberto', updated_at = NOW(), closed_at = NULL, closed_by = NULL WHERE id = %s", (ticket_id,), commit=True)

def _notify_reopening(ticket):
    """Envia notificações de reabertura de ticket."""
    ticket_id = ticket['id']
    user_id = ticket['user_id']
    assigned_to = ticket['assigned_to']
    closed_by = ticket.get('closed_by')

    log_event(user_id, f"Seu ticket #{ticket_id} foi reaberto.", ticket_id)
    notify_user_ticket_update(user_id, dict(ticket), 'reopened')

    if assigned_to:
        log_event(assigned_to, f"Ticket #{ticket_id} foi reaberto.", ticket_id)
        push_event(assigned_to, {
            'type': 'ticket_update',
            'event': 'reopened',
            'ticket': {'id': ticket_id, 'subject': ticket['subject'], 'priority': ticket['priority']}
        })

    if closed_by:
        log_event(closed_by, f"Ticket #{ticket_id} que você havia fechado foi reaberto.", ticket_id)
        push_event(closed_by, {
            'type': 'ticket_update',
            'event': 'reopened',
            'ticket': {'id': ticket_id, 'subject': ticket['subject'], 'priority': ticket['priority']}
        })

    managers = run_query("SELECT id FROM users WHERE role = 'manager'", fetchall=True, dict_cursor=True)
    for m in managers:
        log_event(m['id'], f"Ticket #{ticket_id} foi reaberto.", ticket_id)
        push_event(m['id'], {
            'type': 'ticket_update',
            'event': 'reopened',
            'ticket': {'id': ticket_id, 'subject': ticket['subject'], 'priority': ticket['priority']}
        })

@app.route('/api/admin/tickets/<int:ticket_id>/reopen', methods=['PUT'])
def api_admin_reopen_ticket(ticket_id):
    """
    Reabre um ticket fechado ou cancelado.
    Apenas gerentes podem reabrir tickets cancelados.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        ticket = run_query("SELECT t.*, u.name AS user_name FROM tickets t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = %s", (ticket_id,), fetchone=True, dict_cursor=True)
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado.'}), 404

        if ticket['status'] == 'Cancelado' and session.get('user_role') != 'manager':
            return jsonify({'error': 'Apenas gerentes podem reabrir tickets cancelados.'}), 403

        _reopen_ticket_in_db(ticket_id)
        _notify_reopening(ticket)

        updated_ticket = run_query("SELECT * FROM tickets WHERE id = %s", (ticket_id,), fetchone=True, dict_cursor=True)

        return jsonify({
            'success': True,
            'message': f"Ticket #{ticket_id} reaberto com sucesso.",
            'ticket': dict(updated_ticket)
        })

    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao reabrir o ticket: {str(e)}'}), 500






@app.route('/api/ticket-types', methods=['GET'])
def api_get_ticket_types():
    """
    Retorna todos os tipos de ticket ativos.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        ticket_types = run_query(
            "SELECT * FROM ticket_types WHERE active = TRUE ORDER BY name",
            fetchall=True,
            dict_cursor=True
        )
        return jsonify([dict(tt) for tt in ticket_types])
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao buscar os tipos de chamado: {str(e)}'}), 500

@app.route('/api/ticket-types', methods=['POST'])
def api_create_ticket_type():
    """
    Cria um novo tipo de chamado.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'O nome do tipo de chamado é obrigatório.'}), 400
        
        description = data.get('description', '').strip()

        run_query(
            "INSERT INTO ticket_types (name, description, active) VALUES (%s, %s, TRUE) "
            "ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, active = TRUE "
            "WHERE ticket_types.active = FALSE",
            (name, description),
            commit=True
        )
        return jsonify({'success': True}), 201

    except IntegrityError:
        return jsonify({'error': f'O tipo de chamado "{name}" já existe.'}), 409
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao criar o tipo de chamado: {str(e)}'}), 500

@app.route('/api/ticket-types/<int:type_id>', methods=['PUT'])
def api_update_ticket_type(type_id):
    """
    Atualiza um tipo de chamado existente.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400

        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'O nome do tipo de chamado é obrigatório.'}), 400
            
        description = data.get('description', '').strip()
        active = data.get('active', True)

        run_query(
            "UPDATE ticket_types SET name = %s, description = %s, active = %s WHERE id = %s",
            (name, description, active, type_id),
            commit=True
        )
        return jsonify({'success': True})

    except IntegrityError:
        return jsonify({'error': f'O tipo de chamado "{name}" já existe.'}), 409
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao atualizar o tipo de chamado: {str(e)}'}), 500

@app.route('/api/ticket-types/<int:type_id>', methods=['DELETE'])
def api_delete_ticket_type(type_id):
    """
    Marca um tipo de chamado como inativo (soft delete).
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        run_query("UPDATE ticket_types SET active = FALSE WHERE id = %s", (type_id,), commit=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao inativar o tipo de chamado: {str(e)}'}), 500


@app.route('/api/ticket-statuses', methods=['GET'])
def api_get_ticket_statuses():
    """
    Retorna todos os status de ticket ativos.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        ticket_statuses = run_query(
            "SELECT * FROM ticket_statuses WHERE active = TRUE ORDER BY name",
            fetchall=True,
            dict_cursor=True
        )
        return jsonify([dict(status) for status in ticket_statuses])
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao buscar os status de chamado: {str(e)}'}), 500

@app.route('/api/ticket-statuses', methods=['POST'])
def api_create_ticket_status():
    """
    Cria um novo status de chamado.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'O nome do status é obrigatório.'}), 400
        
        color = data.get('color', '#808080').strip()

        run_query(
            "INSERT INTO ticket_statuses (name, color, active) VALUES (%s, %s, TRUE) "
            "ON CONFLICT (name) DO UPDATE SET color = EXCLUDED.color, active = TRUE "
            "WHERE ticket_statuses.active = FALSE",
            (name, color),
            commit=True
        )
        return jsonify({'success': True}), 201

    except IntegrityError:
        return jsonify({'error': f'O status de chamado "{name}" já existe.'}), 409
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao criar o status de chamado: {str(e)}'}), 500

@app.route('/api/ticket-statuses/<int:status_id>', methods=['PUT'])
def api_update_ticket_status(status_id):
    """
    Atualiza um status de chamado existente.
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Requisição inválida. Nenhum dado JSON recebido.'}), 400

        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'O nome do status é obrigatório.'}), 400
            
        color = data.get('color', '#808080').strip()
        active = data.get('active', True)

        run_query(
            "UPDATE ticket_statuses SET name = %s, color = %s, active = %s WHERE id = %s",
            (name, color, active, status_id),
            commit=True
        )
        return jsonify({'success': True})

    except IntegrityError:
        return jsonify({'error': f'O status de chamado "{name}" já existe.'}), 409
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao atualizar o status de chamado: {str(e)}'}), 500

@app.route('/api/ticket-statuses/<int:status_id>', methods=['DELETE'])
def api_delete_ticket_status(status_id):
    """
    Marca um status de chamado como inativo (soft delete).
    """
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Acesso não autorizado.'}), 401

    try:
        run_query("UPDATE ticket_statuses SET active = FALSE WHERE id = %s", (status_id,), commit=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Ocorreu um erro ao inativar o status de chamado: {str(e)}'}), 500


@app.route('/debug')
def debug_frontend():
    """Página de debug para testar o frontend"""
    return send_from_directory('.', 'debug_frontend.html')

# Substituir a parte final do arquivo por esta:

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
