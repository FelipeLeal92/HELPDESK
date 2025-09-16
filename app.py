from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify, send_from_directory, Response, stream_with_context
import psycopg2
from psycopg2 import IntegrityError
from psycopg2.extras import DictCursor
from datetime import timedelta, datetime
import secrets
import string
import hashlib
import os
import queue
import json
from collections import defaultdict
from werkzeug.utils import secure_filename
from database import init_database

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'SECRET-KEY'
app.permanent_session_lifetime = timedelta(days=7)

OPEN_STATUSES = ('Aberto', 'Em Andamento', 'Pendente')
RESOLVED_STATUSES = ('Resolvido', 'Fechado', 'Concluído', 'Finalizado')
CANCELLED_STATUSES = ('Cancelado',)

# Uploads configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'xls', 'xlsx', 'csv'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

def get_db_connection():
    try:
        database_url = os.environ.get('DATABASE_URL')
        if not database_url:
            raise ValueError("DATABASE_URL não encontrado nas variáveis de ambiente")
        
        # Adicione logging para debug
        print(f"Tentando conectar ao banco: {database_url[:50]}...")
        
        conn = psycopg2.connect(database_url)
        conn.autocommit = True
        return conn
    except psycopg2.Error as e:
        print(f"Erro ao conectar ao PostgreSQL: {str(e)}")
        print(f"Tipo de erro: {type(e)}")
        raise
    except Exception as e:
        print(f"Erro geral na conexão: {str(e)}")
        raise

def log_event(user_id, message, ticket_id=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO logs (user_id, ticket_id, message) VALUES (%s, %s, %s)", (user_id, ticket_id, message))
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Erro ao registrar log: {str(e)}")

def allowed_file(filename: str) -> bool:
    """Check allowed extensions for uploaded files."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_telegram_notification(message, event_type='general'):
    """Envia notificação via Telegram usando bot e grupo configurados"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        # Get all telegram settings at once
        telegram_settings = {}
        settings_keys = ['telegram_bot_token', 'telegram_group_id', 'telegram_topic_new_tickets', 
                        'telegram_topic_messages', 'telegram_topic_assignments', 'telegram_topic_closed', 'telegram_topic_cancelled']
        
        for key in settings_keys:
            cur.execute('SELECT value FROM settings WHERE key = %s', (key,))
            row = cur.fetchone()
            telegram_settings[key] = row['value'] if row else ''
        
        cur.close()
        conn.close()
        
        bot_token = telegram_settings['telegram_bot_token']
        group_id = telegram_settings['telegram_group_id']
        
        # Determine topic ID based on event type
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
        
        # Add topic ID if specified
        if topic_id:
            data['message_thread_id'] = int(topic_id)
        
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
    """Garante que as colunas/tabelas necessárias existam e migra senhas em texto puro para hash sha256."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Obter colunas da tabela users
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'users'
        """)
        cols = {row[0] for row in cur.fetchall()}

        # Adicionar colunas se não existirem
        if 'email_updates' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN email_updates INTEGER DEFAULT TRUE")
        if 'sms_urgent' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN sms_urgent INTEGER DEFAULT FALSE")
        if 'push_realtime' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN push_realtime INTEGER DEFAULT TRUE")
        if 'role' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            cur.execute("UPDATE users SET role = 'admin' WHERE is_admin = TRUE")
            cur.execute("UPDATE users SET role = 'user' WHERE is_admin = FALSE")

        # Criar tabela settings se não existir
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Inserir valores padrão se não existirem
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
            cur.execute("""
                INSERT INTO settings (key, value)
                VALUES (%s, %s)
                ON CONFLICT (key) DO NOTHING
            """, (k, v))

        # Obter colunas da tabela tickets
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'tickets'
        """)
        tcols = {row[0] for row in cur.fetchall()}
        if 'closed_by' not in tcols:
            cur.execute("ALTER TABLE tickets ADD COLUMN closed_by INTEGER")

        # Migrar senhas para hash sha256 se necessário
        cur.execute('SELECT id, password FROM users')
        rows = cur.fetchall()
        for row in rows:
            user_id, pwd = row
            pwd = pwd or ''
            is_hex64 = isinstance(pwd, str) and len(pwd) == 64 and all(c in '0123456789abcdef' for c in pwd.lower())
            if not is_hex64:
                hashed = hash_password(pwd)
                cur.execute('UPDATE users SET password = %s WHERE id = %s', (hashed, user_id))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print(f"Erro ao garantir schema: {str(e)}")


#Helper centralizado
def run_query(query, params=None, fetchone=False, fetchall=False, commit=False, dict_cursor=False):
    """
    Executa uma query no PostgreSQL com tratamento de conexão e erros.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor if dict_cursor else None)
    try:
        cur.execute(query, params or ()) 
        result = None
        if fetchone:
            result = cur.fetchone()
        elif fetchall:
            result = cur.fetchall()
        if commit:
            conn.commit()
        return result
    except IntegrityError as e:
        conn.rollback()
        raise e
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


# Helper to notify user on ticket events
def notify_user_ticket_update(user_id: int, ticket: dict, event_type: str):
    """Send Telegram/SMS/push based on user preferences for ticket updates."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute('SELECT name, email, phone, email_updates, sms_urgent, push_realtime FROM users WHERE id = %s', (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            return
            
        # Telegram notification (replaces email)
        if bool(user['email_updates']):  # Using email_updates preference for Telegram
            ticket_id = ticket.get('id', '')
            ticket_type = ticket.get('type', '')
            priority = ticket.get('priority', '')
            subject = ticket.get('subject', ticket.get('description', ''))[:50]
            user_name = user['name'] or 'Usuário'
            
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
        if user['sms_urgent'] and ticket.get('priority') == 'Urgente' and user['phone']:
            try:
                sms_body = f"[URGENTE] Chamado #{ticket.get('id')} - {event_type}"
                send_sms(user['phone'], sms_body)
            except Exception as e:
                print(f"Erro ao enviar SMS: {str(e)}")
                
        # Push via SSE
        if bool((user['push_realtime'])):
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


# Rotas da aplicação
@app.before_request
def enforce_https():
    # Se não estiver em produção, pular o redirecionamento
    if app.debug or os.environ.get('FLASK_ENV') == 'development':
        return
        
    if request.scheme != 'https':
        url = request.url.replace('http://', 'https://')
        return redirect(url)

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = 'remember' in request.form

        print(f"=== TENTATIVA DE LOGIN ===")
        print(f"Email: {email}")
        print(f"Password: {hash_password(password)}")

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)

        print(f"\n--- Buscando usuário no banco ---")
        cur.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cur.fetchone()

        if user:
            print(f"\n--- Usuário encontrado ---")
            print(f"ID: {user['id']}")
            print(f"Email: {user['email']}")
            print(f"Name: {user['name']}")
            print(f"Role: {user['role']}")
            print(f"Password no banco: {user['password']}")
            print(f"Password informado: {hash_password(password)}")
            
            # Verificar se a senha bate
            if user['password'] == hash_password(password):
                print(f"\n--- SENHA CORRETA - Login bem-sucedido ---")
                
                # Determinar privilégios
                role = user.get('role', 'user')
                is_admin = role in ['admin', 'manager']
                print(f"Role: {role}, Is Admin: {is_admin}")
                
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                session['user_name'] = user['name'] if user['name'] else 'Usuário'
                session['user_role'] = role
                session['is_admin'] = is_admin
                
                redirect_to = 'admin_dashboard' if is_admin else 'user_dashboard'
                print(f"Redirecionando para: {redirect_to}")
                
                resp = make_response(redirect(url_for(redirect_to)))
                if remember:
                    session.permanent = True
                    resp.set_cookie('remember_me', 'true', max_age=app.permanent_session_lifetime.total_seconds())
                    resp.set_cookie('remembered_email', email, max_age=app.permanent_session_lifetime.total_seconds())
                else:
                    resp.set_cookie('remember_me', '', expires=0)
                    resp.set_cookie('remembered_email', '', expires=0)
                return resp
            else:
                print(f"\n--- SENHA INCORRETA ---")
        else:
            print(f"\n--- USUÁRIO NÃO ENCONTRADO ---")
        
        cur.close()
        conn.close()
        flash('Email ou senha incorretos', 'error')
        return redirect(url_for('index'))
    else:
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

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']
        if new_password != confirm_password:
            flash('As senhas não coincidem', 'error')
            return redirect(url_for('recover'))
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
        if user:
            # Update password in database (store hashed)
            cur.execute('UPDATE users SET password = %s WHERE email = %s', (hash_password(new_password), email))
            flash('Senha alterada com sucesso', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email não encontrado', 'error')
        cur.close()
        conn.close()
        return redirect(url_for('recover'))
    return render_template('recover.html')

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
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute("SELECT * FROM logs WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
    logs = cur.fetchall()
    cur.close()
    conn.close()
    formatted_logs = []
    for log in logs:
        log_dict = dict(log)
        log_dict['created_at'] = format_date(log_dict.get('created_at'))
        formatted_logs.append(log_dict)
    return jsonify(formatted_logs)

@app.route('/api/logs/<int:log_id>/read', methods=['PUT'])
def mark_log_as_read(log_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE logs SET is_read = TRUE WHERE id = %s AND user_id = %s", (log_id, session['user_id']))
    cur.close()
    conn.close()
    return jsonify({'success': True})

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
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'GET':
        cur.execute('SELECT value FROM settings WHERE key = %s', ('help_center',))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row or not row['value']:
            return jsonify(default_help_center_config)
        try:
            value = json.loads(row['value'])
            return jsonify(value)
        except Exception:
            return jsonify(default_help_center_config)
    # PUT
    if not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        cur.close()
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403
    try:
        payload = request.get_json(force=True)
    except Exception:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid JSON'}), 400
    # Basic validation
    if not isinstance(payload, dict):
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid payload'}), 400
    try:
        cur.execute('INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value',
                    ('help_center', json.dumps(payload, ensure_ascii=False)))
    finally:
        cur.close()
        conn.close()
    return jsonify({'success': True})


@app.route('/api/tickets', methods=['GET', 'POST'])
def api_tickets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # Handle POST for creating tickets
    if request.method == 'POST':
        def after_insert_notify(conn, ticket_id):
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute('SELECT id, user_id, type, priority, subject, description, status FROM tickets WHERE id = %s', (ticket_id,))
            t = cur.fetchone()
            if t:
                log_event(t['user_id'], f"Novo ticket criado: {t['subject']}", ticket_id)
                notify_user_ticket_update(t['user_id'], dict(t), 'created')
                cur.execute("SELECT id FROM users WHERE is_admin = TRUE OR role IN ('admin', 'manager')")
                admins = cur.fetchall()
                for admin in admins:
                    log_event(admin['id'], f"Novo ticket #{ticket_id} criado por {session['user_name']}", ticket_id)
                    push_event(admin['id'], {'type': 'ticket_update', 'event': 'created', 'ticket': dict(t)})
                
                # Notificação para administradores no Telegram
                try:
                    user_name = session.get('user_name', 'Usuário')
                    ticket_type = t.get('type', 'N/A')
                    priority = t.get('priority', 'N/A')
                    subject = t.get('subject') or (t.get('description', '')[:50])

                    message = (
                        f"\U0001F4E8 <b>Novo Chamado Criado</b>\n\n"
                        f"<b>ID:</b> #{ticket_id}\n"
                        f"<b>Usuário:</b> {user_name}\n"
                        f"<b>Tipo:</b> {ticket_type}\n"
                        f"<b>Prioridade:</b> {priority}\n"
                        f"<b>Assunto:</b> {subject}"
                    )
                    send_telegram_notification(message, 'created')
                except Exception as e:
                    print(f"Erro ao enviar notificação de novo ticket para Telegram: {str(e)}")
            cur.close()

        # If multipart/form-data (supports attachments)
        if request.content_type and 'multipart/form-data' in request.content_type:
            form = request.form
            type_ = form.get('type')
            priority = form.get('priority')
            subject = form.get('subject', '')
            description = form.get('description')
            if not type_ or not priority or not description:
                return jsonify({'error': 'Campos obrigatórios ausentes'}), 400
            
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute('''INSERT INTO tickets (user_id, type, priority, subject, description, status, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id''',
                            (session['user_id'], type_, priority, subject, description, 'Aberto'))
                ticket_id = cur.fetchone()[0]
                files = request.files.getlist('attachments')
                for f in files:
                    if f and allowed_file(f.filename):
                        f.seek(0, os.SEEK_END)
                        size = f.tell()
                        f.seek(0)
                        if size > MAX_FILE_SIZE:
                            return jsonify({'error': f'Arquivo muito grande: {f.filename}. Limite 10MB por arquivo.'}), 400
                        original = secure_filename(f.filename)
                        unique_name = f"{ticket_id}_{secrets.token_hex(4)}_{original}"
                        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
                        f.save(save_path)
                        filesize = os.path.getsize(save_path)
                        cur.execute('''INSERT INTO attachments (ticket_id, filename, filepath, filesize)
                                       VALUES (%s, %s, %s, %s)''',
                                    (ticket_id, original, unique_name, filesize))
                    elif f:
                        return jsonify({'error': f'Extensão não permitida: {f.filename}'}), 400
                
                after_insert_notify(conn, ticket_id)
                return jsonify({'success': True, 'ticket_id': ticket_id})
            except Exception as e:
                print(f"Erro ao criar ticket (form-data): {e}")
                return jsonify({'error': 'Erro interno ao criar ticket'}), 500
            finally:
                cur.close()
                conn.close()

        # JSON fallback (without attachments)
        else:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request must be JSON'}), 400
            
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute('''INSERT INTO tickets (user_id, type, priority, subject, description, status, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id''',
                            (session['user_id'], data['type'], data['priority'], 
                             data.get('subject', ''), data['description'], 'Aberto'))
                ticket_id = cur.fetchone()[0]
                after_insert_notify(conn, ticket_id)
                return jsonify({'success': True, 'ticket_id': ticket_id})
            except Exception as e:
                print(f"Erro ao criar ticket (JSON): {e}")
                return jsonify({'error': 'Erro interno ao criar ticket'}), 500
            finally:
                cur.close()
                conn.close()

    # Handle GET for listing tickets
    else: # request.method == 'GET'
        print(f"=== API TICKETS (GET) ===")
        print(f"User ID: {session.get('user_id')}")
        print(f"User Role: {session.get('user_role')}")
        print(f"Is Admin: {session.get('is_admin')}")
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        try:
            if session.get('is_admin') or session.get('user_role') in ['admin', 'manager']:
                cur.execute('''
                    SELECT t.id, 
                           t.type, 
                           t.priority, 
                           t.subject, 
                           t.status, 
                           COALESCE(u.name, '') as user_name, 
                           COALESCE(a.name, '') as assigned_to_name,
                           t.created_at,
                           t.updated_at
                    FROM tickets t 
                    LEFT JOIN users u ON t.user_id = u.id 
                    LEFT JOIN users a ON t.assigned_to = a.id
                    ORDER BY t.created_at DESC
                ''')
            else:
                cur.execute('''
                    SELECT id, type, priority, subject, status, 
                           (SELECT name FROM users WHERE id = user_id) as user_name,
                           (SELECT name FROM users WHERE id = assigned_to) as assigned_to_name,
                           created_at,
                           updated_at
                    FROM tickets 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC
                ''', (session['user_id'],))
            
            tickets = cur.fetchall()
            print(f"Retornando {len(tickets)} tickets")
            
            formatted_tickets = []
            for ticket in tickets:
                ticket_dict = dict(ticket)
                ticket_dict['created_at'] = format_date(ticket_dict.get('created_at'))
                ticket_dict['updated_at'] = format_date(ticket_dict.get('updated_at'))
                ticket_dict['user_name'] = ticket_dict.get('user_name', '')
                ticket_dict['assigned_to_name'] = ticket_dict.get('assigned_to_name', '')
                formatted_tickets.append(ticket_dict)
            
            return jsonify(formatted_tickets)
            
        except Exception as e:
            print(f"ERRO ao carregar tickets: {str(e)}")
            print(f"Tipo do erro: {type(e)}")
            return jsonify({'error': str(e)}), 500
        finally:
            cur.close()
            conn.close()


@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
def api_get_ticket(ticket_id):
    """Buscar detalhes de um ticket específico"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    print(f"=== API GET TICKET {ticket_id} ===")
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    try:
        # Buscar ticket principal com LEFT JOINs para nomes
        cur.execute('''
            SELECT t.id, 
                   t.type, 
                   t.priority, 
                   t.subject, 
                   t.description, 
                   t.status,
                   COALESCE(u.name, '') as user_name, 
                   COALESCE(a.name, '') as assigned_to_name,
                   t.created_at,
                   t.updated_at,
                   t.closed_at
            FROM tickets t 
            LEFT JOIN users u ON t.user_id = u.id 
            LEFT JOIN users a ON t.assigned_to = a.id
            WHERE t.id = %s
        ''', (ticket_id,))
        ticket = cur.fetchone()
        
        if not ticket:
            print(f"Ticket {ticket_id} não encontrado")
            return jsonify({'error': 'Not found'}), 404
        
        print(f"Ticket encontrado: {dict(ticket)}")
        
        # Buscar anexos
        cur.execute('''
            SELECT id, filename, filepath, filesize, uploaded_at 
            FROM attachments 
            WHERE ticket_id = %s 
            ORDER BY uploaded_at DESC
        ''', (ticket_id,))
        attachments = cur.fetchall()
        
        # Formatar resposta
        ticket_dict = dict(ticket)

        # Formatar datas
        for date_field in ['created_at', 'updated_at', 'closed_at']:
            if ticket_dict.get(date_field):
                ticket_dict[date_field] = ticket_dict[date_field].isoformat() if hasattr(ticket_dict[date_field], 'isoformat') else str(ticket_dict[date_field])
        
        # Formatar anexos
        ticket_dict['attachments'] = [
            {
                'id': a['id'],
                'filename': a['filename'],
                'url': url_for('uploaded_file', filename=a['filepath']),
                'filesize': a['filesize'],
                'uploaded_at': format_date(a['uploaded_at'])
            } for a in attachments
        ]
        
        print(f"Ticket com {len(attachments)} anexos")
        return jsonify(ticket_dict)
        
    except Exception as e:
        print(f"Erro ao buscar ticket {ticket_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

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
            COUNT(*) FILTER (
                WHERE status IN ('Aberto', 'Em Andamento', 'Pendente')
            ) AS open,
            COUNT(*) FILTER (
                WHERE status IN ('Resolvido', 'Fechado', 'Concluído', 'Finalizado')
            ) AS resolved
        FROM tickets
    """, fetchone=True, dict_cursor=True) or {'total': 0, 'open': 0, 'resolved': 0}

    return jsonify({
        'stats': {
            'total': stats['total'],
            'open': stats['open'],
            'resolved': stats['resolved']
        },
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


@app.route('/api/admin/tickets/<int:ticket_id>/status', methods=['PUT'])
def api_admin_update_ticket_status(ticket_id):
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    status = data.get('status')

    # Verificar se o ticket existe e obter informações de atribuição
    ticket = run_query(
        "SELECT * FROM tickets WHERE id = %s",
        (ticket_id,),
        fetchone=True,
        dict_cursor=True
    )
    if not ticket:
        return jsonify({'error': 'Ticket não encontrado'}), 404

    # Se o status for de finalização e houver um responsável atribuído
    if status in ['Resolvido', 'Fechado', 'Rejeitado'] and ticket['assigned_to']:
        # Apenas o responsável atribuído pode finalizar o chamado
        if session['user_id'] != ticket['assigned_to']:
            return jsonify({'error': 'Somente o administrador responsável por este chamado pode finalizá-lo'}), 403

    # Atualiza status e updated_at
    run_query(
        "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s",
        (status, ticket_id),
        commit=True
    )

    # Se for finalização, atualiza closed_at e closed_by
    if status in ['Resolvido', 'Fechado', 'Rejeitado']:
        run_query(
            "UPDATE tickets SET closed_at = NOW(), closed_by = %s WHERE id = %s",
            (session['user_id'], ticket_id),
            commit=True
        )

    # Buscar ticket atualizado para notificação
    t = run_query(
        "SELECT id, user_id, type, priority, subject, description, status FROM tickets WHERE id = %s",
        (ticket_id,),
        fetchone=True,
        dict_cursor=True
    )

    if t:
        t_dict = dict(t)
        t_dict['created_at'] = format_date(t_dict.get('created_at'))
        t_dict['updated_at'] = format_date(t_dict.get('updated_at'))
        t_dict['closed_at'] = format_date(t_dict.get('closed_at'))

        # Determinar tipo de evento
        event_type = 'status_changed'
        if status in ['Resolvido', 'Fechado']:
            event_type = 'closed'
            log_event(t['user_id'], f"Seu ticket #{ticket_id} foi concluído.", ticket_id)
        elif status == 'Cancelado':
            event_type = 'cancelled'
            log_event(t['user_id'], f"Seu ticket #{ticket_id} foi cancelado.", ticket_id)
        else:
            log_event(t['user_id'], f"O status do seu ticket #{ticket_id} foi alterado para {status}.", ticket_id)

        notify_user_ticket_update(t['user_id'], t_dict, event_type)

    return jsonify({'success': True})


@app.route('/api/tickets/<int:ticket_id>/responses', methods=['GET'])
def api_get_ticket_responses(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # Verifica se o ticket existe e pega o dono
    ticket = run_query(
        "SELECT user_id FROM tickets WHERE id = %s",
        (ticket_id,),
        fetchone=True,
        dict_cursor=True
    )
    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404

    # Permissão: dono do ticket ou staff (admin/manager)
    if not (
        (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'])
        or ticket['user_id'] == session['user_id']
    ):
        return jsonify({'error': 'Forbidden'}), 403

    # Busca respostas do ticket
    responses = run_query("""
        SELECT tr.id, tr.message, tr.created_at, u.name AS user_name,
               CASE WHEN u.is_admin = TRUE THEN 'admin' ELSE 'user' END AS user_role
        FROM ticket_responses tr
        JOIN users u ON tr.user_id = u.id
        WHERE tr.ticket_id = %s
        ORDER BY tr.created_at ASC
    """, (ticket_id,), fetchall=True, dict_cursor=True)

    # Formata datas
    formatted_responses = []
    for r in responses:
        r_dict = dict(r)
        r_dict['created_at'] = format_date(r_dict.get('created_at'))
        formatted_responses.append(r_dict)

    return jsonify(formatted_responses)


@app.route('/api/tickets/<int:ticket_id>/responses', methods=['POST'])
def api_create_ticket_response(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    # Buscar ticket com nome do usuário
    ticket = run_query("""
        SELECT t.*, u.name AS user_name
        FROM tickets t
        LEFT JOIN users u ON t.user_id = u.id
        WHERE t.id = %s
    """, (ticket_id,), fetchone=True, dict_cursor=True)

    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404

    # Buscar nome do administrador atribuído (se houver)
    assigned_user = None
    if ticket['assigned_to']:
        assigned_user = run_query(
            "SELECT name FROM users WHERE id = %s",
            (ticket['assigned_to'],),
            fetchone=True,
            dict_cursor=True
        )

    # Permissões
    is_owner = (ticket['user_id'] == session['user_id'])
    is_staff = (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'])
    assigned_to = ticket['assigned_to']

    if is_staff and assigned_to:
        if session['user_id'] != assigned_to:
            return jsonify({'error': 'Somente o administrador designado pode responder a este ticket'}), 403
    elif not (is_owner or is_staff):
        return jsonify({'error': 'Forbidden'}), 403

    # Inserir resposta e obter ID e data de criação
    response_row = run_query("""
        INSERT INTO ticket_responses (ticket_id, user_id, message, created_at)
        VALUES (%s, %s, %s, NOW())
        RETURNING id, created_at
    """, (ticket_id, session['user_id'], message), fetchone=True, commit=True)

    response_id = response_row[0] if response_row else None
    response_created_at = response_row[1] if response_row else datetime.now()

    # Notificações
    if is_staff:
        log_event(ticket['user_id'], f"O suporte respondeu ao seu ticket #{ticket_id}.", ticket_id)
        
        # Get user preferences for SMS and Push
        user_prefs = run_query("SELECT phone, sms_urgent, push_realtime FROM users WHERE id = %s", (ticket['user_id'],), fetchone=True, dict_cursor=True)

        # Send SMS if urgent
        if user_prefs and user_prefs['sms_urgent'] and ticket.get('priority') == 'Urgente' and user_prefs['phone']:
            sms_body = f"[URGENTE] Nova resposta do suporte no chamado #{ticket.get('id')}"
            send_sms(user_prefs['phone'], sms_body)

        # Send Push via SSE with detailed response object
        if user_prefs and user_prefs['push_realtime']:
            push_event(ticket['user_id'], {
                'type': 'new_response',
                'ticket_id': ticket_id,
                'response': {
                    'id': response_id,
                    'message': message,
                    'user_name': session['user_name'],
                    'user_role': session.get('user_role', 'admin'),
                    'created_at': format_date(response_created_at)
                }
            })

        # Send ONE detailed Telegram notification
        try:
            admin_name = session.get('user_name', 'Administrador')
            assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user else None
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            
            response_message = f"\U0001F4AC <b>Nova Resposta do Suporte</b>\n\n"
            response_message += f"<b>ID:</b> #{ticket_id}\n"
            response_message += f"<b>Respondido por:</b> {admin_name}\n"
            if assignee:
                response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
            response_message += f"<b>Tipo:</b> {ticket_type}\n"
            response_message += f"<b>Usuário:</b> {user_name}\n"
            response_message += f"<b>Mensagem:</b> {message[:500]}{'...' if len(message) > 500 else ''}"
            
            send_telegram_notification(response_message, 'response_admin')
        except Exception as e:
            print(f"Erro ao enviar notificação de resposta admin: {str(e)}")

    else: # User is replying
        staff_users = run_query(
            "SELECT id FROM users WHERE role IN ('admin', 'manager')",
            fetchall=True,
            dict_cursor=True
        )
        
        # Create a serializable ticket dictionary to notify admins
        serializable_ticket = dict(ticket)
        serializable_ticket['created_at'] = format_date(serializable_ticket.get('created_at'))
        serializable_ticket['updated_at'] = format_date(serializable_ticket.get('updated_at'))
        serializable_ticket['closed_at'] = format_date(serializable_ticket.get('closed_at'))

        for staff in staff_users:
            log_event(staff['id'], f"Nova resposta do usuário no ticket #{ticket_id}", ticket_id)
            # Push a more detailed event to admins
            push_event(staff['id'], {
                'type': 'new_response',
                'ticket_id': ticket_id,
                'ticket_subject': serializable_ticket['subject'],
                'response': {
                    'id': response_id,
                    'message': message,
                    'user_name': session['user_name'],
                    'user_role': 'user',
                    'created_at': format_date(response_created_at)
                }
            })

        try:
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user else None
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            
            response_message = f"\U0001F4E8 <b>Nova Resposta do Usuário</b>\n\n"
            response_message += f"<b>ID:</b> #{ticket_id}\n"
            response_message += f"<b>Usuário:</b> {user_name}\n"
            if assignee:
                response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
            response_message += f"<b>Tipo:</b> {ticket_type}\n"
            response_message += f"<b>Prioridade:</b> {ticket_priority}\n"
            response_message += f"<b>Mensagem:</b> {message[:500]}{'...' if len(message) > 500 else ''}"
            
            send_telegram_notification(response_message, 'response_user')
        except Exception as e:
            print(f"Erro ao enviar notificação de resposta usuário: {str(e)}")

    return jsonify({
        'success': True,
        'response_id': response_id,
        'created_at': format_date(response_created_at)
    })


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
            f"\U0001F916 <b>Teste de Conexão</b>\n\n"
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


@app.route('/api/admin/tickets/<int:ticket_id>/assign', methods=['PUT'])
def api_admin_assign_ticket(ticket_id):
    """Atribui um ticket a um administrador ou gerente"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    print(f"=== ATRIBUIÇÃO DE TICKET {ticket_id} ===")

    data = request.get_json() or {}
    assigned_to = data.get('assigned_to')

    if not assigned_to:
        print("ERRO: ID do administrador não fornecido")
        return jsonify({'error': 'ID do administrador é obrigatório'}), 400

    try:
        # Verificar se o ticket existe
        ticket = run_query("""
            SELECT t.*, u.name AS user_name
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        """, (ticket_id,), fetchone=True, dict_cursor=True)

        if not ticket:
            print(f"ERRO: Ticket {ticket_id} não encontrado")
            return jsonify({'error': 'Ticket não encontrado'}), 404

        # Verificar se o usuário é admin/manager
        assigned_user = run_query("""
            SELECT name, email FROM users
            WHERE id = %s AND role IN ('admin', 'manager')
        """, (assigned_to,), fetchone=True, dict_cursor=True)

        if not assigned_user:
            print(f"ERRO: Usuário {assigned_to} não é administrador")
            return jsonify({'error': 'Usuário não é um administrador ou gerente'}), 400

        print(f"Atribuindo ticket {ticket_id} para {assigned_user['name']}")

        # Atribuir o ticket
        run_query("""
            UPDATE tickets
            SET assigned_to = %s, updated_at = NOW()
            WHERE id = %s
        """, (assigned_to, ticket_id), commit=True)

        # Log e notificações
        log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi atribuído ao administrador {assigned_user['name']}.", ticket_id)
        log_event(assigned_to, f"Você foi designado para o ticket #{ticket_id}.", ticket_id)

        # Notificação especial no Telegram
        try:
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            ticket_subject = ticket['subject'] if ticket['subject'] else (
                ticket['description'][:50] if ticket['description'] else 'N/A'
            )

            assignment_message = (
                f"\U0001F464 <b>Chamado Atribuído</b>\n\n"
                f"<b>ID:</b> #{ticket_id}\n"
                f"<b>Responsável:</b> {assigned_user['name']}\n"
                f"<b>Tipo:</b> {ticket_type}\n"
                f"<b>Prioridade:</b> {ticket_priority}\n"
                f"<b>Assunto:</b> {ticket_subject}\n"
                f"<b>Usuário:</b> {user_name}"
            )

            send_telegram_notification(assignment_message, 'assigned')
        except Exception as e:
            print(f"Erro ao enviar notificação de atribuição: {str(e)}")

        # Push notifications
        notify_user_ticket_update(ticket['user_id'], dict(ticket), 'assigned')
        push_event(assigned_to, {
            'type': 'ticket_update',
            'event': 'assigned_to_you',
            'ticket': {
                'id': ticket['id'],
                'subject': ticket['subject'],
                'priority': ticket['priority']
            }
        })

        # Buscar ticket atualizado para retorno com datas formatadas
        updated_ticket = run_query("""
            SELECT id, subject, priority, created_at, updated_at, closed_at
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
            'assigned_to': assigned_user['name'],
            'message': f'Ticket atribuído para {assigned_user["name"]}',
            'ticket': updated_ticket
        })

    except Exception as e:
        print(f"Erro ao atribuir ticket: {str(e)}")
        return jsonify({'error': 'Erro interno ao atribuir ticket'}), 500


@app.route('/api/admin/tickets/<int:ticket_id>/cancel', methods=['PUT'])
def api_admin_cancel_ticket(ticket_id):
    """Cancela um ticket (apenas gerentes)"""
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

        # Cancelar ticket
        run_query("""
            UPDATE tickets
            SET status = 'Cancelado', updated_at = NOW()
            WHERE id = %s
        """, (ticket_id,), commit=True)

        manager_name = session.get('user_name', 'Gerente')

        # Log e notificações
        log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi cancelado pelo gerente {manager_name}.", ticket_id)
        notify_user_ticket_update(ticket['user_id'], dict(ticket), 'cancelled')

        # Notificação no Telegram
        try:
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            ticket_subject = ticket['subject'] if ticket['subject'] else (
                ticket['description'][:50] if ticket['description'] else 'N/A'
            )

            cancel_message = (
                f"\U0000274C <b>Chamado Cancelado</b>\n\n"
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


@app.route('/api/admin/tickets/<int:ticket_id>/reopen', methods=['PUT'])
def api_admin_reopen_ticket(ticket_id):
    """Reabre um ticket fechado ou cancelado (apenas gerentes para tickets cancelados)"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    print(f"=== REABERTURA DO TICKET {ticket_id} ===")

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

        # Se o ticket foi cancelado, apenas gerentes podem reabrir
        if ticket['status'] == 'Cancelado' and session.get('user_role') != 'manager':
            return jsonify({'error': 'Apenas gerentes podem reabrir tickets cancelados'}), 403

        # Atualiza status para Aberto, limpa fechamento e quem fechou
        run_query("""
            UPDATE tickets
            SET status = 'Aberto', updated_at = NOW(), closed_at = NULL, closed_by = NULL
            WHERE id = %s
        """, (ticket_id,), commit=True)

        user_id = ticket['user_id']
        assigned_to = ticket['assigned_to']
        closed_by = ticket.get('closed_by')

        # Notificar usuário dono
        log_event(user_id, f"Seu ticket #{ticket_id} foi reaberto.", ticket_id)
        notify_user_ticket_update(user_id, dict(ticket), 'reopened')

        # Notificar responsável (se houver)
        if assigned_to:
            log_event(assigned_to, f"Ticket #{ticket_id} foi reaberto.", ticket_id)
            push_event(assigned_to, {
                'type': 'ticket_update',
                'event': 'reopened',
                'ticket': {
                    'id': ticket['id'],
                    'subject': ticket['subject'],
                    'priority': ticket['priority']
                }
            })

        # Notificar quem fechou (se conhecido)
        if closed_by:
            log_event(closed_by, f"Ticket #{ticket_id} que você havia fechado foi reaberto.", ticket_id)
            push_event(closed_by, {
                'type': 'ticket_update',
                'event': 'reopened',
                'ticket': {
                    'id': ticket['id'],
                    'subject': ticket['subject'],
                    'priority': ticket['priority']
                }
            })

        # Notificar todos os gerentes
        managers = run_query(
            "SELECT id FROM users WHERE role = 'manager'",
            fetchall=True,
            dict_cursor=True
        )
        for m in managers:
            log_event(m['id'], f"Ticket #{ticket_id} foi reaberto.", ticket_id)
            push_event(m['id'], {
                'type': 'ticket_update',
                'event': 'reopened',
                'ticket': {
                    'id': ticket['id'],
                    'subject': ticket['subject'],
                    'priority': ticket['priority']
                }
            })

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
            'message': f"Ticket #{ticket_id} reaberto com sucesso",
            'ticket': updated_ticket
        })

    except Exception as e:
        print(f"Erro ao reabrir ticket: {str(e)}")
        return jsonify({'error': 'Erro interno ao reabrir ticket'}), 500


@app.route('/api/ticket-types', methods=['GET'])
def api_get_ticket_types():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    ticket_types = run_query("""
        SELECT * 
        FROM ticket_types 
        WHERE active = TRUE 
        ORDER BY name
    """, fetchall=True, dict_cursor=True)

    return jsonify([dict(ticket_type) for ticket_type in ticket_types])


@app.route('/api/ticket-types', methods=['POST'])
def api_create_ticket_type():
    """Cria um novo tipo de chamado"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()

    if not name:
        return jsonify({'error': 'O nome do tipo de chamado é obrigatório'}), 400

    print(f"=== CRIANDO TIPO DE CHAMADO: {name} ===")

    try:
        run_query("""
            INSERT INTO ticket_types (name, description, active)
            VALUES (%s, %s, TRUE)
        """, (name, description), commit=True)

        return jsonify({'success': True})

    except IntegrityError:
        print(f"ERRO: Tipo de chamado '{name}' já existe")
        return jsonify({'error': 'Tipo de chamado já existe'}), 400

    except Exception as e:
        print(f"Erro ao criar tipo de chamado: {str(e)}")
        return jsonify({'error': 'Erro interno ao criar tipo de chamado'}), 500


@app.route('/api/ticket-types/<int:type_id>', methods=['PUT'])
def api_update_ticket_type(type_id):
    """Atualiza um tipo de chamado existente"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    active = data.get('active', True)

    if not name:
        return jsonify({'error': 'O nome do tipo de chamado é obrigatório'}), 400

    print(f"=== ATUALIZANDO TIPO DE CHAMADO ID {type_id} ===")

    try:
        run_query("""
            UPDATE ticket_types
            SET name = %s, description = %s, active = %s
            WHERE id = %s
        """, (name, description, active, type_id), commit=True)

        return jsonify({
            'success': True,
            'message': f"Tipo de chamado '{name}' atualizado com sucesso"
        })

    except Exception as e:
        print(f"Erro ao atualizar tipo de chamado: {str(e)}")
        return jsonify({'error': 'Erro interno ao atualizar tipo de chamado'}), 500


@app.route('/api/ticket-types/<int:type_id>', methods=['DELETE'])
def api_delete_ticket_type(type_id):
    """Marca um tipo de chamado como inativo (soft delete)"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    print(f"=== MARCANDO TIPO DE CHAMADO ID {type_id} COMO INATIVO ===")

    try:
        run_query("""
            UPDATE ticket_types
            SET active = FALSE
            WHERE id = %s
        """, (type_id,), commit=True)

        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro ao inativar tipo de chamado: {str(e)}")
        return jsonify({'error': 'Erro interno ao inativar tipo de chamado'}), 500


@app.route('/api/ticket-statuses', methods=['GET'])
def api_get_ticket_statuses():
    """Lista todos os status de ticket ativos"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    print("=== LISTANDO STATUS DE TICKET ATIVOS ===")

    try:
        ticket_statuses = run_query("""
            SELECT *
            FROM ticket_statuses
            WHERE active = TRUE
            ORDER BY name
        """, fetchall=True, dict_cursor=True)

        return jsonify([dict(status) for status in ticket_statuses])
    except Exception as e:
        print(f"Erro ao buscar status de ticket: {str(e)}")
        return jsonify({'error': 'Erro interno ao buscar status de ticket'}), 500


@app.route('/api/ticket-statuses', methods=['POST'])
def api_create_ticket_status():
    """Cria um novo status de chamado"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    color = data.get('color', '#808080').strip()

    if not name:
        return jsonify({'error': 'O nome do status é obrigatório'}), 400

    print(f"=== CRIANDO STATUS DE CHAMADO: {name} ===")

    try:
        run_query("""
            INSERT INTO ticket_statuses (name, color, active)
            VALUES (%s, %s, TRUE)
        """, (name, color), commit=True)

        return jsonify({'success': True})

    except IntegrityError:
        print(f"ERRO: Status de chamado '{name}' já existe")
        return jsonify({'error': 'Status de chamado já existe'}), 400

    except Exception as e:
        print(f"Erro ao criar status de chamado: {str(e)}")
        return jsonify({'error': 'Erro interno ao criar status de chamado'}), 500


@app.route('/api/ticket-statuses/<int:status_id>', methods=['PUT'])
def api_update_ticket_status(status_id):
    """Atualiza um status de chamado existente"""
    if 'user_id' not in session or not (
        session.get('is_admin') or session.get('user_role') in ['admin', 'manager']
    ):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    color = data.get('color', '#808080').strip()
    active = data.get('active', True)

    if not name:
        return jsonify({'error': 'O nome do status é obrigatório'}), 400

    print(f"=== ATUALIZANDO STATUS DE CHAMADO ID {status_id} ===")

    try:
        run_query("""
            UPDATE ticket_statuses
            SET name = %s, color = %s, active = %s
            WHERE id = %s
        """, (name, color, active, status_id), commit=True)

        return jsonify({
            'success': True,
            'message': f"Status de chamado '{name}' atualizado com sucesso"
        })

    except Exception as e:
        print(f"Erro ao atualizar status de chamado: {str(e)}")
        return jsonify({'error': 'Erro interno ao atualizar status de chamado'}), 500


@app.route('/api/ticket-statuses/<int:status_id>', methods=['DELETE'])
def api_delete_ticket_status(status_id):
    """Marca um status de chamado como inativo (soft delete)"""
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 401

    print(f"=== MARCANDO STATUS DE CHAMADO ID {status_id} COMO INATIVO ===")

    try:
        run_query("""
            UPDATE ticket_statuses
            SET active = FALSE
            WHERE id = %s
        """, (status_id,), commit=True)

        return jsonify({
            'success': True,
            'message': f"Status de chamado ID {status_id} marcado como inativo"
        })

    except Exception as e:
        print(f"Erro ao inativar status de chamado: {str(e)}")
        return jsonify({'error': 'Erro interno ao inativar status de chamado'}), 500


@app.route('/debug')
def debug_frontend():
    """Página de debug para testar o frontend"""
    return send_from_directory('.', 'debug_frontend.html')

# Substituir a parte final do arquivo por esta:

if __name__ == '__main__':
    init_database()

    app.run(host='0.0.0.0', port=5000, debug=True)