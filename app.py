from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify, send_from_directory, Response, stream_with_context
import psycopg2
from psycopg2.extras import DictCursor
from datetime import timedelta
import secrets
import string
import hashlib
import os
import queue
import json
from collections import defaultdict
from werkzeug.utils import secure_filename
from database import init_database

app = Flask(__name__, static_folder='static')
app.secret_key = 'super_secret_key'
app.permanent_session_lifetime = timedelta(days=7)

# Uploads configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'xls', 'xlsx', 'csv'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Funções auxiliares - definidas antes de serem usadas
def get_db_connection():
    try:
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        conn.autocommit = True
        return conn
    except psycopg2.Error as e:
        print(f"Erro ao conectar ao banco de dados: {str(e)}")
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
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and user['password'] == hash_password(password):
            # Determinar privilégios com base na coluna de função (role)
            role = user.get('role', 'user')
            is_admin = role in ['admin', 'manager']

            # Definir sessão
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = user['name'] if user['name'] else 'Usuário'
            session['user_role'] = role
            session['is_admin'] = is_admin

            redirect_to = 'admin_dashboard' if is_admin else 'user_dashboard'
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
    return jsonify(logs)

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

@app.route('/api/tickets', methods=['GET'])
def api_get_tickets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        if session.get('is_admin') or session.get('user_role') in ['admin', 'manager']:
            cur.execute('''
                SELECT t.*, u.name as user_name, a.name as assigned_to_name 
                FROM tickets t 
                LEFT JOIN users u ON t.user_id = u.id 
                LEFT JOIN users a ON t.assigned_to = a.id
                ORDER BY t.created_at DESC
            ''')
            tickets = cur.fetchall()
        else:
            cur.execute('SELECT * FROM tickets WHERE user_id = %s ORDER BY created_at DESC', 
                                  (session['user_id'],))
            tickets = cur.fetchall()
        
        # Log para depuração
        print(f"Retornando {len(tickets)} tickets para usuário {session.get('user_id')}")
        
        return jsonify(tickets)
    except Exception as e:
        print(f"Erro ao carregar tickets: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
def api_get_ticket(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT * FROM tickets WHERE id = %s', (ticket_id,))
    ticket = cur.fetchone()
    if not ticket:
        cur.close()
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    # Authorization: admin or ticket owner
    is_owner = (ticket['user_id'] == session['user_id'])
    if not ((session.get('is_admin') or session.get('user_role') in ['admin', 'manager']) or is_owner):
        cur.close()
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403
    cur.execute(
        'SELECT id, filename, filepath, filesize, uploaded_at FROM attachments WHERE ticket_id = %s ORDER BY uploaded_at DESC',
        (ticket_id,)
    )
    attachments = cur.fetchall()
    ticket['attachments'] = [
        {
            'id': a['id'],
            'filename': a['filename'],
            'url': url_for('uploaded_file', filename=a['filepath']),
            'filesize': a['filesize'],
            'uploaded_at': a['uploaded_at'],
        } for a in attachments
    ]
    cur.close()
    conn.close()
    return jsonify(ticket)

@app.route('/api/tickets', methods=['POST'])
def api_create_ticket():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    def after_insert_notify(conn, ticket_id):
        cur = conn.cursor(cursor_factory=DictCursor)
        # Build ticket dict for notifications
        cur.execute('SELECT id, user_id, type, priority, subject, description, status FROM tickets WHERE id = %s', (ticket_id,))
        t = cur.fetchone()
        if t:
            log_event(t['user_id'], f"Novo ticket criado: {t['subject']}", ticket_id)
            notify_user_ticket_update(t['user_id'], t, 'created')
            cur.execute("SELECT id FROM users WHERE is_admin = TRUE OR role IN ('admin', 'manager')")
            admins = cur.fetchall()
            for admin in admins:
                log_event(admin['id'], f"Novo ticket #{ticket_id} criado por {session['user_name']}", ticket_id)
                push_event(admin['id'], {'type': 'ticket_update', 'event': 'created', 'ticket': t})
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
        cur.execute('''INSERT INTO tickets (user_id, type, priority, subject, description, status, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id''',
                    (session['user_id'], type_, priority, subject, description, 'Aberto'))
        ticket_id = cur.fetchone()[0]
        files = request.files.getlist('attachments')
        for f in files:
            if f and allowed_file(f.filename):
                # Enforce per-file size limit (10MB)
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                if size > MAX_FILE_SIZE:
                    conn.rollback()
                    cur.close()
                    conn.close()
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
                conn.rollback()
                cur.close()
                conn.close()
                return jsonify({'error': f'Extensão não permitida: {f.filename}'}), 400
        after_insert_notify(conn, ticket_id)
        cur.close()
        conn.close()
        return jsonify({'success': True, 'ticket_id': ticket_id})
    # JSON fallback (without attachments)
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''INSERT INTO tickets (user_id, type, priority, subject, description, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id''',
                (session['user_id'], data['type'], data['priority'], 
                 data.get('subject', ''), data['description'], 'Aberto'))
    ticket_id = cur.fetchone()[0]
    after_insert_notify(conn, ticket_id)
    cur.close()
    conn.close()
    
    return jsonify({'success': True, 'ticket_id': ticket_id})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Serve uploaded files
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)

# Admin API routes
@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    cur.execute('SELECT COUNT(*) as count FROM tickets')
    total = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM tickets WHERE status IN ('Aberto', 'Em Andamento', 'Pendente')")
    open_tickets = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM tickets WHERE status IN ('Resolvido', 'Fechado')")
    resolved = cur.fetchone()['count']
    
    cur.close()
    conn.close()
    
    return jsonify({
        'total': total,
        'open': open_tickets,
        'resolved': resolved
    })

@app.route('/api/admin/tickets/recent', methods=['GET'])
def api_admin_tickets_recent():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''
        SELECT t.*, u.name as user_name, a.name as assigned_to_name 
        FROM tickets t 
        LEFT JOIN users u ON t.user_id = u.id 
        LEFT JOIN users a ON t.assigned_to = a.id
        ORDER BY t.created_at DESC 
        LIMIT 10
    ''')
    tickets = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(tickets)

@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''SELECT id, name, email, phone, role, created_at 
                            FROM users ORDER BY created_at DESC''')
    users = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(users)

@app.route('/api/admin/users', methods=['POST'])
def api_admin_create_user():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Processar role do frontend
        role = data.get('role', 'user')
        if role not in ['user', 'manager', 'admin']:
            role = 'user'
        
        # Manter compatibilidade com is_admin para o banco
        is_admin_value = role in ['admin', 'manager']
        
        cur.execute('''INSERT INTO users (name, email, password, phone, role, is_admin)
                        VALUES (%s, %s, %s, %s, %s, %s)''',
                     (data['name'], data['email'], hash_password(data['password']), 
                      data.get('phone', ''), role, is_admin_value))
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except psycopg2.IntegrityError:
        cur.close()
        conn.close()
        return jsonify({'error': 'Email já existe'}), 400

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def api_admin_update_user(user_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor()
    # If password provided, update hashed; otherwise, keep existing
    # Processar role do frontend
    role = data.get('role', 'user')
    if role not in ['user', 'manager', 'admin']:
        role = 'user'
    
    # Manter compatibilidade com is_admin para o banco
    is_admin_value = role in ['admin', 'manager']
    
    if 'password' in data and data['password']:
        cur.execute('''UPDATE users SET name = %s, email = %s, phone = %s, role = %s, is_admin = %s, password = %s
                        WHERE id = %s''',
                     (data['name'], data['email'], data.get('phone', ''), 
                      role, is_admin_value, hash_password(data['password']), user_id))
    else:
        cur.execute('''UPDATE users SET name = %s, email = %s, phone = %s, role = %s, is_admin = %s
                        WHERE id = %s''',
                     (data['name'], data['email'], data.get('phone', ''), 
                      role, is_admin_value, user_id))
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def api_admin_delete_user(user_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

# User Settings (Profile/Security/Notifications)
@app.route('/api/user/settings', methods=['GET'])
def api_user_get_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''SELECT id, name, email, phone, role,
                                  COALESCE(email_updates, TRUE) AS email_updates,
                                  COALESCE(sms_urgent, FALSE) AS sms_urgent,
                                  COALESCE(push_realtime, TRUE) AS push_realtime
                           FROM users WHERE id = %s''', (session['user_id'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(user)

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
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('UPDATE users SET name = %s, email = %s, phone = %s WHERE id = %s', (name, email, phone, session['user_id']))
    except psycopg2.IntegrityError:
        cur.close()
        conn.close()
        return jsonify({'error': 'Email já existe'}), 400
    cur.close()
    conn.close()
    return jsonify({'success': True})

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
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT password FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()
    if not user or user['password'] != hash_password(current):
        cur.close()
        conn.close()
        return jsonify({'error': 'Senha atual inválida'}), 400
    cur.execute('UPDATE users SET password = %s WHERE id = %s', (hash_password(new), session['user_id']))
    cur.close()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/user/settings/notifications', methods=['PUT'])
def api_user_update_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    email_updates = bool(data.get('email_updates'))
    sms_urgent = bool(data.get('sms_urgent'))
    push_realtime = bool(data.get('push_realtime'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE users SET email_updates = %s, sms_urgent = %s, push_realtime = %s WHERE id = %s',
                 (email_updates, sms_urgent, push_realtime, session['user_id']))
    cur.close()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/tickets/<int:ticket_id>/status', methods=['PUT'])
def api_admin_update_ticket_status(ticket_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    status = data.get('status')
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    # Verificar se o ticket existe e obter informações de atribuição
    cur.execute('SELECT * FROM tickets WHERE id = %s', (ticket_id,))
    ticket = cur.fetchone()
    if not ticket:
        cur.close()
        conn.close()
        return jsonify({'error': 'Ticket não encontrado'}), 404
    
    # Se o status for de finalização (Resolvido, Fechado, Rejeitado) e houver um responsável atribuído
    if status in ['Resolvido', 'Fechado', 'Rejeitado'] and ticket['assigned_to']:
        # Apenas o responsável atribuído pode finalizar o chamado
        if session['user_id'] != ticket['assigned_to']:
            cur.close()
            conn.close()
            return jsonify({'error': 'Somente o administrador responsável por este chamado pode finalizá-lo'}), 403
    
    cur.execute('UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s',
                 (status, ticket_id))
    
    if status in ['Resolvido', 'Fechado', 'Rejeitado']:
        cur.execute('UPDATE tickets SET closed_at = NOW(), closed_by = %s WHERE id = %s', (session['user_id'], ticket_id))
    
    # Notify user about status change
    cur.execute('SELECT id, user_id, type, priority, subject, description, status FROM tickets WHERE id = %s', (ticket_id,))
    t = cur.fetchone()
    if t:
        # Determine event type based on status
        event_type = 'status_changed'
        if status in ['Resolvido', 'Fechado']:
            event_type = 'closed'
            log_event(t['user_id'], f"Seu ticket #{ticket_id} foi concluído.", ticket_id)
        elif status == 'Cancelado':
            event_type = 'cancelled'
            log_event(t['user_id'], f"Seu ticket #{ticket_id} foi cancelado.", ticket_id)
        else:
            log_event(t['user_id'], f"O status do seu ticket #{ticket_id} foi alterado para {status}.", ticket_id)
        
        notify_user_ticket_update(t['user_id'], t, event_type)
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/tickets/<int:ticket_id>/responses', methods=['GET'])
def api_get_ticket_responses(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT user_id FROM tickets WHERE id = %s', (ticket_id,))
    ticket = cur.fetchone()
    if not ticket:
        cur.close()
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

# Only allow: ticket owner OR any staff (admin/manager) to view responses
    if not ((session.get('is_admin') or session.get('user_role') in ['admin', 'manager']) or ticket['user_id'] == session['user_id']):
        cur.close()
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403

    cur.execute('''
        SELECT tr.id, tr.message, tr.created_at, u.name as user_name, 
               u.role as user_role
        FROM ticket_responses tr
        JOIN users u ON tr.user_id = u.id
        WHERE tr.ticket_id = %s
        ORDER BY tr.created_at ASC
    ''', (ticket_id,))
    responses = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(responses)

@app.route('/api/tickets/<int:ticket_id>/responses', methods=['POST'])
def api_create_ticket_response(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    # Buscar ticket com nome do usuário
    cur.execute('''
        SELECT t.*, u.name as user_name
        FROM tickets t
        LEFT JOIN users u ON t.user_id = u.id
        WHERE t.id = %s
    ''', (ticket_id,))
    ticket = cur.fetchone()
    if not ticket:
        cur.close()
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

    # Buscar nome do administrador atribuído (se houver)
    assigned_user = None
    if ticket['assigned_to']:
        cur.execute('SELECT name FROM users WHERE id = %s', (ticket['assigned_to'],))
        assigned_user = cur.fetchone()

# Only allow: ticket owner OR assigned admin/manager (if assigned), otherwise forbid
    is_owner = (ticket['user_id'] == session['user_id'])
    is_staff = (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'])
    assigned_to = ticket['assigned_to']
    if is_staff and assigned_to:
        # Staff can only respond if they are assigned to this ticket
        if session['user_id'] != assigned_to:
            cur.close()
            conn.close()
            return jsonify({'error': 'Somente o administrador designado pode responder a este ticket'}), 403
    elif not (is_owner or is_staff):
        cur.close()
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403

    cur.execute('''
        INSERT INTO ticket_responses (ticket_id, user_id, message)
        VALUES (%s, %s, %s) RETURNING id
    ''', (ticket_id, session['user_id'], message))
    response_id = cur.fetchone()[0]

    # Notify the other party (user if admin/manager responded, admin/manager if user responded)
    if session.get('is_admin') or session.get('user_role') in ['admin', 'manager']:
        log_event(ticket['user_id'], f"O suporte respondeu ao seu ticket #{ticket_id}.", ticket_id)
        notify_user_ticket_update(ticket['user_id'], ticket, 'response_admin')
        
        # Send Telegram notification for admin response
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
    else:
        # Notify all admins and managers
        cur.execute("SELECT id FROM users WHERE is_admin = TRUE OR role IN ('admin', 'manager')")
        staff_users = cur.fetchall()
        for staff in staff_users:
            log_event(staff['id'], f"Nova resposta do usuário no ticket #{ticket_id}", ticket_id)
            push_event(staff['id'], {'type': 'ticket_update', 'event': 'response_user', 'ticket': ticket})
        
        # Send Telegram notification for user response
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

    cur.close()
    conn.close()
    return jsonify({'success': True, 'response_id': response_id})

# Admin General Settings API
@app.route('/api/admin/settings', methods=['GET'])
def api_admin_get_settings():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT key, value FROM settings')
    rows = cur.fetchall()
    cur.close()
    conn.close()
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
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    allowed_keys = {'company_name', 'support_email', 'support_phone', 'telegram_bot_token', 'telegram_group_id', 'telegram_topic_new_tickets', 'telegram_topic_messages', 'telegram_topic_assignments', 'telegram_topic_closed', 'telegram_topic_cancelled'}
    conn = get_db_connection()
    cur = conn.cursor()
    for k in allowed_keys:
        if k in data:
            cur.execute('INSERT INTO settings(key, value) VALUES(%s, %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value', (k, str(data[k])))
    cur.close()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/telegram/test', methods=['POST'])
def api_test_telegram():
    """Testa a conexão com o bot do Telegram"""
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json() or {}
    bot_token = data.get('bot_token', '').strip()
    group_id = data.get('group_id', '').strip()
    
    if not bot_token or not group_id:
        return jsonify({'error': 'Token do bot e ID do grupo são obrigatórios'}), 400
    
    try:
        import requests
        
        # Test bot token
        bot_url = f"https://api.telegram.org/bot{bot_token}/getMe"
        bot_response = requests.get(bot_url, timeout=10)
        
        if bot_response.status_code != 200:
            return jsonify({
                'success': False, 
                'error': 'Token do bot inválido ou bot não encontrado'
            }), 400
        
        bot_info = bot_response.json()
        if not bot_info.get('ok'):
            return jsonify({
                'success': False, 
                'error': 'Token do bot inválido'
            }), 400
        
        bot_name = bot_info.get('result', {}).get('username', 'Bot')
        
        # Test sending message to group
        test_message = f"\U0001F916 <b>Teste de Conexão</b>\n\nBot <b>@{bot_name}</b> conectado com sucesso!\nSistema HelpDesk configurado."
        
        message_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        message_data = {
            'chat_id': group_id,
            'text': test_message,
            'parse_mode': 'HTML'
        }
        
        message_response = requests.post(message_url, data=message_data, timeout=10)
        
        if message_response.status_code != 200:
            return jsonify({
                'success': False, 
                'error': 'Não foi possível enviar mensagem para o grupo. Verifique o ID do grupo e se o bot foi adicionado ao grupo.'
            }), 400
        
        message_result = message_response.json()
        if not message_result.get('ok'):
            error_description = message_result.get('description', 'Erro desconhecido')
            return jsonify({
                'success': False, 
                'error': f'Erro ao enviar mensagem: {error_description}'
            }), 400
        
        return jsonify({
            'success': True, 
            'message': f'Conexão testada com sucesso! Bot @{bot_name} pode enviar mensagens para o grupo.'
        })
        
    except requests.RequestException as e:
        return jsonify({
            'success': False, 
            'error': f'Erro de conexão: {str(e)}'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': f'Erro interno: {str(e)}'
        }), 500

@app.route('/api/admin/administrators', methods=['GET'])
def api_get_administrators():
    """API endpoint to get list of administrators for ticket assignment"""
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('''
        SELECT id, name, email
        FROM users 
        WHERE role IN ('admin', 'manager') 
        ORDER BY name
    ''')
    administrators = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(administrators)

@app.route('/api/admin/tickets/<int:ticket_id>/assign', methods=['PUT'])
def api_admin_assign_ticket(ticket_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    assigned_to = data.get('assigned_to')
    
    if not assigned_to:
        return jsonify({'error': 'ID do administrador é obrigatório'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        # Verificar se o ticket existe e buscar nome do usuário
        cur.execute('''
            SELECT t.*, u.name as user_name
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        ''', (ticket_id,))
        ticket = cur.fetchone()
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado'}), 404
        
        # Verificar se o usuário a ser atribuído é admin ou manager
        cur.execute("SELECT * FROM users WHERE id = %s AND (role = 'admin' OR role = 'manager')", (assigned_to,))
        assigned_user = cur.fetchone()
        if not assigned_user:
            return jsonify({'error': 'Usuário não é um administrador ou gerente'}), 400
        
        # Atribuir o ticket
        cur.execute('UPDATE tickets SET assigned_to = %s, updated_at = NOW() WHERE id = %s',
                     (assigned_to, ticket_id))
        
        # Notificar o usuário sobre a atribuição
        log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi atribuído ao administrador {assigned_user['name']}.", ticket_id)
        
        # Notificar o administrador atribuído
        log_event(assigned_to, f"Você foi designado para o ticket #{ticket_id}.", ticket_id)
        
        # Send special assignment notification to Telegram
        try:
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            ticket_subject = ticket['subject'] if ticket['subject'] else (ticket['description'][:50] if ticket['description'] else 'N/A')
            
            assignment_message = f"\U0001F464 <b>Chamado Atribuído</b>\n\n"
            assignment_message += f"<b>ID:</b> #{ticket_id}\n"
            assignment_message += f"<b>Responsável:</b> {assigned_user['name']}\n"
            assignment_message += f"<b>Tipo:</b> {ticket_type}\n"
            assignment_message += f"<b>Prioridade:</b> {ticket_priority}\n"
            assignment_message += f"<b>Assunto:</b> {ticket_subject}\n"
            assignment_message += f"<b>Usuário:</b> {user_name}"
            
            send_telegram_notification(assignment_message, 'assigned')
        except Exception as e:
            print(f"Erro ao enviar notificação de atribuição: {str(e)}")
        
        # Push notifications
        notify_user_ticket_update(ticket['user_id'], ticket, 'assigned')
        push_event(assigned_to, {
            'type': 'ticket_update',
            'event': 'assigned_to_you',
            'ticket': {
                'id': ticket['id'],
                'subject': ticket['subject'],
                'priority': ticket['priority']
            }
        })
        
        return jsonify({'success': True, 'assigned_to': assigned_user['name']})
    except Exception as e:
        print(f"Error assigning ticket: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/admin/tickets/<int:ticket_id>/cancel', methods=['PUT'])
def api_admin_cancel_ticket(ticket_id):
    """Cancela um ticket (apenas gerentes)"""
    if 'user_id' not in session or session.get('user_role') != 'manager':
        return jsonify({'error': 'Apenas gerentes podem cancelar tickets'}), 403
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        # Buscar ticket com nome do usuário
        cur.execute('''
            SELECT t.*, u.name as user_name
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        ''', (ticket_id,))
        ticket = cur.fetchone()
        
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado'}), 404
        
        # Verificar se o ticket não está já cancelado
        if ticket['status'] == 'Cancelado':
            return jsonify({'error': 'Ticket já está cancelado'}), 400
        
        # Cancelar ticket
        cur.execute("UPDATE tickets SET status = 'Cancelado', updated_at = NOW() WHERE id = %s", (ticket_id,))
        
        # Log e notificações
        manager_name = session.get('user_name', 'Gerente')
        log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi cancelado pelo gerente {manager_name}.", ticket_id)
        
        # Notificar usuário
        notify_user_ticket_update(ticket['user_id'], ticket, 'cancelled')
        
        # Enviar notificação Telegram
        try:
            user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
            ticket_type = ticket['type'] if ticket['type'] else 'N/A'
            ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
            ticket_subject = ticket['subject'] if ticket['subject'] else (ticket['description'][:50] if ticket['description'] else 'N/A')
            
            cancel_message = f"\U0000274C <b>Chamado Cancelado</b>\n\n"
            cancel_message += f"<b>ID:</b> #{ticket_id}\n"
            cancel_message += f"<b>Cancelado por:</b> {manager_name}\n"
            cancel_message += f"<b>Usuário:</b> {user_name}\n"
            cancel_message += f"<b>Tipo:</b> {ticket_type}\n"
            cancel_message += f"<b>Prioridade:</b> {ticket_priority}\n"
            cancel_message += f"<b>Assunto:</b> {ticket_subject}"
            
            send_telegram_notification(cancel_message, 'cancelled')
        except Exception as e:
            print(f"Erro ao enviar notificação de cancelamento: {str(e)}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Erro ao cancelar ticket: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/admin/tickets/<int:ticket_id>/reopen', methods=['PUT'])
def api_admin_reopen_ticket(ticket_id):
    """Reabre um ticket fechado ou cancelado (apenas gerentes para tickets cancelados)"""
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        # Buscar ticket com nome do usuário
        cur.execute('''
            SELECT t.*, u.name as user_name
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        ''', (ticket_id,))
        ticket = cur.fetchone()
        
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado'}), 404
        
        # Se o ticket foi cancelado, apenas gerentes podem reabrir
        if ticket['status'] == 'Cancelado' and session.get('user_role') != 'manager':
            return jsonify({'error': 'Apenas gerentes podem reabrir tickets cancelados'}), 403
        # Atualiza status para Aberto, limpa fechamento e quem fechou
        cur.execute("UPDATE tickets SET status = 'Aberto', updated_at = NOW(), closed_at = NULL, closed_by = NULL WHERE id = %s", (ticket_id,))
        # Notificações
        user_id = ticket['user_id']
        assigned_to = ticket['assigned_to']
        closed_by = ticket['closed_by'] if 'closed_by' in ticket else None
        # Notificar usuário dono
        log_event(user_id, f"Seu ticket #{ticket_id} foi reaberto.", ticket_id)
        notify_user_ticket_update(user_id, ticket, 'reopened')
        # Notificar responsável (se houver)
        if assigned_to:
            log_event(assigned_to, f"Ticket #{ticket_id} foi reaberto.", ticket_id)
            push_event(assigned_to, {'type': 'ticket_update', 'event': 'reopened', 'ticket': {'id': ticket['id'], 'subject': ticket['subject'], 'priority': ticket['priority']}})
        # Notificar quem fechou (se conhecido)
        if closed_by:
            log_event(closed_by, f"Ticket #{ticket_id} que você havia fechado foi reaberto.", ticket_id)
            push_event(closed_by, {'type': 'ticket_update', 'event': 'reopened', 'ticket': {'id': ticket['id'], 'subject': ticket['subject'], 'priority': ticket['priority']}})
        # Notificar todos os gerentes
        cur.execute("SELECT id FROM users WHERE role = 'manager'")
        managers = cur.fetchall()
        for m in managers:
            log_event(m['id'], f"Ticket #{ticket_id} foi reaberto.", ticket_id)
            push_event(m['id'], {'type': 'ticket_update', 'event': 'reopened', 'ticket': {'id': ticket['id'], 'subject': ticket['subject'], 'priority': ticket['priority']}})
        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro ao reabrir ticket: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        cur.close()
        conn.close()

# Adicione estas rotas no app.py

@app.route('/api/ticket-types', methods=['GET'])
def api_get_ticket_types():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT * FROM ticket_types WHERE active = TRUE ORDER BY name')
    ticket_types = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(ticket_types)

@app.route('/api/ticket-types', methods=['POST'])
def api_create_ticket_type():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''INSERT INTO ticket_types (name, description, active)
                        VALUES (%s, %s, TRUE)''',
                     (data['name'], data.get('description', '')))
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except psycopg2.IntegrityError:
        cur.close()
        conn.close()
        return jsonify({'error': 'Tipo de chamado já existe'}), 400

@app.route('/api/ticket-types/<int:type_id>', methods=['PUT'])
def api_update_ticket_type(type_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''UPDATE ticket_types SET name = %s, description = %s, active = %s
                    WHERE id = %s''',
                 (data['name'], data.get('description', ''), data.get('active', True), type_id))
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/ticket-types/<int:type_id>', methods=['DELETE'])
def api_delete_ticket_type(type_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor()
    # Instead of deleting, we mark as inactive
    cur.execute('UPDATE ticket_types SET active = FALSE WHERE id = %s', (type_id,))
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/ticket-statuses', methods=['GET'])
def api_get_ticket_statuses():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute('SELECT * FROM ticket_statuses WHERE active = TRUE ORDER BY name')
    ticket_statuses = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(ticket_statuses)

@app.route('/api/ticket-statuses', methods=['POST'])
def api_create_ticket_status():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''INSERT INTO ticket_statuses (name, color, active)
                        VALUES (%s, %s, TRUE)''',
                     (data['name'], data.get('color', '#808080'),))
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except psycopg2.IntegrityError:
        cur.close()
        conn.close()
        return jsonify({'error': 'Status de chamado já existe'}), 400

@app.route('/api/ticket-statuses/<int:status_id>', methods=['PUT'])
def api_update_ticket_status(status_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''UPDATE ticket_statuses SET name = %s, color = %s, active = %s
                    WHERE id = %s''',
                 (data['name'], data.get('color', '#808080'), data.get('active', True), status_id))
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/ticket-statuses/<int:status_id>', methods=['DELETE'])
def api_delete_ticket_status(status_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor()
    # Instead of deleting, we mark as inactive
    cur.execute('UPDATE ticket_statuses SET active = FALSE WHERE id = %s', (status_id,))
    cur.close()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/debug')
def debug_frontend():
    """Página de debug para testar o frontend"""
    return send_from_directory('.', 'debug_frontend.html')

# Inicialização da aplicação
if __name__ == '__main__':
    # Inicializa o banco de dados
    init_database()
    # Iniciar a aplicação
    app.run(host='0.0.0.0', port=5000, debug=True)
