from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify, send_from_directory, Response, stream_with_context
import sqlite3
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
        conn = sqlite3.connect('helpdesk.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados: {str(e)}")
        raise

def log_event(user_id, message, ticket_id=None):
    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO logs (user_id, ticket_id, message) VALUES (?, ?, ?)", (user_id, ticket_id, message))
        conn.commit()
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

# Funções de verificação e inicialização
def check_database():
    if not os.path.exists('helpdesk.db'):
        print("Banco de dados não encontrado. Inicializando...")
        init_database()
        print("Banco de dados inicializado com sucesso!")

def check_tables():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar se as tabelas existem
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = ['users', 'tickets', 'ticket_types', 'ticket_statuses', 'ticket_responses', 'attachments', 'logs']
        
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            print(f"Tabelas faltando: {missing_tables}. Recriando banco de dados...")
            conn.close()
            init_database()
        else:
            conn.close()
            print("Todas as tabelas necessárias existem.")
    except Exception as e:
        print(f"Erro ao verificar tabelas: {str(e)}")
        # Tentar inicializar o banco de dados em caso de erro
        init_database()

def ensure_schema_and_password_hash():
    """Ensure required columns/tables exist and migrate plaintext passwords to sha256 hash."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Ensure columns for notification preferences and role
        cur.execute('PRAGMA table_info(users)')
        cols = {row['name'] for row in cur.fetchall()}
        if 'email_updates' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN email_updates INTEGER DEFAULT 1")
        if 'sms_urgent' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN sms_urgent INTEGER DEFAULT 0")
        if 'push_realtime' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN push_realtime INTEGER DEFAULT 1")
        if 'role' not in cols:
            # Add role column and populate based on existing is_admin values
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            cur.execute("UPDATE users SET role = 'admin' WHERE is_admin = 1")
            cur.execute("UPDATE users SET role = 'user' WHERE is_admin = 0")
        # Ensure settings table for admin general settings
        cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        # Seed defaults if missing
        defaults = [
            ('company_name', 'LogVerse'),
            ('support_email', 'suporte@logverse.com'),
            ('support_phone', '(11) 1234-5678')
        ]
        for k, v in defaults:
            cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))
        # Ensure tickets has closed_by column
        cur.execute('PRAGMA table_info(tickets)')
        tcols = {row['name'] for row in cur.fetchall()}
        if 'closed_by' not in tcols:
            cur.execute("ALTER TABLE tickets ADD COLUMN closed_by INTEGER")
        # Migrate plaintext passwords to hashed (sha256 hex)
        cur.execute('SELECT id, password FROM users')
        rows = cur.fetchall()
        for row in rows:
            pwd = row['password'] or ''
            is_hex64 = isinstance(pwd, str) and len(pwd) == 64 and all(c in '0123456789abcdef' for c in pwd.lower())
            if not is_hex64:
                hashed = hash_password(pwd)
                cur.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, row['id']))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao garantir schema: {str(e)}")

# Helper to notify user on ticket events
def notify_user_ticket_update(user_id: int, ticket: dict, event_type: str):
    """Send email/SMS/push based on user preferences for ticket updates."""
    try:
        conn = get_db_connection()
        user = conn.execute('SELECT email, phone, email_updates, sms_urgent, push_realtime FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if not user:
            return
            
        subject = f"Atualização do chamado #{ticket.get('id', '')}"
        body = f"Seu chamado foi atualizado. Tipo: {ticket.get('type')} | Prioridade: {ticket.get('priority')} | Evento: {event_type}."
        
        # Email
        if (user['email_updates'] or 0) == 1 and user['email']:
            try:
                send_email(user['email'], subject, body)
            except Exception as e:
                print(f"Erro ao enviar email: {str(e)}")
                
        # SMS (only if urgent)
        if (user['sms_urgent'] or 0) == 1 and (ticket.get('priority') == 'Urgente') and user['phone']:
            try:
                send_sms(user['phone'], f"[URGENTE] {body}")
            except Exception as e:
                print(f"Erro ao enviar SMS: {str(e)}")
                
        # Push via SSE
        if (user['push_realtime'] or 0) == 1:
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
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and user['password'] == hash_password(password):
            # Determinar privilégios com base nas colunas disponíveis
            user_keys = set(user.keys())
            is_admin = False
            role = 'user'
            if 'is_admin' in user_keys:
                is_admin = bool(user['is_admin'])
                role = 'admin' if is_admin else 'user'
            elif 'role' in user_keys:
                role = (user['role'] or 'user')
                is_admin = role in ['admin', 'manager']

            # Definir sessão
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = user['name'] if user['name'] else 'Usuário'
            session['user_role'] = role
            session['is_admin'] = is_admin

            redirect_to = 'admin_dashboard' if role in ['admin', 'manager'] else 'user_dashboard'
            if remember:
                session.permanent = True
                resp = make_response(redirect(url_for(redirect_to)))
                resp.set_cookie('remember_me', 'true', max_age=app.permanent_session_lifetime.total_seconds())
                return resp
            return redirect(url_for(redirect_to))
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
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            # Update password in database (store hashed)
            conn.execute('UPDATE users SET password = ? WHERE email = ?', (hash_password(new_password), email))
            conn.commit()
            flash('Senha alterada com sucesso', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email não encontrado', 'error')
        conn.close()
        return redirect(url_for('recover'))
    return render_template('recover.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('is_admin', None)
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('remember_me', '', expires=0)
    return resp

# API routes for AJAX requests
@app.route('/api/logs', methods=['GET'])
def get_logs():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM logs WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(log) for log in logs])

@app.route('/api/logs/<int:log_id>/read', methods=['PUT'])
def mark_log_as_read(log_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    conn.execute("UPDATE logs SET is_read = 1 WHERE id = ? AND user_id = ?", (log_id, session['user_id']))
    conn.commit()
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
    cur = conn.cursor()
    if request.method == 'GET':
        row = cur.execute('SELECT value FROM settings WHERE key = ?', ('help_center',)).fetchone()
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
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403
    try:
        payload = request.get_json(force=True)
    except Exception:
        conn.close()
        return jsonify({'error': 'Invalid JSON'}), 400
    # Basic validation
    if not isinstance(payload, dict):
        conn.close()
        return jsonify({'error': 'Invalid payload'}), 400
    try:
        cur.execute('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
                    ('help_center', json.dumps(payload, ensure_ascii=False)))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'success': True})

@app.route('/api/tickets', methods=['GET'])
def api_get_tickets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    try:
        if session.get('is_admin') or session.get('user_role') in ['admin', 'manager']:
            tickets = conn.execute('''
                SELECT t.*, u.name as user_name, a.name as assigned_to_name 
                FROM tickets t 
                LEFT JOIN users u ON t.user_id = u.id 
                LEFT JOIN users a ON t.assigned_to = a.id
                ORDER BY t.created_at DESC
            ''').fetchall()
        else:
            tickets = conn.execute('SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at DESC', 
                                  (session['user_id'],)).fetchall()
        
        # Converter para lista de dicionários
        tickets_list = [dict(ticket) for ticket in tickets]
        
        # Log para depuração
        print(f"Retornando {len(tickets_list)} tickets para usuário {session.get('user_id')}")
        
        return jsonify(tickets_list)
    except Exception as e:
        print(f"Erro ao carregar tickets: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        conn.close()

@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
def api_get_ticket(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    ticket = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    # Authorization: admin or ticket owner
    is_owner = (ticket['user_id'] == session['user_id'])
    if not ((session.get('is_admin') or session.get('user_role') in ['admin', 'manager']) or is_owner):
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403
    attachments = conn.execute(
        'SELECT id, filename, filepath, filesize, uploaded_at FROM attachments WHERE ticket_id = ? ORDER BY uploaded_at DESC',
        (ticket_id,)
    ).fetchall()
    ticket_dict = dict(ticket)
    ticket_dict['attachments'] = [
        {
            'id': a['id'],
            'filename': a['filename'],
            'url': url_for('uploaded_file', filename=a['filepath']),
            'filesize': a['filesize'],
            'uploaded_at': a['uploaded_at'],
        } for a in attachments
    ]
    conn.close()
    return jsonify(ticket_dict)

@app.route('/api/tickets', methods=['POST'])
def api_create_ticket():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    def after_insert_notify(conn, ticket_id):
        # Build ticket dict for notifications
        t = conn.execute('SELECT id, user_id, type, priority, subject, description, status FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
        if t:
            log_event(t['user_id'], f"Novo ticket criado: {t['subject']}", ticket_id)
            notify_user_ticket_update(t['user_id'], dict(t), 'created')
            admins = conn.execute("SELECT id FROM users WHERE is_admin = 1").fetchall()
            for admin in admins:
                log_event(admin['id'], f"Novo ticket #{ticket_id} criado por {session['user_name']}", ticket_id)
                push_event(admin['id'], {'type': 'ticket_update', 'event': 'created', 'ticket': dict(t)})
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
                        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))''',
                    (session['user_id'], type_, priority, subject, description, 'Aberto'))
        ticket_id = cur.lastrowid
        files = request.files.getlist('attachments')
        for f in files:
            if f and allowed_file(f.filename):
                # Enforce per-file size limit (10MB)
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                if size > MAX_FILE_SIZE:
                    conn.rollback()
                    conn.close()
                    return jsonify({'error': f'Arquivo muito grande: {f.filename}. Limite 10MB por arquivo.'}), 400
                original = secure_filename(f.filename)
                unique_name = f"{ticket_id}_{secrets.token_hex(4)}_{original}"
                save_path = os.path.join(UPLOAD_FOLDER, unique_name)
                f.save(save_path)
                filesize = os.path.getsize(save_path)
                cur.execute('''INSERT INTO attachments (ticket_id, filename, filepath, filesize)
                               VALUES (?, ?, ?, ?)''',
                            (ticket_id, original, unique_name, filesize))
            elif f:
                conn.rollback()
                conn.close()
                return jsonify({'error': f'Extensão não permitida: {f.filename}'}), 400
        conn.commit()
        after_insert_notify(conn, ticket_id)
        conn.close()
        return jsonify({'success': True, 'ticket_id': ticket_id})
    # JSON fallback (without attachments)
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''INSERT INTO tickets (user_id, type, priority, subject, description, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))''',
                (session['user_id'], data['type'], data['priority'], 
                 data.get('subject', ''), data['description'], 'Aberto'))
    ticket_id = cur.lastrowid
    conn.commit()
    after_insert_notify(conn, ticket_id)
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
    
    total = conn.execute('SELECT COUNT(*) as count FROM tickets').fetchone()['count']
    open_tickets = conn.execute("SELECT COUNT(*) as count FROM tickets WHERE status IN ('Aberto', 'Em Andamento', 'Pendente')").fetchone()['count']
    resolved = conn.execute("SELECT COUNT(*) as count FROM tickets WHERE status IN ('Resolvido', 'Fechado')").fetchone()['count']
    
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
    tickets = conn.execute('''
        SELECT t.*, u.name as user_name, a.name as assigned_to_name 
        FROM tickets t 
        LEFT JOIN users u ON t.user_id = u.id 
        LEFT JOIN users a ON t.assigned_to = a.id
        ORDER BY t.created_at DESC 
        LIMIT 10
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(ticket) for ticket in tickets])

@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    users = conn.execute('''SELECT id, name, email, phone, 
                                   COALESCE(role, CASE WHEN is_admin = 1 THEN 'admin' ELSE 'user' END) as role, 
                                   created_at 
                            FROM users ORDER BY created_at DESC''').fetchall()
    conn.close()
    
    return jsonify([dict(user) for user in users])

@app.route('/api/admin/users', methods=['POST'])
def api_admin_create_user():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    try:
        # Processar role do frontend
        role = data.get('role', 'user')
        if role not in ['user', 'manager', 'admin']:
            role = 'user'
        
        # Manter compatibilidade com is_admin para o banco
        is_admin_value = 1 if role in ['admin', 'manager'] else 0
        
        conn.execute('''INSERT INTO users (name, email, password, phone, role, is_admin)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (data['name'], data['email'], hash_password(data['password']), 
                      data.get('phone', ''), role, is_admin_value))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Email já existe'}), 400

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def api_admin_update_user(user_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    # If password provided, update hashed; otherwise, keep existing
    # Processar role do frontend
    role = data.get('role', 'user')
    if role not in ['user', 'manager', 'admin']:
        role = 'user'
    
    # Manter compatibilidade com is_admin para o banco
    is_admin_value = 1 if role in ['admin', 'manager'] else 0
    
    if 'password' in data and data['password']:
        conn.execute('''UPDATE users SET name = ?, email = ?, phone = ?, role = ?, is_admin = ?, password = ?
                        WHERE id = ?''',
                     (data['name'], data['email'], data.get('phone', ''), 
                      role, is_admin_value, hash_password(data['password']), user_id))
    else:
        conn.execute('''UPDATE users SET name = ?, email = ?, phone = ?, role = ?, is_admin = ?
                        WHERE id = ?''',
                     (data['name'], data['email'], data.get('phone', ''), 
                      role, is_admin_value, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def api_admin_delete_user(user_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# User Settings (Profile/Security/Notifications)
@app.route('/api/user/settings', methods=['GET'])
def api_user_get_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    user = conn.execute('''SELECT id, name, email, phone, 
                                  COALESCE(email_updates,1) AS email_updates,
                                  COALESCE(sms_urgent,0) AS sms_urgent,
                                  COALESCE(push_realtime,1) AS push_realtime
                           FROM users WHERE id = ?''', (session['user_id'],)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(user))

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
    try:
        conn.execute('UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?', (name, email, phone, session['user_id']))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Email já existe'}), 400
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
    user = conn.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['password'] != hash_password(current):
        conn.close()
        return jsonify({'error': 'Senha atual inválida'}), 400
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hash_password(new), session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/user/settings/notifications', methods=['PUT'])
def api_user_update_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    email_updates = 1 if data.get('email_updates') else 0
    sms_urgent = 1 if data.get('sms_urgent') else 0
    push_realtime = 1 if data.get('push_realtime') else 0
    conn = get_db_connection()
    conn.execute('UPDATE users SET email_updates = ?, sms_urgent = ?, push_realtime = ? WHERE id = ?',
                 (email_updates, sms_urgent, push_realtime, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/tickets/<int:ticket_id>/status', methods=['PUT'])
def api_admin_update_ticket_status(ticket_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    status = data.get('status')
    
    conn = get_db_connection()
    
    # Verificar se o ticket existe e obter informações de atribuição
    ticket = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket não encontrado'}), 404
    
    # Se o status for de finalização (Resolvido, Fechado, Rejeitado) e houver um responsável atribuído
    if status in ['Resolvido', 'Fechado', 'Rejeitado'] and ticket['assigned_to']:
        # Apenas o responsável atribuído pode finalizar o chamado
        if session['user_id'] != ticket['assigned_to']:
            conn.close()
            return jsonify({'error': 'Somente o administrador responsável por este chamado pode finalizá-lo'}), 403
    
    conn.execute('UPDATE tickets SET status = ?, updated_at = datetime("now") WHERE id = ?',
                 (status, ticket_id))
    
    if status in ['Resolvido', 'Fechado', 'Rejeitado']:
        conn.execute('UPDATE tickets SET closed_at = datetime("now"), closed_by = ? WHERE id = ?', (session['user_id'], ticket_id))
    
    conn.commit()
    # Notify user about status change
    t = conn.execute('SELECT id, user_id, type, priority, subject, description, status FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if t:
        if status in ['Resolvido', 'Fechado', 'Rejeitado']:
            log_event(t['user_id'], f"Seu ticket #{ticket_id} foi concluído.", ticket_id)
        else:
            log_event(t['user_id'], f"O status do seu ticket #{ticket_id} foi alterado para {status}.", ticket_id)
        notify_user_ticket_update(t['user_id'], dict(t), 'status_changed')
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/tickets/<int:ticket_id>/responses', methods=['GET'])
def api_get_ticket_responses(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    ticket = conn.execute('SELECT user_id FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

# Only allow: ticket owner OR any staff (admin/manager) to view responses
    if not ((session.get('is_admin') or session.get('user_role') in ['admin', 'manager']) or ticket['user_id'] == session['user_id']):
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403

    responses = conn.execute('''
        SELECT tr.id, tr.message, tr.created_at, u.name as user_name, 
               CASE WHEN u.is_admin = 1 THEN 'admin' ELSE 'user' END as user_role
        FROM ticket_responses tr
        JOIN users u ON tr.user_id = u.id
        WHERE tr.ticket_id = ?
        ORDER BY tr.created_at ASC
    ''', (ticket_id,)).fetchall()
    conn.close()
    return jsonify([dict(response) for response in responses])

@app.route('/api/tickets/<int:ticket_id>/responses', methods=['POST'])
def api_create_ticket_response(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    conn = get_db_connection()
    ticket = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return jsonify({'error': 'Ticket not found'}), 404

# Only allow: ticket owner OR assigned admin/manager (if assigned), otherwise forbid
    is_owner = (ticket['user_id'] == session['user_id'])
    is_staff = (session.get('is_admin') or session.get('user_role') in ['admin', 'manager'])
    assigned_to = ticket.get('assigned_to') if isinstance(ticket, dict) else ticket['assigned_to']
    if is_staff and assigned_to:
        # Staff can only respond if they are assigned to this ticket
        if session['user_id'] != assigned_to:
            conn.close()
            return jsonify({'error': 'Somente o administrador designado pode responder a este ticket'}), 403
    elif not (is_owner or is_staff):
        conn.close()
        return jsonify({'error': 'Forbidden'}), 403

    cur = conn.cursor()
    cur.execute('''
        INSERT INTO ticket_responses (ticket_id, user_id, message)
        VALUES (?, ?, ?)
    ''', (ticket_id, session['user_id'], message))
    conn.commit()

    # Notify the other party (user if admin/manager responded, admin/manager if user responded)
    if session.get('is_admin') or session.get('user_role') in ['admin', 'manager']:
        log_event(ticket['user_id'], f"O suporte respondeu ao seu ticket #{ticket_id}.", ticket_id)
        notify_user_ticket_update(ticket['user_id'], dict(ticket), 'response_admin')
    else:
        # Notify all admins and managers
        staff_users = conn.execute("SELECT id FROM users WHERE is_admin = 1").fetchall()
        for staff in staff_users:
            log_event(staff['id'], f"Nova resposta do usuário no ticket #{ticket_id}", ticket_id)
            push_event(staff['id'], {'type': 'ticket_update', 'event': 'response_user', 'ticket': dict(ticket)})

    conn.close()
    return jsonify({'success': True, 'response_id': cur.lastrowid})

# Admin General Settings API
@app.route('/api/admin/settings', methods=['GET'])
def api_admin_get_settings():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    rows = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    data = {row['key']: row['value'] for row in rows}
    return jsonify({
        'company_name': data.get('company_name', ''),
        'support_email': data.get('support_email', ''),
        'support_phone': data.get('support_phone', '')
    })

@app.route('/api/admin/settings', methods=['PUT'])
def api_admin_update_settings():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    allowed_keys = {'company_name', 'support_email', 'support_phone'}
    conn = get_db_connection()
    cur = conn.cursor()
    for k in allowed_keys:
        if k in data:
            cur.execute('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, str(data[k])))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/administrators', methods=['GET'])
def api_get_administrators():
    """API endpoint to get list of administrators for ticket assignment"""
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    administrators = conn.execute('''
        SELECT id, name, email
        FROM users 
        WHERE role IN ('admin', 'manager') 
        ORDER BY name
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(admin) for admin in administrators])

@app.route('/api/admin/tickets/<int:ticket_id>/assign', methods=['PUT'])
def api_admin_assign_ticket(ticket_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    assigned_to = data.get('assigned_to')
    
    if not assigned_to:
        return jsonify({'error': 'ID do administrador é obrigatório'}), 400
    
    conn = get_db_connection()
    try:
        # Verificar se o ticket existe
        ticket = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado'}), 404
        
        # Verificar se o usuário a ser atribuído é admin ou manager
        assigned_user = conn.execute('SELECT * FROM users WHERE id = ? AND (role = "admin" OR role = "manager")', (assigned_to,)).fetchone()
        if not assigned_user:
            return jsonify({'error': 'Usuário não é um administrador ou gerente'}), 400
        
        # Atribuir o ticket
        conn.execute('UPDATE tickets SET assigned_to = ?, updated_at = datetime("now") WHERE id = ?',
                     (assigned_to, ticket_id))
        conn.commit()
        
        # Notificar o usuário sobre a atribuição
        log_event(ticket['user_id'], f"Seu ticket #{ticket_id} foi atribuído ao administrador {assigned_user['name']}.", ticket_id)
        
        # Notificar o administrador atribuído
        log_event(assigned_to, f"Você foi designado para o ticket #{ticket_id}.", ticket_id)
        
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
        
        return jsonify({'success': True, 'assigned_to': assigned_user['name']})
    except Exception as e:
        print(f"Error assigning ticket: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        conn.close()

@app.route('/api/admin/tickets/<int:ticket_id>/reopen', methods=['PUT'])
def api_admin_reopen_ticket(ticket_id):
    """Reabre um ticket fechado e notifica responsável, quem fechou, gerentes e o usuário dono."""
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    try:
        ticket = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({'error': 'Ticket não encontrado'}), 404
        # Atualiza status para Aberto, limpa fechamento e quem fechou
        conn.execute("UPDATE tickets SET status = 'Aberto', updated_at = datetime('now'), closed_at = NULL, closed_by = NULL WHERE id = ?", (ticket_id,))
        conn.commit()
        # Notificações
        user_id = ticket['user_id']
        assigned_to = ticket['assigned_to']
        closed_by = ticket['closed_by'] if 'closed_by' in ticket.keys() else None
        # Notificar usuário dono
        log_event(user_id, f"Seu ticket #{ticket_id} foi reaberto.", ticket_id)
        notify_user_ticket_update(user_id, dict(ticket), 'reopened')
        # Notificar responsável (se houver)
        if assigned_to:
            log_event(assigned_to, f"Ticket #{ticket_id} foi reaberto.", ticket_id)
            push_event(assigned_to, {'type': 'ticket_update', 'event': 'reopened', 'ticket': {'id': ticket['id'], 'subject': ticket['subject'], 'priority': ticket['priority']}})
        # Notificar quem fechou (se conhecido)
        if closed_by:
            log_event(closed_by, f"Ticket #{ticket_id} que você havia fechado foi reaberto.", ticket_id)
            push_event(closed_by, {'type': 'ticket_update', 'event': 'reopened', 'ticket': {'id': ticket['id'], 'subject': ticket['subject'], 'priority': ticket['priority']}})
        # Notificar todos os gerentes
        managers = conn.execute("SELECT id FROM users WHERE role = 'manager'").fetchall()
        for m in managers:
            log_event(m['id'], f"Ticket #{ticket_id} foi reaberto.", ticket_id)
            push_event(m['id'], {'type': 'ticket_update', 'event': 'reopened', 'ticket': {'id': ticket['id'], 'subject': ticket['subject'], 'priority': ticket['priority']}})
        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro ao reabrir ticket: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        conn.close()

# Adicione estas rotas no app.py

@app.route('/api/ticket-types', methods=['GET'])
def api_get_ticket_types():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    ticket_types = conn.execute('SELECT * FROM ticket_types WHERE active = 1 ORDER BY name').fetchall()
    conn.close()
    
    return jsonify([dict(ticket_type) for ticket_type in ticket_types])

@app.route('/api/ticket-types', methods=['POST'])
def api_create_ticket_type():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    try:
        conn.execute('''INSERT INTO ticket_types (name, description, active)
                        VALUES (?, ?, 1)''',
                     (data['name'], data.get('description', '')))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Tipo de chamado já existe'}), 400

@app.route('/api/ticket-types/<int:type_id>', methods=['PUT'])
def api_update_ticket_type(type_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    conn.execute('''UPDATE ticket_types SET name = ?, description = ?, active = ?
                    WHERE id = ?''',
                 (data['name'], data.get('description', ''), data.get('active', 1), type_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/ticket-types/<int:type_id>', methods=['DELETE'])
def api_delete_ticket_type(type_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    # Instead of deleting, we mark as inactive
    conn.execute('UPDATE ticket_types SET active = 0 WHERE id = ?', (type_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/ticket-statuses', methods=['GET'])
def api_get_ticket_statuses():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    ticket_statuses = conn.execute('SELECT * FROM ticket_statuses WHERE active = 1 ORDER BY name').fetchall()
    conn.close()
    
    return jsonify([dict(ticket_status) for ticket_status in ticket_statuses])

@app.route('/api/ticket-statuses', methods=['POST'])
def api_create_ticket_status():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    try:
        conn.execute('''INSERT INTO ticket_statuses (name, color, active)
                        VALUES (?, ?, 1)''',
                     (data['name'], data.get('color', '#808080'),))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Status de chamado já existe'}), 400

@app.route('/api/ticket-statuses/<int:status_id>', methods=['PUT'])
def api_update_ticket_status(status_id):
    if 'user_id' not in session or not (session.get('is_admin') or session.get('user_role') in ['admin', 'manager']):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    conn = get_db_connection()
    conn.execute('''UPDATE ticket_statuses SET name = ?, color = ?, active = ?
                    WHERE id = ?''',
                 (data['name'], data.get('color', '#808080'), data.get('active', 1), status_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/ticket-statuses/<int:status_id>', methods=['DELETE'])
def api_delete_ticket_status(status_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    # Instead of deleting, we mark as inactive
    conn.execute('UPDATE ticket_statuses SET active = 0 WHERE id = ?', (status_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Inicialização da aplicação
if __name__ == '__main__':
    # Verificar e inicializar o banco de dados
    check_database()
    check_tables()
    ensure_schema_and_password_hash()
    
    # Iniciar a aplicação
    app.run(host='0.0.0.0', port=5000, debug=True)
