from dotenv import load_dotenv
load_dotenv()

#Database.py
import psycopg2
import os
import hashlib
from psycopg2.extras import DictCursor

def get_db_connection():
    print(f"DATABASE_URL: {os.environ.get('DATABASE_URL')}")
    conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
    return conn

def init_database():
    conn = get_db_connection()
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id SERIAL PRIMARY KEY,
                  name TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  phone TEXT,
                  role TEXT NOT NULL DEFAULT 'user',
                  is_admin INTEGER DEFAULT 0,
                  email_updates INTEGER DEFAULT 1,
                  sms_urgent INTEGER DEFAULT 0,
                  push_realtime INTEGER DEFAULT 1,
                  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW())''')

    # Create ticket_types table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_types
                 (id SERIAL PRIMARY KEY,
                  name TEXT NOT NULL,
                  description TEXT,
                  active INTEGER DEFAULT 1)''')

    # Create ticket_statuses table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_statuses
                 (id SERIAL PRIMARY KEY,
                  name TEXT NOT NULL,
                  color TEXT DEFAULT '#gray',
                  active INTEGER DEFAULT 1)''')

    # Create tickets table
    c.execute('''CREATE TABLE IF NOT EXISTS tickets
                 (id SERIAL PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  type TEXT NOT NULL,
                  priority TEXT NOT NULL,
                  subject TEXT,
                  description TEXT NOT NULL,
                  status TEXT DEFAULT 'Aberto',
                  assigned_to INTEGER,
                  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                  closed_at TIMESTAMP,
                  closed_by INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (assigned_to) REFERENCES users (id))''')

    # Create ticket_responses table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_responses
                 (id SERIAL PRIMARY KEY,
                  ticket_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  message TEXT NOT NULL,
                  is_internal INTEGER DEFAULT 0,
                  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')

    # Create attachments table
    c.execute('''CREATE TABLE IF NOT EXISTS attachments
                 (id SERIAL PRIMARY KEY,
                  ticket_id INTEGER,
                  response_id INTEGER,
                  filename TEXT NOT NULL,
                  filepath TEXT NOT NULL,
                  filesize INTEGER,
                  uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                  FOREIGN KEY (response_id) REFERENCES ticket_responses (id))''')

    # Create logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id SERIAL PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  ticket_id INTEGER,
                  message TEXT NOT NULL,
                  is_read INTEGER DEFAULT 0,
                  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id))''')
                  
    # Create settings table
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")


    # Insert default ticket types
    ticket_types = [
        ('Suporte Técnico', 'Problemas técnicos e dúvidas sobre o sistema'),
        ('Hardware', 'Problemas com equipamentos e hardware'),
        ('Software', 'Problemas com software e aplicações'),
        ('Rede', 'Problemas de conectividade e rede'),
        ('Acesso', 'Problemas de login e permissões'),
        ('Faturamento', 'Questões relacionadas a cobrança e pagamentos'),
        ('Instalação', 'Solicitações de instalação de software/hardware'),
        ('Melhoria', 'Sugestões de melhorias no sistema'),
        ('Bug', 'Relatos de bugs e erros no sistema'),
        ('Outro', 'Outros tipos de solicitação')
    ]
    
    for type_name, description in ticket_types:
        c.execute("INSERT INTO ticket_types (name, description) VALUES (%s, %s) ON CONFLICT DO NOTHING", (type_name, description))

    # Insert default ticket statuses
    statuses = [
        ('Aberto', '#blue'),
        ('Em Andamento', '#yellow'),
        ('Pendente', '#orange'),
        ('Resolvido', '#green'),
        ('Fechado', '#gray'),
        ('Cancelado', '#red')
    ]
    
    for status_name, color in statuses:
        c.execute("INSERT INTO ticket_statuses (name, color) VALUES (%s, %s) ON CONFLICT DO NOTHING", (status_name, color))

    conn.commit()
    c.close()
    conn.close()

if __name__ == '__main__':
    init_database()
    print("Banco de dados inicializado com sucesso!")