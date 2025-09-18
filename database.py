from dotenv import load_dotenv
load_dotenv()

#Database.py
import psycopg2
import sqlite3
import os
import hashlib
from psycopg2.extras import DictCursor

def get_db_connection():
    """Conecta ao Postgres se DATABASE_URL estiver definido, caso contrário usa SQLite local."""
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Evitar logar credenciais
        print("DATABASE_URL configurado (redigido).")
        # Forçar SSL se for Postgres e não houver parâmetro
        if 'postgres' in database_url and 'sslmode=' not in database_url:
            sep = '&' if '?' in database_url else '?'
            database_url = f"{database_url}{sep}sslmode=require"
        return psycopg2.connect(database_url)
    # Fallback SQLite
    db_path = os.path.join(os.path.dirname(__file__), 'helpdesk.db')
    print(f"DATABASE_URL ausente. Usando SQLite em {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
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

    conn.commit()
    c.close()
    conn.close()

if __name__ == '__main__':
    init_database()
    print("Banco de dados inicializado com sucesso!")