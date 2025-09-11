#Database.py
import sqlite3
import hashlib

def init_database():
    conn = sqlite3.connect('helpdesk.db')
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  phone TEXT,
                  role TEXT NOT NULL DEFAULT 'user',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Create ticket_types table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_types
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  active INTEGER DEFAULT 1)''')

    # Create ticket_statuses table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_statuses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  color TEXT DEFAULT '#gray',
                  active INTEGER DEFAULT 1)''')

    # Create tickets table
    c.execute('''CREATE TABLE IF NOT EXISTS tickets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  type TEXT NOT NULL,
                  priority TEXT NOT NULL,
                  subject TEXT,
                  description TEXT NOT NULL,
                  status TEXT DEFAULT 'Aberto',
                  assigned_to INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  closed_at TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (assigned_to) REFERENCES users (id))''')

    # Create ticket_responses table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_responses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ticket_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  message TEXT NOT NULL,
                  is_internal INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')

    # Create attachments table
    c.execute('''CREATE TABLE IF NOT EXISTS attachments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ticket_id INTEGER,
                  response_id INTEGER,
                  filename TEXT NOT NULL,
                  filepath TEXT NOT NULL,
                  filesize INTEGER,
                  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                  FOREIGN KEY (response_id) REFERENCES ticket_responses (id))''')

    # Create logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  ticket_id INTEGER,
                  message TEXT NOT NULL,
                  is_read INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id))''')


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
        try:
            c.execute("INSERT INTO ticket_types (name, description) VALUES (?, ?)", (type_name, description))
        except sqlite3.IntegrityError:
            pass

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
        try:
            c.execute("INSERT INTO ticket_statuses (name, color) VALUES (?, ?)", (status_name, color))
        except sqlite3.IntegrityError:
            pass

    # Insert some sample tickets
    sample_tickets = [
        (2, 'Suporte Técnico', 'Alta', 'Problema com login no sistema', 'Não consigo acessar o sistema após a atualização de ontem.', 'Pendente'),
        (2, 'Hardware', 'Média', 'Solicitação de novo monitor', 'Preciso de um monitor adicional para meu home office.', 'Resolvido'),
        (2, 'Software', 'Baixa', 'Atualização do software', 'Preciso de ajuda para atualizar o sistema para a versão 2.3.1.', 'Em Andamento')
    ]
    
    for user_id, ticket_type, priority, subject, description, status in sample_tickets:
        try:
            c.execute('''INSERT INTO tickets (user_id, type, priority, subject, description, status)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (user_id, ticket_type, priority, subject, description, status))
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_database()
    print("Banco de dados inicializado com sucesso!")

