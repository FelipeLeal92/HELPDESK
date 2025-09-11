import sqlite3
import hashlib

def hash_password(password):
    """Hashes the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def add_users_bulk():
    """Connects to the database and adds a list of users in bulk."""
    try:
        conn = sqlite3.connect('helpdesk.db')
        c = conn.cursor()

        # --- List of users to add ---
        # Format: (Name, Email, Password, Role)
        # Available roles: 'user', 'manager', 'admin'
        users_to_add = [
            ('Carolina Carvalho', 'sucessoaocliente@logtudo.com.br', 'user123', 'user'),
            ('Charles Siqueira', 'prestacaodecontasrec2@logtudo.com.br', 'user123', 'user'),
            ('Claudia Santos', 'faturamento@logtudo.com.br', 'user123', 'user'),
            ('Gabriel', 'Operacional.vix@logtudo.com.br', 'user123', 'user'),
            ('Genilson', 'programacao2@logtudo.com.br', 'user123', 'user'),
            ('Tiago', 'financeiro1@logtudo.com.br', 'user123', 'user'),
            ('James Daniel', 'Operacional.aereo@logtudo.com.br', 'user123', 'user'),
            ('Leoncio Henrique', 'prestacaodecontasrec@logtudo.com.br', 'user123', 'user'),
            ('Lucas Marques', 'monitoramento.ssa@logtudo.com.br', 'user123', 'user'),
            ('Maria Denise', 'Operacional.ce@logtudo.com.br', 'user123', 'user'),
            ('Quezia Bispo', 'faturamento1@logtudo.com.br', 'user123', 'user'),
            ('Rafael Santos', 'programacao@logtudo.com.br', 'user123', 'user'),
            ('Tiago', 'contasapagar@logtudo.com.br', 'auser123', 'user'),
            ('Vania', 'financeiro@logtudo.com.br', 'user123', 'user'),
            ('Viviane', 'prestacaodecontas1@logtudo.com.br', 'user123s', 'user'),
            ('Fabiano', 'gestaologistica@logtudo.com.br', 'manager123', 'amanager'),
            ('Suiderly', 'liderlogistica@logtudo.com.br', 'user123', 'user'),
            ('Diego', 'gestaofinanceiro1@logtudo.com.br', 'user123', 'user'),
            ('Deidmar', 'suporte.gestao@logtudo.com.br', 'admin', 'admin'),
            ('Eduardo', 'contratacao@logtudo.com.br', 'user123', 'user'),
            ('Lucas de Jesus', 'suporte.aereo@logtudo.com.br', 'user123', 'user'),
            ('Jecilene', 'monitoramento3@logtudo.com.br', 'user123', 'user'),
            ('Marcos França', 'marcos.franca@logtudo.com.br', 'user123', 'user'),
            ('Patricia França', ' patricia.franca@logtudo.com.br', 'user123', 'user')           
        ]

        for name, email, password, role in users_to_add:
            try:
                hashed_password = hash_password(password)
                c.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                          (name, email, hashed_password, role))
                print(f"Successfully added user: {name} ({email})")
            except sqlite3.IntegrityError:
                print(f"User with email {email} already exists. Skipping.")
        
        conn.commit()
        print("\nBulk user addition process completed successfully!")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    add_users_bulk()
