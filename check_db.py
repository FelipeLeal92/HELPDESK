import sqlite3
import os

def check_database():
    db_file = 'helpdesk.db'
    
    if not os.path.exists(db_file):
        print("❌ Banco de dados não existe!")
        return False
    
    print("✅ Banco de dados existe")
    
    try:
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Verificar tabelas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"📋 Tabelas encontradas: {tables}")
        
        # Verificar colunas da tabela users primeiro
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        print(f"\n📊 Estrutura da tabela users:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
        
        # Verificar usuários
        if 'users' in tables:
            # Descobrir se temos 'role' ou 'is_admin'
            column_names = [col[1] for col in columns]
            if 'role' in column_names:
                cursor.execute("SELECT id, name, email, role FROM users")
                users = cursor.fetchall()
                print(f"\n👥 Usuários cadastrados ({len(users)}):")
                for user in users:
                    print(f"  - ID: {user['id']}, Nome: {user['name']}, Email: {user['email']}, Role: {user['role']}")
            elif 'is_admin' in column_names:
                cursor.execute("SELECT id, name, email, is_admin FROM users")
                users = cursor.fetchall()
                print(f"\n👥 Usuários cadastrados ({len(users)}):")
                for user in users:
                    admin_status = "admin" if user['is_admin'] else "user"
                    print(f"  - ID: {user['id']}, Nome: {user['name']}, Email: {user['email']}, Admin: {admin_status}")
            else:
                cursor.execute("SELECT * FROM users LIMIT 1")
                sample = cursor.fetchone()
                print(f"\n👥 Estrutura de usuário de exemplo:")
                for key in sample.keys():
                    print(f"  - {key}: {sample[key]}")
        
        # Verificar tickets
        if 'tickets' in tables:
            cursor.execute("SELECT COUNT(*) as count FROM tickets")
            ticket_count = cursor.fetchone()['count']
            print(f"\n🎫 Total de tickets: {ticket_count}")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Erro ao acessar banco de dados: {str(e)}")
        return False

if __name__ == '__main__':
    check_database()
