import sqlite3

def clear_tables():
    conn = sqlite3.connect('helpdesk.db')
    c = conn.cursor()

    c.execute('DELETE FROM attachments')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    clear_tables()
    print("Tabelas 'users' e 'tickets' limpas com sucesso!")
