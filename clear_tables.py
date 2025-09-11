import sqlite3

def clear_tables():
    conn = sqlite3.connect('helpdesk.db')
    c = conn.cursor()

    # Clear users table
    c.execute('DELETE FROM users')

    # Clear tickets table
    c.execute('DELETE FROM tickets')

    c.execute('DELETE FROM ticket_responses')

    c.execute('DELETE FROM attachments')

    c.execute('DELETE FROM logs')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    clear_tables()
    print("Tabelas 'users' e 'tickets' limpas com sucesso!")
