import sqlite3
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

# Configurações
SQLITE_DB = "helpdesk.db"  # caminho do seu banco SQLite
POSTGRES_URL = os.environ.get("DATABASE_URL")

# Conectar ao SQLite
sqlite_conn = sqlite3.connect(SQLITE_DB)
sqlite_cursor = sqlite_conn.cursor()

# Conectar ao Postgres
pg_conn = psycopg2.connect(POSTGRES_URL)
pg_cursor = pg_conn.cursor()

# Lista de colunas booleanas por tabela
boolean_columns = {
    "users": ["is_admin", "email_updates", "sms_urgent", "push_realtime"],
    "ticket_types": ["active"],
    "ticket_statuses": ["active"],
    "ticket_responses": ["is_internal"],
    "logs": ["is_read"]
}

try:
    sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tabelas = [t[0] for t in sqlite_cursor.fetchall() if t[0] != 'sqlite_sequence']

    for tabela in reversed(tabelas):
        print(f"Limpando tabela: {tabela}")
        pg_cursor.execute(f"TRUNCATE TABLE {tabela} RESTART IDENTITY CASCADE;")

    for tabela in tabelas:
        print(f"Migrando tabela: {tabela}")
        sqlite_cursor.execute(f"PRAGMA table_info({tabela});")
        colunas = [col[1] for col in sqlite_cursor.fetchall()]
        colunas_str = ", ".join(colunas)

        sqlite_cursor.execute(f"SELECT {colunas_str} FROM {tabela}")
        linhas = sqlite_cursor.fetchall()

        for linha in linhas:
            linha = list(linha)
            if tabela in boolean_columns:
                for idx, col in enumerate(colunas):
                    if col in boolean_columns[tabela]:
                        linha[idx] = bool(linha[idx]) if linha[idx] is not None else None

            placeholders = ", ".join(["%s"] * len(linha))
            insert_sql = f'INSERT INTO {tabela} ({colunas_str}) VALUES ({placeholders})'
            pg_cursor.execute(insert_sql, linha)

    pg_conn.commit()
    print("Migração concluída!")

except Exception as e:
    pg_conn.rollback()
    print(f"Erro durante a migração: {e}")

finally:
    sqlite_conn.close()
    pg_conn.close()
