import sqlite3
import psycopg2
import os

# Configurações
SQLITE_DB = "helpdesk.db"  # caminho do seu banco SQLite
POSTGRES_URL = os.environ.get("DATABASE_URL")  # defina no terminal ou no Render

# Conectar ao SQLite
sqlite_conn = sqlite3.connect(SQLITE_DB)
sqlite_cursor = sqlite_conn.cursor()

# Conectar ao Postgres
pg_conn = psycopg2.connect(POSTGRES_URL)
pg_cursor = pg_conn.cursor()

# Lista de tabelas para migrar
sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tabelas = [t[0] for t in sqlite_cursor.fetchall()]

for tabela in tabelas:
    print(f"Migrando tabela: {tabela}")
    # Obter colunas
    sqlite_cursor.execute(f"PRAGMA table_info({tabela});")
    colunas = [col[1] for col in sqlite_cursor.fetchall()]
    colunas_str = ", ".join(colunas)

    # Ler dados do SQLite
    sqlite_cursor.execute(f"SELECT {colunas_str} FROM {tabela}")
    linhas = sqlite_cursor.fetchall()

    # Inserir no Postgres
    for linha in linhas:
        placeholders = ", ".join(["%s"] * len(linha))
        insert_sql = f'INSERT INTO {tabela} ({colunas_str}) VALUES ({placeholders})'
        pg_cursor.execute(insert_sql, linha)

pg_conn.commit()
sqlite_conn.close()
pg_conn.close()

print("Migração concluída!")