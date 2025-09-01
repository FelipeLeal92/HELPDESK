import sqlite3

conn = sqlite3.connect('helpdesk.db')
c = conn.cursor()

# Adicionar os novos tipos de chamados
tipos = [
    ('Acesso', 'Problemas de acesso e permissões'),
    ('Automação', 'Solicitações relacionadas a automação de processos'),
    ('Hardware', 'Problemas com equipamentos físicos'),
    ('Software', 'Problemas com programas e sistemas'),
    ('Suporte técnico', 'Assistência técnica geral')
]

for tipo, desc in tipos:
    c.execute("INSERT INTO ticket_types (name, description) VALUES (?, ?)", (tipo, desc))

conn.commit()
conn.close()

print('Novos tipos de chamados adicionados com sucesso!')