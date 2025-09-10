#!/usr/bin/env python3
"""
Teste das notificações Telegram após as correções.
Simula cenários de resposta de usuário e admin com admin atribuído.
"""

import sys
import os
import sqlite3
from app import get_db_connection, send_telegram_notification

def test_telegram_format():
    """Testa o formato das mensagens de notificação"""
    print("=== Teste de Formato das Mensagens Telegram ===\n")
    
    # Simular resposta do usuário
    ticket_id = 123
    user_name = "João Silva"
    assignee = "Maria Administradora"
    message = "Estou tendo problemas para acessar o sistema após a manutenção de ontem. O erro aparece na tela de login."
    
    user_response_message = f"\U0001F4E8 <b>Nova Resposta do Usuário</b>\n\n"
    user_response_message += f"<b>ID:</b> #{ticket_id}\n"
    user_response_message += f"<b>Usuário:</b> {user_name}\n"
    user_response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
    user_response_message += f"<b>Tipo:</b> Suporte Técnico\n"
    user_response_message += f"<b>Prioridade:</b> Alta\n"
    user_response_message += f"<b>Mensagem:</b> {message[:500]}{'...' if len(message) > 500 else ''}"
    
    print("RESPOSTA DO USUÁRIO:")
    print(user_response_message)
    print("\n" + "="*60 + "\n")
    
    # Simular resposta do admin
    admin_name = "Maria Administradora"
    admin_message = "Olá João, identifiquei o problema. Vou reconfigurar suas permissões de acesso. Pode tentar novamente em alguns minutos?"
    
    admin_response_message = f"\U0001F4AC <b>Nova Resposta do Suporte</b>\n\n"
    admin_response_message += f"<b>ID:</b> #{ticket_id}\n"
    admin_response_message += f"<b>Respondido por:</b> {admin_name}\n"
    admin_response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
    admin_response_message += f"<b>Tipo:</b> Suporte Técnico\n"
    admin_response_message += f"<b>Usuário:</b> {user_name}\n"
    admin_response_message += f"<b>Mensagem:</b> {admin_message[:500]}{'...' if len(admin_message) > 500 else ''}"
    
    print("RESPOSTA DO ADMIN:")
    print(admin_response_message)
    print("\n" + "="*60 + "\n")

def test_database_connection():
    """Testa se consegue conectar ao banco e buscar dados"""
    print("=== Teste de Conexão com Banco ===\n")
    
    try:
        conn = get_db_connection()
        
        # Verificar se há tickets com admin atribuído
        tickets_with_assignment = conn.execute('''
            SELECT t.id, t.subject, t.assigned_to, u.name as assigned_name
            FROM tickets t
            LEFT JOIN users u ON t.assigned_to = u.id
            WHERE t.assigned_to IS NOT NULL
            LIMIT 3
        ''').fetchall()
        
        print(f"Tickets com admin atribuído: {len(tickets_with_assignment)}")
        for ticket in tickets_with_assignment:
            print(f"  - Ticket #{ticket['id']}: {ticket['subject']} -> {ticket['assigned_name']}")
        
        # Verificar configurações do Telegram
        telegram_settings = {}
        settings_keys = ['telegram_bot_token', 'telegram_group_id', 'telegram_topic_messages']
        
        for key in settings_keys:
            row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
            telegram_settings[key] = row['value'] if row else ''
        
        print(f"\nConfigurações Telegram:")
        print(f"  - Bot Token configurado: {'Sim' if telegram_settings['telegram_bot_token'] else 'Não'}")
        print(f"  - Group ID configurado: {'Sim' if telegram_settings['telegram_group_id'] else 'Não'}")
        print(f"  - Topic Messages: {telegram_settings['telegram_topic_messages'] or 'Não configurado'}")
        
        conn.close()
        
    except Exception as e:
        print(f"Erro ao conectar ao banco: {str(e)}")

def test_message_with_different_lengths():
    """Testa mensagens de diferentes tamanhos"""
    print("=== Teste de Mensagens com Diferentes Tamanhos ===\n")
    
    # Mensagem curta
    short_message = "Problema resolvido!"
    print(f"Mensagem curta ({len(short_message)} chars): {short_message}")
    
    # Mensagem longa
    long_message = "Este é um exemplo de mensagem muito longa que vai ultrapassar o limite de 500 caracteres. " * 10
    truncated = long_message[:500] + ('...' if len(long_message) > 500 else '')
    print(f"Mensagem longa ({len(long_message)} chars -> {len(truncated)} chars):")
    print(truncated)
    print()

def main():
    """Função principal do teste"""
    print("🔍 TESTE DAS NOTIFICAÇÕES TELEGRAM\n")
    
    # Verificar se o arquivo de banco existe
    if not os.path.exists('helpdesk.db'):
        print("❌ Banco de dados não encontrado. Execute 'python database.py' primeiro.")
        return
    
    test_database_connection()
    print()
    test_telegram_format()
    print()
    test_message_with_different_lengths()
    
    print("✅ Testes concluídos!")
    print("\n📝 Próximos passos:")
    print("1. Configure o token do bot e group ID em Configurações > Admin")
    print("2. Use o endpoint /api/admin/telegram/test para testar conectividade")
    print("3. Crie um ticket e adicione respostas para testar as notificações ao vivo")

if __name__ == "__main__":
    main()
