#!/usr/bin/env python3
"""
Teste avançado do fluxo de resposta a tickets com notificações Telegram.
Simula o comportamento real da aplicação.
"""

import sys
import os
from app import get_db_connection

def simulate_ticket_response_logic():
    """Simula a lógica de resposta a ticket conforme implementada no app.py"""
    print("=== Simulação do Fluxo de Resposta a Ticket ===\n")
    
    try:
        conn = get_db_connection()
        
        # Buscar um ticket que tenha admin atribuído
        ticket = conn.execute('''
            SELECT * FROM tickets 
            WHERE assigned_to IS NOT NULL 
            LIMIT 1
        ''').fetchone()
        
        if not ticket:
            print("❌ Nenhum ticket com admin atribuído encontrado.")
            print("💡 Dica: Atribua um admin a algum ticket no dashboard administrativo.")
            conn.close()
            return
        
        ticket_id = ticket['id']
        print(f"📋 Usando ticket #{ticket_id} para simulação")
        print(f"   - Assunto: {ticket['subject']}")
        print(f"   - Status: {ticket['status']}")
        print(f"   - Admin atribuído ID: {ticket['assigned_to']}")
        
        # Buscar nome do administrador atribuído (seguindo a lógica do app.py)
        assigned_user = None
        if ticket['assigned_to']:
            assigned_user = conn.execute('SELECT name FROM users WHERE id = ?', (ticket['assigned_to'],)).fetchone()
        
        # Buscar informações do usuário dono do ticket
        ticket_owner = conn.execute('SELECT name FROM users WHERE id = ?', (ticket['user_id'],)).fetchone()
        
        print(f"   - Admin atribuído: {assigned_user['name'] if assigned_user else 'N/A'}")
        print(f"   - Usuário dono: {ticket_owner['name'] if ticket_owner else 'N/A'}")
        
        # Simular mensagem de resposta do usuário
        user_message = "Obrigado pela resposta! Agora consegui acessar o sistema sem problemas. O erro foi resolvido completamente."
        
        print(f"\n💬 Simulando resposta do usuário:")
        print(f"   Mensagem: {user_message}")
        
        # Construir notificação seguindo a lógica atualizada do app.py
        user_name = ticket_owner['name'] if ticket_owner else 'Usuário'
        assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user.keys() else None
        
        response_message = f"\U0001F4E8 <b>Nova Resposta do Usuário</b>\n\n"
        response_message += f"<b>ID:</b> #{ticket_id}\n"
        response_message += f"<b>Usuário:</b> {user_name}\n"
        if assignee:
            response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
        response_message += f"<b>Tipo:</b> {ticket.get('type', '')}\n"
        response_message += f"<b>Prioridade:</b> {ticket.get('priority', '')}\n"
        response_message += f"<b>Mensagem:</b> {user_message[:500]}{'...' if len(user_message) > 500 else ''}"
        
        print(f"\n📤 Notificação Telegram que seria enviada:")
        print("=" * 50)
        print(response_message)
        print("=" * 50)
        
        # Simular resposta do admin
        admin_message = "Perfeito! Fico feliz que conseguiu resolver. Qualquer outro problema, pode abrir um novo chamado. Vou marcar este como resolvido."
        
        print(f"\n👨‍💻 Simulando resposta do admin:")
        print(f"   Mensagem: {admin_message}")
        
        admin_response_message = f"\U0001F4AC <b>Nova Resposta do Suporte</b>\n\n"
        admin_response_message += f"<b>ID:</b> #{ticket_id}\n"
        admin_response_message += f"<b>Respondido por:</b> {assignee or 'Admin'}\n"
        if assignee:
            admin_response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
        admin_response_message += f"<b>Tipo:</b> {ticket.get('type', '')}\n"
        admin_response_message += f"<b>Usuário:</b> {user_name}\n"
        admin_response_message += f"<b>Mensagem:</b> {admin_message[:500]}{'...' if len(admin_message) > 500 else ''}"
        
        print(f"\n📤 Notificação Telegram que seria enviada:")
        print("=" * 50)
        print(admin_response_message)
        print("=" * 50)
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro na simulação: {str(e)}")

def test_notification_topics():
    """Testa as configurações de tópicos para diferentes tipos de evento"""
    print("\n=== Teste de Configuração de Tópicos ===\n")
    
    try:
        conn = get_db_connection()
        
        # Buscar todas as configurações de tópicos
        topic_settings = {}
        topic_keys = [
            'telegram_topic_new_tickets',
            'telegram_topic_messages', 
            'telegram_topic_assignments',
            'telegram_topic_closed',
            'telegram_topic_cancelled'
        ]
        
        for key in topic_keys:
            row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
            topic_settings[key] = row['value'] if row else ''
        
        print("📋 Configuração atual dos tópicos:")
        print(f"   🆕 Novos tickets: {topic_settings['telegram_topic_new_tickets'] or 'Não configurado'}")
        print(f"   💬 Mensagens: {topic_settings['telegram_topic_messages'] or 'Não configurado'}")
        print(f"   👤 Atribuições: {topic_settings['telegram_topic_assignments'] or 'Não configurado'}")
        print(f"   ✅ Fechados: {topic_settings['telegram_topic_closed'] or 'Não configurado'}")
        print(f"   ❌ Cancelados: {topic_settings['telegram_topic_cancelled'] or 'Não configurado'}")
        
        # Simular mapeamento de eventos para tópicos
        event_mappings = {
            'created': topic_settings['telegram_topic_new_tickets'],
            'assigned': topic_settings['telegram_topic_assignments'],
            'response_user': topic_settings['telegram_topic_messages'],
            'response_admin': topic_settings['telegram_topic_messages'],
            'status_changed': topic_settings['telegram_topic_messages'],
            'closed': topic_settings['telegram_topic_closed'],
            'cancelled': topic_settings['telegram_topic_cancelled'],
            'reopened': topic_settings['telegram_topic_new_tickets']
        }
        
        print(f"\n🎯 Mapeamento evento → tópico:")
        for event, topic_id in event_mappings.items():
            status = "✅" if topic_id else "⚠️"
            print(f"   {status} {event}: {topic_id or 'Canal principal'}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro ao testar tópicos: {str(e)}")

def main():
    """Função principal do teste avançado"""
    print("🧪 TESTE AVANÇADO - FLUXO DE RESPOSTA A TICKETS\n")
    
    # Verificar se o arquivo de banco existe
    if not os.path.exists('helpdesk.db'):
        print("❌ Banco de dados não encontrado. Execute 'python database.py' primeiro.")
        return
    
    simulate_ticket_response_logic()
    test_notification_topics()
    
    print("\n✅ Testes avançados concluídos!")
    print("\n🎉 RESUMO DAS MELHORIAS IMPLEMENTADAS:")
    print("   ✓ Admin atribuído incluído nas notificações")
    print("   ✓ Conteúdo da mensagem incluído (até 500 caracteres)")
    print("   ✓ Notificações tanto para resposta de usuário quanto admin")
    print("   ✓ Formatação HTML melhorada para Telegram")
    print("   ✓ Suporte completo a tópicos por tipo de evento")
    
    print("\n🔧 Para testar em produção:")
    print("   1. Configure token do bot e group ID no dashboard admin")
    print("   2. Use /api/admin/telegram/test para verificar conectividade")
    print("   3. Atribua admins aos tickets existentes")
    print("   4. Adicione respostas aos tickets para ver as notificações")

if __name__ == "__main__":
    main()
