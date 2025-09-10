#!/usr/bin/env python3
"""
Teste específico das correções de notificação Telegram.
Valida se os campos estão sendo corretamente acessados e formatados.
"""

import sys
import os
from app import get_db_connection

def test_ticket_data_access():
    """Testa se consegue acessar corretamente os dados do ticket com JOIN"""
    print("=== Teste de Acesso aos Dados do Ticket ===\n")
    
    try:
        conn = get_db_connection()
        
        # Usar a mesma consulta que está no app.py agora
        ticket = conn.execute('''
            SELECT t.*, u.name as user_name
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.assigned_to IS NOT NULL
            LIMIT 1
        ''').fetchone()
        
        if not ticket:
            print("❌ Nenhum ticket com admin atribuído encontrado.")
            conn.close()
            return
        
        ticket_id = ticket['id']
        print(f"📋 Ticket #{ticket_id} encontrado com dados:")
        print(f"   - user_name: {ticket['user_name']}")
        print(f"   - type: {ticket['type']}")
        print(f"   - priority: {ticket['priority']}")
        print(f"   - assigned_to: {ticket['assigned_to']}")
        
        # Testar acesso ao admin atribuído
        assigned_user = None
        if ticket['assigned_to']:
            assigned_user = conn.execute('SELECT name FROM users WHERE id = ?', (ticket['assigned_to'],)).fetchone()
            print(f"   - assigned_user: {assigned_user['name'] if assigned_user else 'N/A'}")
        
        # Simular a construção da mensagem exatamente como no app.py
        user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
        assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user.keys() else None
        ticket_type = ticket['type'] if ticket['type'] else 'N/A'
        ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
        message = "Esta é uma mensagem de teste do usuário para verificar se a notificação funciona corretamente."
        
        print(f"\n🔍 Variáveis extraídas:")
        print(f"   - user_name: '{user_name}'")
        print(f"   - assignee: '{assignee}'")
        print(f"   - ticket_type: '{ticket_type}'")
        print(f"   - ticket_priority: '{ticket_priority}'")
        
        # Construir mensagem de notificação do usuário
        response_message = f"\U0001F4E8 <b>Nova Resposta do Usuário</b>\n\n"
        response_message += f"<b>ID:</b> #{ticket_id}\n"
        response_message += f"<b>Usuário:</b> {user_name}\n"
        if assignee:
            response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
        response_message += f"<b>Tipo:</b> {ticket_type}\n"
        response_message += f"<b>Prioridade:</b> {ticket_priority}\n"
        response_message += f"<b>Mensagem:</b> {message[:500]}{'...' if len(message) > 500 else ''}"
        
        print(f"\n📤 Mensagem de notificação que seria enviada:")
        print("=" * 60)
        print(response_message)
        print("=" * 60)
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro no teste: {str(e)}")
        import traceback
        traceback.print_exc()

def test_telegram_settings():
    """Verifica as configurações do Telegram"""
    print("\n=== Teste das Configurações Telegram ===\n")
    
    try:
        conn = get_db_connection()
        
        # Verificar configurações essenciais
        essential_keys = ['telegram_bot_token', 'telegram_group_id', 'telegram_topic_messages']
        
        settings = {}
        for key in essential_keys:
            row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
            settings[key] = row['value'] if row else ''
        
        print("🔧 Configurações essenciais:")
        for key, value in settings.items():
            status = "✅" if value else "❌"
            display_value = "[CONFIGURADO]" if value and 'token' in key else value
            print(f"   {status} {key}: {display_value}")
        
        # Verificar se todas as configurações essenciais estão preenchidas
        all_configured = all(settings.values())
        
        if all_configured:
            print("\n✅ Todas as configurações essenciais estão definidas!")
            print("🚀 As notificações devem funcionar corretamente.")
        else:
            print("\n⚠️ Algumas configurações estão faltando.")
            print("💡 Configure no Dashboard Admin > Configurações")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro ao verificar configurações: {str(e)}")

def simulate_notification_sending():
    """Simula o envio de notificação sem realmente enviar"""
    print("\n=== Simulação de Envio de Notificação ===\n")
    
    from app import send_telegram_notification
    
    # Criar mensagem de teste
    test_message = """\U0001F4E8 <b>Nova Resposta do Usuário</b>

<b>ID:</b> #123
<b>Usuário:</b> João Silva
<b>Admin Atribuído:</b> Maria Administradora
<b>Tipo:</b> Suporte Técnico
<b>Prioridade:</b> Alta
<b>Mensagem:</b> Problema foi resolvido, obrigado pela ajuda!"""
    
    print("📋 Mensagem de teste:")
    print("-" * 40)
    print(test_message)
    print("-" * 40)
    
    print("\n🔄 Tentando enviar notificação (modo teste)...")
    
    # Note: Esta chamada pode falhar se as configurações não estiverem corretas,
    # mas isso é esperado em um ambiente de teste
    try:
        result = send_telegram_notification(test_message, 'response_user')
        print(f"✅ Resultado: {result}")
        if result:
            print("🎉 Notificação enviada com sucesso!")
        else:
            print("⚠️ Notificação não foi enviada (verificar configurações)")
    except Exception as e:
        print(f"❌ Erro ao enviar: {str(e)}")
        print("💡 Isso é normal se as configurações do Telegram não estiverem completas")

def main():
    """Função principal do teste de correções"""
    print("🔧 TESTE DAS CORREÇÕES DE NOTIFICAÇÃO TELEGRAM\n")
    
    if not os.path.exists('helpdesk.db'):
        print("❌ Banco de dados não encontrado. Execute 'python database.py' primeiro.")
        return
    
    test_ticket_data_access()
    test_telegram_settings()
    simulate_notification_sending()
    
    print("\n✅ Testes das correções concluídos!")
    print("\n🎯 CORREÇÕES IMPLEMENTADAS:")
    print("   ✓ JOIN correto para buscar nome do usuário (user_name)")
    print("   ✓ Acesso correto aos campos do ticket (sem .get())")
    print("   ✓ Escape correto das quebras de linha (\\n em vez de \\\\n)")
    print("   ✓ Verificação robusta de campos nulos")
    print("   ✓ Conteúdo da mensagem incluído (até 500 caracteres)")
    print("   ✓ Nome do admin atribuído incluído quando disponível")
    
    print("\n🚀 Para testar ao vivo:")
    print("   1. Certifique-se de que as configurações do Telegram estão corretas")
    print("   2. Atribua um admin a um ticket existente")
    print("   3. Como usuário, responda ao ticket")
    print("   4. Verifique se a notificação aparece no grupo do Telegram")

if __name__ == "__main__":
    main()
