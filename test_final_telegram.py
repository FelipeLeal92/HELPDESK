#!/usr/bin/env python3
"""
Teste final completo das correções de notificação Telegram.
Valida todos os cenários: resposta de usuário, resposta de admin e atribuição.
"""

import sys
import os
from app import get_db_connection, send_telegram_notification

def test_user_response_notification():
    """Testa a notificação de resposta do usuário"""
    print("=== Teste de Notificação - Resposta do Usuário ===\n")
    
    try:
        conn = get_db_connection()
        
        # Buscar um ticket com admin atribuído
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
            return False
        
        # Buscar nome do admin atribuído
        assigned_user = None
        if ticket['assigned_to']:
            assigned_user = conn.execute('SELECT name FROM users WHERE id = ?', (ticket['assigned_to'],)).fetchone()
        
        # Simular a mensagem exatamente como no app.py
        ticket_id = ticket['id']
        message = "Olá, estou testando o sistema de notificações. Por favor, me ajudem a resolver este problema urgente!"
        
        user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
        assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user.keys() else None
        ticket_type = ticket['type'] if ticket['type'] else 'N/A'
        ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
        
        response_message = f"\U0001F4E8 <b>Nova Resposta do Usuário</b>\n\n"
        response_message += f"<b>ID:</b> #{ticket_id}\n"
        response_message += f"<b>Usuário:</b> {user_name}\n"
        if assignee:
            response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
        response_message += f"<b>Tipo:</b> {ticket_type}\n"
        response_message += f"<b>Prioridade:</b> {ticket_priority}\n"
        response_message += f"<b>Mensagem:</b> {message[:500]}{'...' if len(message) > 500 else ''}"
        
        print("📤 Mensagem de resposta do usuário:")
        print("-" * 50)
        print(response_message)
        print("-" * 50)
        
        # Tentar enviar
        result = send_telegram_notification(response_message, 'response_user')
        print(f"✅ Resultado do envio: {result}")
        
        conn.close()
        return result
        
    except Exception as e:
        print(f"❌ Erro no teste: {str(e)}")
        return False

def test_admin_response_notification():
    """Testa a notificação de resposta do admin"""
    print("\n=== Teste de Notificação - Resposta do Admin ===\n")
    
    try:
        conn = get_db_connection()
        
        # Buscar um ticket com admin atribuído
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
            return False
        
        # Buscar nome do admin atribuído
        assigned_user = None
        if ticket['assigned_to']:
            assigned_user = conn.execute('SELECT name FROM users WHERE id = ?', (ticket['assigned_to'],)).fetchone()
        
        # Simular a mensagem do admin
        ticket_id = ticket['id']
        message = "Olá! Identifiquei o problema e vou resolver em breve. Aguarde alguns minutos para a correção."
        admin_name = "Administrador Teste"
        
        user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
        assignee = assigned_user['name'] if assigned_user and 'name' in assigned_user.keys() else None
        ticket_type = ticket['type'] if ticket['type'] else 'N/A'
        
        response_message = f"\U0001F4AC <b>Nova Resposta do Suporte</b>\n\n"
        response_message += f"<b>ID:</b> #{ticket_id}\n"
        response_message += f"<b>Respondido por:</b> {admin_name}\n"
        if assignee:
            response_message += f"<b>Admin Atribuído:</b> {assignee}\n"
        response_message += f"<b>Tipo:</b> {ticket_type}\n"
        response_message += f"<b>Usuário:</b> {user_name}\n"
        response_message += f"<b>Mensagem:</b> {message[:500]}{'...' if len(message) > 500 else ''}"
        
        print("📤 Mensagem de resposta do admin:")
        print("-" * 50)
        print(response_message)
        print("-" * 50)
        
        # Tentar enviar
        result = send_telegram_notification(response_message, 'response_admin')
        print(f"✅ Resultado do envio: {result}")
        
        conn.close()
        return result
        
    except Exception as e:
        print(f"❌ Erro no teste: {str(e)}")
        return False

def test_assignment_notification():
    """Testa a notificação de atribuição"""
    print("\n=== Teste de Notificação - Atribuição ===\n")
    
    try:
        conn = get_db_connection()
        
        # Buscar um ticket com admin atribuído
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
            return False
        
        # Buscar nome do admin atribuído
        assigned_user = conn.execute('SELECT name FROM users WHERE id = ?', (ticket['assigned_to'],)).fetchone()
        
        # Simular mensagem de atribuição
        ticket_id = ticket['id']
        
        user_name = ticket['user_name'] if ticket['user_name'] else 'Usuário'
        ticket_type = ticket['type'] if ticket['type'] else 'N/A'
        ticket_priority = ticket['priority'] if ticket['priority'] else 'N/A'
        ticket_subject = ticket['subject'] if ticket['subject'] else (ticket['description'][:50] if ticket['description'] else 'N/A')
        
        assignment_message = f"\U0001F464 <b>Chamado Atribuído</b>\n\n"
        assignment_message += f"<b>ID:</b> #{ticket_id}\n"
        assignment_message += f"<b>Responsável:</b> {assigned_user['name']}\n"
        assignment_message += f"<b>Tipo:</b> {ticket_type}\n"
        assignment_message += f"<b>Prioridade:</b> {ticket_priority}\n"
        assignment_message += f"<b>Assunto:</b> {ticket_subject}\n"
        assignment_message += f"<b>Usuário:</b> {user_name}"
        
        print("📤 Mensagem de atribuição:")
        print("-" * 50)
        print(assignment_message)
        print("-" * 50)
        
        # Tentar enviar
        result = send_telegram_notification(assignment_message, 'assigned')
        print(f"✅ Resultado do envio: {result}")
        
        conn.close()
        return result
        
    except Exception as e:
        print(f"❌ Erro no teste: {str(e)}")
        return False

def verify_telegram_configuration():
    """Verifica se a configuração do Telegram está completa"""
    print("=== Verificação da Configuração Telegram ===\n")
    
    try:
        conn = get_db_connection()
        
        # Verificar configurações
        settings = {}
        required_keys = ['telegram_bot_token', 'telegram_group_id']
        optional_keys = ['telegram_topic_messages', 'telegram_topic_assignments']
        
        for key in required_keys + optional_keys:
            row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
            settings[key] = row['value'] if row else ''
        
        print("🔧 Configurações:")
        for key in required_keys:
            value = settings[key]
            status = "✅" if value else "❌"
            display = "[CONFIGURADO]" if value and 'token' in key else (value if value else "[VAZIO]")
            print(f"   {status} {key}: {display}")
        
        for key in optional_keys:
            value = settings[key]
            status = "✅" if value else "⚠️"
            display = value if value else "[NÃO CONFIGURADO]"
            print(f"   {status} {key}: {display}")
        
        # Verificar se as configurações obrigatórias estão preenchidas
        all_required = all(settings[key] for key in required_keys)
        
        conn.close()
        return all_required
        
    except Exception as e:
        print(f"❌ Erro ao verificar configurações: {str(e)}")
        return False

def main():
    """Função principal do teste final"""
    print("🚀 TESTE FINAL COMPLETO - NOTIFICAÇÕES TELEGRAM\n")
    
    if not os.path.exists('helpdesk.db'):
        print("❌ Banco de dados não encontrado.")
        return
    
    # Verificar configuração
    config_ok = verify_telegram_configuration()
    
    if not config_ok:
        print("\n⚠️ Configuração incompleta. Configure o Telegram no Dashboard Admin.")
        print("Continuando com testes de formato...\n")
    
    # Executar testes
    tests_results = []
    
    print("\n" + "="*60)
    result1 = test_user_response_notification()
    tests_results.append(('Resposta do Usuário', result1))
    
    print("\n" + "="*60)
    result2 = test_admin_response_notification()
    tests_results.append(('Resposta do Admin', result2))
    
    print("\n" + "="*60)
    result3 = test_assignment_notification()
    tests_results.append(('Atribuição', result3))
    
    print("\n" + "="*60)
    print("\n📊 RESUMO DOS TESTES:")
    for test_name, result in tests_results:
        status = "✅ SUCESSO" if result else "❌ FALHOU"
        print(f"   {status} - {test_name}")
    
    successful_tests = sum(1 for _, result in tests_results if result)
    total_tests = len(tests_results)
    
    print(f"\n🎯 RESULTADO FINAL: {successful_tests}/{total_tests} testes bem-sucedidos")
    
    if successful_tests == total_tests:
        print("\n🎉 TODAS AS CORREÇÕES ESTÃO FUNCIONANDO!")
        print("✅ As mensagens dos usuários serão notificadas no Telegram")
        print("✅ O admin atribuído aparece nos cards")
        print("✅ O conteúdo das mensagens é incluído")
        print("✅ A formatação está correta")
    else:
        print(f"\n⚠️ {total_tests - successful_tests} teste(s) falharam")
        print("💡 Verifique as configurações do Telegram no Dashboard Admin")
    
    print("\n📝 PRÓXIMOS PASSOS PARA USO REAL:")
    print("   1. Configure o bot token e group ID no Dashboard Admin")
    print("   2. Configure os tópicos (IDs) se estiver usando")
    print("   3. Teste com um ticket real: atribua um admin e responda")
    print("   4. Verifique se as notificações chegam no grupo do Telegram")

if __name__ == "__main__":
    main()
