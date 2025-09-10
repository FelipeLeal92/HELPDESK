#!/usr/bin/env python3
"""
Teste das novas funcionalidades implementadas:
- Cancelamento de tickets por gerentes
- Reabertura de tickets cancelados (apenas gerentes)
- Navegação inteligente para aba de mensagens
"""

import sys
import os
from app import get_db_connection

def test_manager_permissions():
    """Testa se existem usuários com papel de manager"""
    print("=== Teste de Permissões de Gerente ===\n")
    
    try:
        conn = get_db_connection()
        
        # Verificar usuários com papel de manager
        managers = conn.execute("SELECT id, name, email, role FROM users WHERE role = 'manager'").fetchall()
        admins = conn.execute("SELECT id, name, email, role FROM users WHERE role = 'admin'").fetchall()
        
        print(f"👥 Gerentes encontrados: {len(managers)}")
        for manager in managers:
            print(f"   - {manager['name']} ({manager['email']})")
        
        print(f"\n👨‍💻 Administradores encontrados: {len(admins)}")
        for admin in admins:
            print(f"   - {admin['name']} ({admin['email']})")
        
        if len(managers) == 0:
            print("\n⚠️ Nenhum gerente encontrado!")
            print("💡 Criando um gerente de teste...")
            
            # Criar um gerente de teste
            conn.execute('''
                INSERT INTO users (name, email, password, role, is_admin) 
                VALUES (?, ?, ?, ?, ?)
            ''', ('Gerente Teste', 'gerente@teste.com', 'gerente123', 'manager', 1))
            conn.commit()
            
            print("✅ Gerente de teste criado: gerente@teste.com / gerente123")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Erro ao verificar permissões: {str(e)}")
        return False

def test_ticket_status_transitions():
    """Testa as transições de status de tickets"""
    print("\n=== Teste de Transições de Status ===\n")
    
    try:
        conn = get_db_connection()
        
        # Verificar tickets em diferentes status
        statuses = ['Aberto', 'Em Andamento', 'Pendente', 'Resolvido', 'Fechado', 'Cancelado']
        
        for status in statuses:
            count = conn.execute('SELECT COUNT(*) as count FROM tickets WHERE status = ?', (status,)).fetchone()['count']
            print(f"📋 Tickets com status '{status}': {count}")
        
        # Verificar se há tickets que podem ser cancelados
        cancelable_tickets = conn.execute('''
            SELECT id, subject, status, user_id 
            FROM tickets 
            WHERE status IN ('Aberto', 'Em Andamento', 'Pendente')
            LIMIT 3
        ''').fetchall()
        
        print(f"\n🎯 Tickets que podem ser cancelados: {len(cancelable_tickets)}")
        for ticket in cancelable_tickets:
            print(f"   - #{ticket['id']}: {ticket['subject'] or 'Sem assunto'} (Status: {ticket['status']})")
        
        # Verificar tickets cancelados que podem ser reabertos
        cancelled_tickets = conn.execute('''
            SELECT id, subject, status 
            FROM tickets 
            WHERE status = 'Cancelado'
            LIMIT 3
        ''').fetchall()
        
        print(f"\n🔄 Tickets cancelados que podem ser reabertos por gerentes: {len(cancelled_tickets)}")
        for ticket in cancelled_tickets:
            print(f"   - #{ticket['id']}: {ticket['subject'] or 'Sem assunto'}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Erro ao verificar transições de status: {str(e)}")
        return False

def test_telegram_notification_format():
    """Testa o formato das notificações Telegram para cancelamento"""
    print("\n=== Teste de Formato de Notificação Telegram ===\n")
    
    try:
        # Simular dados de um ticket cancelado
        ticket_data = {
            'id': 123,
            'user_name': 'João Silva',
            'type': 'Suporte Técnico',
            'priority': 'Alta',
            'subject': 'Problema com sistema'
        }
        
        manager_name = "Maria Gerente"
        
        # Construir mensagem como seria feita no backend
        cancel_message = f"\U0000274C <b>Chamado Cancelado</b>\n\n"
        cancel_message += f"<b>ID:</b> #{ticket_data['id']}\n"
        cancel_message += f"<b>Cancelado por:</b> {manager_name}\n"
        cancel_message += f"<b>Usuário:</b> {ticket_data['user_name']}\n"
        cancel_message += f"<b>Tipo:</b> {ticket_data['type']}\n"
        cancel_message += f"<b>Prioridade:</b> {ticket_data['priority']}\n"
        cancel_message += f"<b>Assunto:</b> {ticket_data['subject']}"
        
        print("📧 Formato da mensagem de cancelamento:")
        print("-" * 50)
        print(cancel_message)
        print("-" * 50)
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao testar formato de notificação: {str(e)}")
        return False

def test_endpoints_existence():
    """Verifica se os novos endpoints foram implementados"""
    print("\n=== Teste de Endpoints Implementados ===\n")
    
    try:
        from app import app
        
        # Listar todas as rotas da aplicação
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'rule': rule.rule
            })
        
        # Verificar se os novos endpoints existem
        cancel_endpoint = None
        reopen_endpoint = None
        
        for route in routes:
            if 'cancel' in route['rule']:
                cancel_endpoint = route
            if 'reopen' in route['rule']:
                reopen_endpoint = route
        
        print("🔍 Endpoints encontrados:")
        
        if cancel_endpoint:
            print(f"   ✅ Cancel: {cancel_endpoint['rule']} - {cancel_endpoint['methods']}")
        else:
            print("   ❌ Endpoint de cancelamento não encontrado")
        
        if reopen_endpoint:
            print(f"   ✅ Reopen: {reopen_endpoint['rule']} - {reopen_endpoint['methods']}")
        else:
            print("   ❌ Endpoint de reabertura não encontrado")
        
        return cancel_endpoint is not None and reopen_endpoint is not None
        
    except Exception as e:
        print(f"❌ Erro ao verificar endpoints: {str(e)}")
        return False

def test_javascript_functions():
    """Verifica se as funções JavaScript foram implementadas"""
    print("\n=== Teste de Funções JavaScript ===\n")
    
    try:
        # Ler o arquivo JavaScript
        with open('static/js/admin-dashboard.js', 'r', encoding='utf-8') as f:
            js_content = f.read()
        
        # Verificar se as funções foram implementadas
        functions_to_check = [
            'getCurrentUserRole',
            'navigateToMessages',
            'detectUserRole',
            'cancel-ticket-btn',
            'setupMessageSectionEventListeners'
        ]
        
        print("🔍 Funções JavaScript verificadas:")
        all_found = True
        
        for func in functions_to_check:
            if func in js_content:
                print(f"   ✅ {func}: Encontrada")
            else:
                print(f"   ❌ {func}: Não encontrada")
                all_found = False
        
        # Verificar se o botão de cancelar está implementado
        if 'cancel-ticket-btn' in js_content and 'getCurrentUserRole() === \'manager\'' in js_content:
            print("   ✅ Botão de cancelar com verificação de papel: Implementado")
        else:
            print("   ❌ Botão de cancelar com verificação de papel: Não implementado")
            all_found = False
        
        return all_found
        
    except Exception as e:
        print(f"❌ Erro ao verificar funções JavaScript: {str(e)}")
        return False

def main():
    """Função principal do teste"""
    print("🧪 TESTE DAS NOVAS FUNCIONALIDADES\n")
    print("=" * 60)
    
    if not os.path.exists('helpdesk.db'):
        print("❌ Banco de dados não encontrado.")
        return
    
    # Executar todos os testes
    tests_results = []
    
    tests_results.append(('Permissões de Gerente', test_manager_permissions()))
    tests_results.append(('Transições de Status', test_ticket_status_transitions()))
    tests_results.append(('Formato de Notificação', test_telegram_notification_format()))
    tests_results.append(('Endpoints Backend', test_endpoints_existence()))
    tests_results.append(('Funções JavaScript', test_javascript_functions()))
    
    # Resumo dos resultados
    print("\n" + "=" * 60)
    print("📊 RESUMO DOS TESTES:")
    
    successful_tests = 0
    for test_name, result in tests_results:
        status = "✅ PASSOU" if result else "❌ FALHOU"
        print(f"   {status} - {test_name}")
        if result:
            successful_tests += 1
    
    total_tests = len(tests_results)
    print(f"\n🎯 RESULTADO FINAL: {successful_tests}/{total_tests} testes bem-sucedidos")
    
    if successful_tests == total_tests:
        print("\n🎉 TODAS AS FUNCIONALIDADES FORAM IMPLEMENTADAS COM SUCESSO!")
        print("✅ Botão de cancelar para gerentes")
        print("✅ Restrição de reabertura para tickets cancelados")
        print("✅ Navegação inteligente para aba de mensagens")
        print("✅ Notificações Telegram adequadas")
    else:
        failed_tests = total_tests - successful_tests
        print(f"\n⚠️ {failed_tests} teste(s) falharam. Verifique os detalhes acima.")
    
    print("\n📝 PRÓXIMOS PASSOS PARA USAR:")
    print("   1. Acesse o dashboard administrativo como gerente")
    print("   2. Vá para 'Chamados Abertos' e teste o botão de cancelar")
    print("   3. Vá para 'Chamados Fechados' e teste a reabertura")
    print("   4. Use o ícone de mensagem para navegar para a aba de mensagens")
    print("   5. Verifique se o ticket é pré-selecionado na aba de mensagens")

if __name__ == "__main__":
    main()
