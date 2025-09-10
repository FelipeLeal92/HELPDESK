import requests
import sys

def test_admin_auth():
    """Testa se as rotas administrativas funcionam corretamente após login"""
    base_url = "http://localhost:5000"
    
    # Iniciar sessão
    session = requests.Session()
    
    # Fazer login como admin
    login_data = {
        'email': 'admin@example.com',
        'password': 'admin'
    }
    
    print("🔐 Testando login como administrador...")
    response = session.post(f"{base_url}/login", data=login_data)
    
    if response.status_code != 200:
        print("❌ Erro no login!")
        return False
    
    print("✅ Login realizado com sucesso!")
    
    # Testar rotas administrativas que estavam falhando
    admin_routes = [
        '/api/admin/stats',
        '/api/admin/tickets/recent',
        '/api/admin/users',
        '/api/admin/settings'
    ]
    
    print("\n🧪 Testando rotas administrativas...")
    
    for route in admin_routes:
        print(f"   Testando {route}...")
        response = session.get(f"{base_url}{route}")
        
        if response.status_code == 200:
            print(f"   ✅ {route} - OK")
        elif response.status_code == 401:
            print(f"   ❌ {route} - 401 Unauthorized (ainda falhando!)")
            return False
        else:
            print(f"   ⚠️ {route} - Status {response.status_code}")
    
    print("\n✨ Todos os testes passaram! As correções funcionaram.")
    return True

def test_user_auth():
    """Testa se um usuário comum não consegue acessar rotas admin"""
    base_url = "http://localhost:5000"
    
    # Iniciar sessão
    session = requests.Session()
    
    # Fazer login como usuário comum
    login_data = {
        'email': 'joao@example.com',
        'password': 'user123'
    }
    
    print("\n👤 Testando login como usuário comum...")
    response = session.post(f"{base_url}/login", data=login_data)
    
    if response.status_code != 200:
        print("❌ Erro no login do usuário!")
        return False
    
    print("✅ Login de usuário realizado com sucesso!")
    
    # Testar que usuário comum não pode acessar rotas admin
    admin_routes = ['/api/admin/stats', '/api/admin/users']
    
    print("🔒 Testando se usuário comum não acessa rotas admin...")
    
    for route in admin_routes:
        response = session.get(f"{base_url}{route}")
        
        if response.status_code == 401:
            print(f"   ✅ {route} - 401 (correto, usuário comum bloqueado)")
        else:
            print(f"   ❌ {route} - Status {response.status_code} (usuário comum deveria ser bloqueado!)")
            return False
    
    return True

if __name__ == '__main__':
    print("🚀 Iniciando testes de autenticação...")
    
    try:
        # Testar admin
        admin_ok = test_admin_auth()
        
        # Testar usuário comum
        user_ok = test_user_auth()
        
        if admin_ok and user_ok:
            print("\n🎉 Todos os testes passaram! Sistema funcionando corretamente.")
            sys.exit(0)
        else:
            print("\n❌ Alguns testes falharam.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("❌ Erro: Não foi possível conectar ao servidor.")
        print("   Certifique-se de que o servidor está rodando em http://localhost:5000")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro inesperado: {str(e)}")
        sys.exit(1)
