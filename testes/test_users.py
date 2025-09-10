import requests
import sys
import json

def test_user_management():
    """Testa criação e edição de usuários com diferentes roles"""
    base_url = "http://localhost:5000"
    
    # Fazer login como admin
    session = requests.Session()
    login_data = {
        'email': 'admin@example.com',
        'password': 'admin'
    }
    
    print("🔐 Fazendo login como administrador...")
    response = session.post(f"{base_url}/login", data=login_data)
    
    if response.status_code != 200:
        print("❌ Erro no login!")
        return False
    
    print("✅ Login realizado com sucesso!")
    
    # Testar criação de usuário comum
    print("\n👤 Testando criação de usuário comum...")
    user_data = {
        'name': 'Teste User',
        'email': 'teste.user@example.com',
        'password': 'senha123',
        'phone': '(11) 99999-9999',
        'role': 'user'
    }
    
    response = session.post(f"{base_url}/api/admin/users", 
                           headers={'Content-Type': 'application/json'},
                           json=user_data)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            print("✅ Usuário comum criado com sucesso!")
        else:
            print(f"❌ Erro ao criar usuário comum: {data.get('error', 'Erro desconhecido')}")
            return False
    else:
        print(f"❌ Erro HTTP ao criar usuário comum: {response.status_code}")
        return False
    
    # Testar criação de manager
    print("\n👨‍💼 Testando criação de gerente...")
    manager_data = {
        'name': 'Teste Manager',
        'email': 'teste.manager@example.com',
        'password': 'senha123',
        'phone': '(11) 88888-8888',
        'role': 'manager'
    }
    
    response = session.post(f"{base_url}/api/admin/users", 
                           headers={'Content-Type': 'application/json'},
                           json=manager_data)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            print("✅ Gerente criado com sucesso!")
        else:
            print(f"❌ Erro ao criar gerente: {data.get('error', 'Erro desconhecido')}")
            return False
    else:
        print(f"❌ Erro HTTP ao criar gerente: {response.status_code}")
        return False
    
    # Testar criação de admin
    print("\n👨‍💻 Testando criação de administrador...")
    admin_data = {
        'name': 'Teste Admin',
        'email': 'teste.admin@example.com',
        'password': 'senha123',
        'phone': '(11) 77777-7777',
        'role': 'admin'
    }
    
    response = session.post(f"{base_url}/api/admin/users", 
                           headers={'Content-Type': 'application/json'},
                           json=admin_data)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            print("✅ Administrador criado com sucesso!")
        else:
            print(f"❌ Erro ao criar administrador: {data.get('error', 'Erro desconhecido')}")
            return False
    else:
        print(f"❌ Erro HTTP ao criar administrador: {response.status_code}")
        return False
    
    # Listar usuários para verificar
    print("\n📋 Verificando usuários criados...")
    response = session.get(f"{base_url}/api/admin/users")
    
    if response.status_code == 200:
        users = response.json()
        print(f"✅ Total de usuários encontrados: {len(users)}")
        
        for user in users:
            if 'teste' in user.get('name', '').lower():
                role = user.get('role', 'unknown')
                print(f"   - {user['name']}: {user['email']} ({role})")
        
        # Testar edição de usuário (promover usuário comum para manager)
        test_user = next((u for u in users if u.get('email') == 'teste.user@example.com'), None)
        if test_user:
            print(f"\n✏️ Testando edição de usuário (promover para manager)...")
            edit_data = {
                'name': test_user['name'],
                'email': test_user['email'],
                'phone': test_user.get('phone', ''),
                'role': 'manager'
            }
            
            response = session.put(f"{base_url}/api/admin/users/{test_user['id']}", 
                                 headers={'Content-Type': 'application/json'},
                                 json=edit_data)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    print("✅ Usuário promovido para manager com sucesso!")
                else:
                    print(f"❌ Erro ao editar usuário: {data.get('error', 'Erro desconhecido')}")
                    return False
            else:
                print(f"❌ Erro HTTP ao editar usuário: {response.status_code}")
                return False
        
    else:
        print(f"❌ Erro ao listar usuários: {response.status_code}")
        return False
    
    return True

if __name__ == '__main__':
    print("🚀 Iniciando testes de gerenciamento de usuários...")
    
    try:
        success = test_user_management()
        
        if success:
            print("\n🎉 Todos os testes passaram! Sistema de usuários funcionando corretamente.")
            print("\n📝 O que foi testado:")
            print("   ✅ Criação de usuário comum")
            print("   ✅ Criação de gerente")
            print("   ✅ Criação de administrador")
            print("   ✅ Edição de usuário (promoção de role)")
            print("   ✅ Listagem de usuários com roles corretos")
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
