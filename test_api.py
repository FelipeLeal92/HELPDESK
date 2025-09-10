#!/usr/bin/env python3
"""
Script para testar as APIs do dashboard admin
"""
import requests
import json

# URL base da aplicação
BASE_URL = "http://127.0.0.1:5000"

def test_api_endpoint(endpoint, description):
    """Testa um endpoint da API"""
    print(f"\n🔍 Testando: {description}")
    print(f"📡 Endpoint: {endpoint}")
    
    try:
        # Primeiro, vamos fazer login para obter uma sessão
        session = requests.Session()
        
        # Fazer login como admin
        login_data = {
            'email': 'admin@example.com',
            'password': 'admin'
        }
        
        login_response = session.post(f"{BASE_URL}/login", data=login_data)
        
        if login_response.status_code != 200:
            print(f"❌ Erro no login: {login_response.status_code}")
            return False
            
        # Agora testar o endpoint
        response = session.get(f"{BASE_URL}{endpoint}")
        
        print(f"📊 Status Code: {response.status_code}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"✅ Sucesso! Dados recebidos:")
                print(json.dumps(data, indent=2, ensure_ascii=False))
                return True
            except json.JSONDecodeError:
                print(f"⚠️  Resposta não é JSON válido: {response.text[:200]}")
                return False
        else:
            print(f"❌ Erro: {response.status_code}")
            print(f"📝 Resposta: {response.text[:200]}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Erro de conexão - Verifique se a aplicação está rodando")
        return False
    except Exception as e:
        print(f"❌ Erro inesperado: {str(e)}")
        return False

def main():
    print("🚀 Testando APIs do Dashboard Admin")
    print("=" * 50)
    
    # Lista de endpoints para testar
    endpoints = [
        ("/api/admin/stats", "Estatísticas do Dashboard"),
        ("/api/admin/tickets/recent", "Tickets Recentes"),
        ("/api/admin/users", "Lista de Usuários"),
        ("/api/tickets", "Lista de Tickets"),
        ("/api/ticket-types", "Tipos de Tickets"),
        ("/api/ticket-statuses", "Status de Tickets")
    ]
    
    results = []
    
    for endpoint, description in endpoints:
        success = test_api_endpoint(endpoint, description)
        results.append((endpoint, description, success))
    
    # Resumo dos resultados
    print("\n" + "=" * 50)
    print("📋 RESUMO DOS TESTES")
    print("=" * 50)
    
    success_count = 0
    for endpoint, description, success in results:
        status = "✅ OK" if success else "❌ FALHOU"
        print(f"{status} {description}")
        if success:
            success_count += 1
    
    print(f"\n📊 Resultado: {success_count}/{len(results)} testes passaram")
    
    if success_count == len(results):
        print("🎉 Todos os testes passaram! O problema pode estar no frontend.")
    else:
        print("⚠️  Alguns testes falharam. Verifique os erros acima.")

if __name__ == "__main__":
    main()