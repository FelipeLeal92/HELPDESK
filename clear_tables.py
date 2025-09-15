# clear_data.py
import requests
import json

def clear_tables():
    """Função para limpar as tabelas via API"""
    
    # URL do endpoint
    url = 'http://localhost:5000/api/dev/clear-tickets'
    
    # Headers (você precisa do cookie de sessão)
    headers = {
        'Content-Type': 'application/json',
        # Adicione seu cookie de sessão aqui
        'Cookie': '.eJw1jDEKgDAQBP9ytVhLKiu_EYJuwsHdRaKpxL9r0HQ7w7AX-R1Fg8FOcmepGIgPHzZl61wPFA8NLOQoqkiEpTk1Ma5Z6S94Izf924LijRcI7-hBydLk930_dfIqug.aMhdGw.19G5ItWYolEzIphQ3WZbEdSZJBs'
    }
    
    # Dados de confirmação
    data = {
        'confirm': True
    }
    
    try:
        print("Enviando requisição para limpar tabelas...")
        response = requests.post(url, headers=headers, json=data)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ Limpeza realizada com sucesso!")
            print(f"Mensagem: {result.get('message')}")
            
            if 'deleted_records' in result:
                print("\n📊 Registros excluídos:")
                for key, value in result['deleted_records'].items():
                    print(f"  - {key}: {value}")
        else:
            print(f"\n❌ Erro: {response.status_code}")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print("❌ Erro de conexão. Certifique-se de que o servidor Flask está rodando em http://localhost:5000")
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")

if __name__ == "__main__":
    # Confirmação extra de segurança
    confirm = input("⚠️  TEM CERTEZA QUE QUER LIMPAR TODOS OS DADOS DE CHAMADOS? (s/N): ")
    
    if confirm.lower() == 's':
        clear_tables()
    else:
        print("Operação cancelada.")