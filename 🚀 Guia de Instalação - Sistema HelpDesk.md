# 🚀 Guia de Instalação - Sistema HelpDesk

Este guia fornece instruções detalhadas para instalar e configurar o Sistema HelpDesk em diferentes ambientes.

## 📋 Requisitos do Sistema

### Requisitos Mínimos
- **Sistema Operacional**: Windows 10+, macOS 10.14+, ou Linux (Ubuntu 18.04+)
- **Python**: Versão 3.8 ou superior
- **RAM**: 512MB disponível
- **Espaço em Disco**: 100MB
- **Navegador**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+

### Requisitos Recomendados
- **Python**: Versão 3.11+
- **RAM**: 1GB disponível
- **Espaço em Disco**: 500MB

## 🔧 Instalação Passo a Passo

### 1. Preparação do Ambiente

#### No Windows:
```cmd
# Verificar versão do Python
python --version

# Se não tiver Python instalado, baixe de: https://python.org
```

#### No macOS:
```bash
# Verificar versão do Python
python3 --version

# Se não tiver Python instalado:
brew install python3
```

#### No Linux (Ubuntu/Debian):
```bash
# Atualizar repositórios
sudo apt update

# Instalar Python e pip
sudo apt install python3 python3-pip

# Verificar instalação
python3 --version
```

### 2. Download do Sistema

#### Opção A: Download Direto
1. Baixe todos os arquivos do sistema
2. Extraia em uma pasta de sua escolha (ex: `C:\helpdesk` ou `/home/usuario/helpdesk`)

#### Opção B: Clone do Repositório (se disponível)
```bash
git clone [URL_DO_REPOSITORIO] helpdesk
cd helpdesk
```

### 3. Instalação das Dependências

```bash
# Navegar para o diretório do projeto
cd helpdesk

# Instalar Flask (se não estiver instalado)
pip3 install flask

# Verificar instalação
python3 -c "import flask; print('Flask instalado com sucesso!')"
```

### 4. Configuração do Banco de Dados

```bash
# Executar script de inicialização do banco
python3 database.py
```

**Saída esperada:**
```
Banco de dados inicializado com sucesso!
Usuários de exemplo criados.
Tipos de chamados criados.
Status de chamados criados.
Chamados de exemplo criados.
```

### 5. Primeira Execução

```bash
# Iniciar o servidor
python3 app.py
```

**Saída esperada:**
```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://[SEU_IP]:5000
```

### 6. Verificação da Instalação

1. Abra seu navegador
2. Acesse: `http://localhost:5000`
3. Você deve ver a tela de login do sistema
4. Teste com as credenciais:
   - **Admin**: admin@example.com / admin
   - **Usuário**: joao@example.com / user123

## 🔧 Configurações Avançadas

### Configuração de Email (SMTP)

Para habilitar o envio de emails de recuperação de senha:

1. Edite o arquivo `app.py`
2. Localize a função `send_email()`
3. Configure suas credenciais SMTP:

```python
def send_email(to_email, subject, body):
    import smtplib
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    
    # Configurações SMTP
    smtp_server = "smtp.gmail.com"  # Para Gmail
    smtp_port = 587
    smtp_user = "seu-email@gmail.com"
    smtp_password = "sua-senha-de-app"  # Use senha de app, não a senha normal
    
    try:
        # Criar mensagem
        msg = MimeMultipart()
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MimeText(body, 'plain'))
        
        # Enviar email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Erro ao enviar email: {e}")
        return False
```

### Configuração de Segurança

Para ambiente de produção:

1. **Alterar Secret Key**:
```python
# No arquivo app.py, linha ~13
app.secret_key = 'sua-chave-super-secreta-e-aleatoria-aqui'
```

2. **Desabilitar Debug Mode**:
```python
# No final do arquivo app.py
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

3. **Configurar HTTPS** (recomendado para produção)

### Configuração de Porta Personalizada

Se a porta 5000 estiver em uso:

```python
# No arquivo app.py, última linha
app.run(host='0.0.0.0', port=8080, debug=True)  # Usar porta 8080
```

## 🐳 Instalação com Docker (Opcional)

Se preferir usar Docker:

1. **Criar Dockerfile**:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install flask

EXPOSE 5000

CMD ["python", "app.py"]
```

2. **Construir e executar**:
```bash
docker build -t helpdesk .
docker run -p 5000:5000 helpdesk
```

## 🌐 Configuração para Rede Local

Para acessar o sistema de outros computadores na rede:

1. **Descobrir seu IP local**:
```bash
# Windows
ipconfig

# macOS/Linux
ifconfig
# ou
ip addr show
```

2. **Configurar firewall** (se necessário):
   - Windows: Permitir porta 5000 no Windows Defender
   - macOS: Sistema > Segurança > Firewall
   - Linux: `sudo ufw allow 5000`

3. **Acessar de outros dispositivos**:
   - Use: `http://[SEU_IP]:5000`
   - Exemplo: `http://192.168.1.100:5000`

## 🔄 Backup e Restauração

### Fazer Backup
```bash
# Backup do banco de dados
cp helpdesk.db helpdesk_backup_$(date +%Y%m%d).db

# Backup completo do sistema
tar -czf helpdesk_backup_$(date +%Y%m%d).tar.gz .
```

### Restaurar Backup
```bash
# Restaurar banco de dados
cp helpdesk_backup_YYYYMMDD.db helpdesk.db

# Restaurar sistema completo
tar -xzf helpdesk_backup_YYYYMMDD.tar.gz
```

## 🚀 Executar como Serviço (Linux)

Para executar automaticamente no boot:

1. **Criar arquivo de serviço**:
```bash
sudo nano /etc/systemd/system/helpdesk.service
```

2. **Conteúdo do arquivo**:
```ini
[Unit]
Description=Sistema HelpDesk
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/caminho/para/helpdesk
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

3. **Ativar serviço**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable helpdesk
sudo systemctl start helpdesk
```

## 🔍 Solução de Problemas

### Problema: "Módulo flask não encontrado"
**Solução**:
```bash
pip3 install flask
# ou
python3 -m pip install flask
```

### Problema: "Porta 5000 já está em uso"
**Soluções**:
1. Alterar porta no código (ver seção de configuração)
2. Ou parar o processo que usa a porta:
```bash
# Encontrar processo
lsof -i :5000
# Parar processo
kill -9 [PID]
```

### Problema: "Permissão negada para helpdesk.db"
**Solução**:
```bash
chmod 666 helpdesk.db
# ou
sudo chown $USER:$USER helpdesk.db
```

### Problema: "Não consegue acessar de outros computadores"
**Verificações**:
1. Firewall configurado?
2. IP correto?
3. Aplicação rodando em `0.0.0.0` e não `127.0.0.1`?

## 📞 Suporte Técnico

Se encontrar problemas durante a instalação:

1. **Verifique os logs** no terminal onde executou `python3 app.py`
2. **Consulte este guia** novamente
3. **Entre em contato**:
   - Email: suporte@logverse.com
   - Telefone: (11) 1234-5678

## ✅ Checklist de Instalação

- [ ] Python 3.8+ instalado
- [ ] Flask instalado
- [ ] Arquivos do sistema baixados
- [ ] Banco de dados inicializado
- [ ] Sistema executando em localhost:5000
- [ ] Login testado com usuários de exemplo
- [ ] (Opcional) Email configurado
- [ ] (Opcional) Porta personalizada configurada
- [ ] (Opcional) Acesso de rede configurado

---

**Instalação concluída com sucesso! 🎉**

