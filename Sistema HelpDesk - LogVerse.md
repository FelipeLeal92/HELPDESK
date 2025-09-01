# Sistema HelpDesk - LogVerse

Um sistema completo de HelpDesk desenvolvido em Python Flask com interface moderna e responsiva.

## 📋 Funcionalidades

### 🔐 Sistema de Autenticação
- Login seguro com validação de credenciais
- Funcionalidade "Lembrar-me" com cookies persistentes
- Recuperação de senha automática via email
- Redirecionamento automático baseado no tipo de usuário (Admin/Usuário)

### 👤 Dashboard do Usuário
- **Dashboard Principal**: Visualização de estatísticas pessoais de chamados
- **Gerenciamento de Chamados**: Visualizar, criar e acompanhar chamados
- **Abrir Chamados**: Formulário completo com tipos, prioridades e anexos
- **Configurações**: Gerenciar perfil, segurança e notificações
- **Central de Ajuda**: FAQ e informações de contato

### 👨‍💼 Dashboard Administrativo
- **Painel Principal**: Estatísticas gerais e chamados recentes
- **Chamados Abertos**: Gerenciar, responder e finalizar chamados
- **Chamados Fechados**: Histórico completo com filtros
- **Tipos de Chamados**: CRUD completo de categorias e status
- **Gerenciamento de Usuários**: Criar, editar e excluir usuários
- **Configurações**: Configurações gerais do sistema e email

## 🛠️ Tecnologias Utilizadas

- **Backend**: Python 3.11 + Flask
- **Banco de Dados**: SQLite3
- **Frontend**: HTML5 + TailwindCSS + JavaScript
- **Ícones**: Material Symbols
- **Responsividade**: Design mobile-first

## 📁 Estrutura do Projeto

```
helpdesk/
├── app.py                 # Aplicação Flask principal
├── database.py           # Configuração e inicialização do banco
├── helpdesk.db          # Banco de dados SQLite
├── templates/           # Templates HTML
│   ├── index.html       # Página de login
│   ├── recover.html     # Recuperação de senha
│   ├── dashboard-user.html    # Dashboard do usuário
│   └── dashboard-admin.html   # Dashboard administrativo
└── README.md           # Este arquivo
```

## 🚀 Como Executar

### Pré-requisitos
- Python 3.11 ou superior
- Flask (já instalado no ambiente)

### Instalação e Execução

1. **Clone ou baixe o projeto**
   ```bash
   # Se necessário, navegue até o diretório do projeto
   cd /caminho/para/helpdesk
   ```

2. **Inicialize o banco de dados** (se necessário)
   ```bash
   python3 database.py
   ```

3. **Execute a aplicação**
   ```bash
   python3 app.py
   ```

4. **Acesse o sistema**
   - Abra seu navegador e vá para: `http://localhost:5000`

## 👥 Usuários de Teste

O sistema vem com usuários pré-configurados para teste:

### Administrador
- **Email**: admin@example.com
- **Senha**: admin
- **Permissões**: Acesso completo ao sistema

### Usuário Comum
- **Email**: joao@example.com
- **Senha**: user123
- **Permissões**: Acesso ao dashboard do usuário

## 🗄️ Estrutura do Banco de Dados

### Tabelas Principais

#### `users`
- Armazena informações dos usuários
- Campos: id, name, email, password, phone, is_admin, created_at

#### `tickets`
- Armazena os chamados
- Campos: id, user_id, type, priority, subject, description, status, assigned_to, created_at, updated_at, closed_at

#### `ticket_types`
- Tipos de chamados configuráveis
- Campos: id, name, description, active

#### `ticket_statuses`
- Status dos chamados configuráveis
- Campos: id, name, color, active

#### `ticket_responses`
- Respostas e comentários dos chamados
- Campos: id, ticket_id, user_id, message, is_internal, created_at

#### `attachments`
- Anexos dos chamados
- Campos: id, ticket_id, response_id, filename, filepath, filesize, uploaded_at

## 🔧 Configuração

### Email (Recuperação de Senha)
Para configurar o envio de emails, edite a função `send_email()` no arquivo `app.py`:

```python
def send_email(to_email, subject, body):
    # Configure aqui suas credenciais SMTP
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "seu-email@gmail.com"
    smtp_password = "sua-senha-app"
    
    # Implementação do envio de email
```

### Segurança
Para produção, altere a `secret_key` no arquivo `app.py`:

```python
app.secret_key = 'sua-chave-secreta-super-segura'
```

## 📱 Funcionalidades por Tela

### Página de Login (`/`)
- Formulário de autenticação
- Checkbox "Lembrar-me"
- Link para recuperação de senha
- Usuários de teste listados para facilitar acesso

### Dashboard do Usuário (`/user/dashboard`)
- **Dashboard**: Estatísticas pessoais (total, atendidos, pendentes, tempo médio)
- **Chamados**: Lista de chamados do usuário com filtros
- **Abrir Chamado**: Formulário completo com upload de arquivos
- **Configurações**: Perfil, segurança e notificações
- **Central de Ajuda**: FAQ e contatos de suporte

### Dashboard Administrativo (`/admin/dashboard`)
- **Painel Principal**: Estatísticas gerais e chamados recentes
- **Chamados Abertos**: Gerenciamento completo com ações (responder, ver detalhes, anexos, finalizar)
- **Chamados Fechados**: Histórico com filtros por data
- **Tipos de Chamados**: CRUD de categorias e status
- **Usuários**: Gerenciamento completo de usuários
- **Configurações**: Configurações do sistema

## 🔄 API Endpoints

### Autenticação
- `POST /login` - Fazer login
- `GET /logout` - Fazer logout
- `POST /recover` - Recuperar senha

### Chamados (API)
- `GET /api/tickets` - Listar chamados
- `POST /api/tickets` - Criar chamado

### Administração (API)
- `GET /api/admin/stats` - Estatísticas gerais
- `GET /api/admin/tickets/recent` - Chamados recentes
- `GET /api/admin/users` - Listar usuários
- `POST /api/admin/users` - Criar usuário
- `PUT /api/admin/users/<id>` - Atualizar usuário
- `DELETE /api/admin/users/<id>` - Excluir usuário
- `PUT /api/admin/tickets/<id>/status` - Atualizar status do chamado

## 🎨 Design e UX

- **Design Responsivo**: Funciona perfeitamente em desktop, tablet e mobile
- **Interface Moderna**: Utiliza TailwindCSS para um design limpo e profissional
- **Navegação Intuitiva**: Sidebar com ícones e navegação clara
- **Feedback Visual**: Estados de hover, loading e feedback de ações
- **Acessibilidade**: Estrutura semântica e contraste adequado

## 🔒 Segurança

- Validação de entrada em todos os formulários
- Proteção contra SQL Injection (uso de prepared statements)
- Sessões seguras com timeout
- Validação de permissões em todas as rotas administrativas
- Hash de senhas (implementação básica - recomenda-se bcrypt para produção)

## 📈 Melhorias Futuras

- Implementação de hash bcrypt para senhas
- Sistema de notificações em tempo real
- Upload real de arquivos
- Relatórios avançados com gráficos
- Sistema de SLA (Service Level Agreement)
- Integração com sistemas externos
- API REST completa
- Testes automatizados

## 🐛 Solução de Problemas

### Erro de Banco de Dados
Se houver problemas com o banco, execute:
```bash
python3 database.py
```

### Porta em Uso
Se a porta 5000 estiver em uso, altere no `app.py`:
```python
app.run(host='0.0.0.0', port=5001, debug=True)
```

### Problemas de Permissão
Certifique-se de que o arquivo `helpdesk.db` tem permissões de escrita.

## 📞 Suporte

Para dúvidas ou problemas:
- Email: suporte@logverse.com
- Telefone: (11) 1234-5678

---

**Desenvolvido com ❤️ para LogVerse**

