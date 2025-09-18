# HelpDesk_LogTudo

## Executar localmente

1. Pré-requisitos
   - Python 3.13 (ou 3.11+)
   - (Opcional) virtualenv
   - SQLite (já embutido) ou PostgreSQL disponível

2. Clonar e instalar dependências
   ```bash
   # Windows PowerShell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Configurar variáveis de ambiente
   Crie um arquivo `.env` na raiz com, no mínimo:
   ```ini
   FLASK_ENV=development
   SECRET_KEY=troque-isto
   # Use SQLite local
   DATABASE_URL=sqlite:///helpdesk.db
   # ou PostgreSQL
   # DATABASE_URL=postgresql+psycopg2://user:password@host:5432/dbname
   # Em produção, sslmode=require é forçado pelo código.

   # Telegram (opcional)
   TELEGRAM_BOT_TOKEN=
   TELEGRAM_GROUP_ID=
   TELEGRAM_TOPIC_NEW_TICKETS=
   TELEGRAM_TOPIC_MESSAGES=
   TELEGRAM_TOPIC_ASSIGNMENTS=
   TELEGRAM_TOPIC_CLOSED=
   TELEGRAM_TOPIC_CANCELLED=
   ```

4. Inicializar base de dados
   - Se ainda não existir `helpdesk.db`:
   ```bash
   python check_db.py
   python seed_admin.py
   python add_ticket_types.py
   ```

5. Rodar a aplicação (dev)
   ```bash
   python app.py
   ```
   - Acesse http://127.0.0.1:5000
   - Health check: http://127.0.0.1:5000/healthz

6. Testes
   ```bash
   python run_tests.py
   ```

## Deploy (Guia)

A aplicação é Flask + SQLite/PostgreSQL, com uploads (pasta `uploads/`) e integrações com Telegram. A melhor plataforma recomendada para este perfil (estado simples, HTTP + long-polling/eventos curtos, necessidade de volume para uploads) é um container em serviço gerenciado. Duas opções práticas:

### Opção A: Fly.io (container simples com volume)

1. Requisitos
   - `flyctl` instalado
   - Conta Fly.io

2. Build & Deploy
   ```bash
   # Local: gerar imagem usando Dockerfile
   docker build -t helpdesk:latest .
   ```
   Em seguida crie o app no Fly e um volume para `uploads`:
   ```bash
   fly launch --no-deploy
   fly volumes create uploads --size 1 --region iad
   ```
   Configure secrets (substitua valores):
   ```bash
   fly secrets set SECRET_KEY=... DATABASE_URL=postgresql+psycopg2://... TELEGRAM_BOT_TOKEN=... TELEGRAM_GROUP_ID=...
   ```
   Monte o volume no `fly.toml` (exemplo):
   ```toml
   [mounts]
   source = "uploads"
   destination = "/app/uploads"
   ```
   Faça o deploy:
   ```bash
   fly deploy
   ```

3. Observações
   - O Dockerfile já inicia o Gunicorn em 0.0.0.0:8000
   - Configure Postgres gerenciado do Fly ou outro provedor. O código força `sslmode=require`.

### Opção B: Railway (deploy de Docker com volume persistente)

1. Requisitos
   - Conta Railway

2. Passos
   - Crie um novo projeto a partir do repositório.
   - Configure variáveis: `SECRET_KEY`, `DATABASE_URL`, tokens do Telegram.
   - Configure serviço para construir via Dockerfile.
   - Adicione Volume e monte em `/app/uploads`.

3. Observações
   - Caso use Railway Postgres, use a `DATABASE_URL` fornecida. SSL é exigido pelo app.

### Banco de dados
- Desenvolvimento: SQLite local (`helpdesk.db`).
- Produção: PostgreSQL gerenciado (Fly Postgres, Railway Postgres, RDS, etc.).
- Migração: script `migrar_sqlite_para_postgre.py` pode auxiliar a migração.

### Variáveis de ambiente principais
- `SECRET_KEY` (obrigatória)
- `DATABASE_URL` (SQLite ou Postgres)
- `TELEGRAM_*` (opcional)

### Segurança
- App configura headers de segurança, limita Tamanho de Upload (10MB) e cookies seguros.
- Container roda como usuário não-root.

### Logs e Saúde
- Acesso a logs conforme plataforma (fly logs / railway logs).
- Healthcheck HTTP em `/healthz`.

## Otimizações de Frontend já aplicadas
- Escapagem de HTML nas listagens para evitar XSS.
- Transições suaves entre seções com Tailwind (aplicar classes de `transition-opacity` ao alternar abas via JS, se necessário).
- Remoção de logs de console sensíveis.

## Dúvidas
Se precisar, abra um issue ou peça para ajustar CSP/CDNs e tuning de performance (threads do Gunicorn, workers, etc.).