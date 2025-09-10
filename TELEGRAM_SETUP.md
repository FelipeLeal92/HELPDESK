# 🤖 Configuração do Telegram para Notificações

Este guia explica como configurar notificações via Telegram no sistema HelpDesk.

## 📋 Pré-requisitos

1. **Telegram instalado** em seu dispositivo
2. **Conta no Telegram**
3. **Grupo do Telegram** criado para receber notificações

## 🔧 Passo a Passo

### 1️⃣ Criar um Bot no Telegram

1. Abra o Telegram e procure por `@BotFather`
2. Envie o comando `/newbot`
3. Escolha um nome para seu bot (ex: "HelpDesk Notificações")
4. Escolha um username para o bot (ex: "helpdesk_notifications_bot")
5. Copie o **token** fornecido (formato: `1234567890:AAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBB`)

### 2️⃣ Criar um Grupo e Adicionar o Bot

1. Crie um novo grupo no Telegram
2. Adicione o bot que você criou ao grupo
3. Envie uma mensagem qualquer no grupo
4. Para obter o ID do grupo, siga um destes métodos:

#### Método A: Bot GetUpdates
1. Envie uma mensagem no grupo mencionando o bot: `@seu_bot olá`
2. Acesse: `https://api.telegram.org/bot[SEU_TOKEN]/getUpdates`
3. Procure por `"chat":{"id":-1001234567890}` - esse é o ID do grupo

#### Método B: Bot IDBot
1. Adicione `@userinfobot` ao grupo
2. O bot enviará automaticamente o ID do grupo

### 3️⃣ Configurar no Sistema

1. Acesse **Dashboard Administrativo > Configurações**
2. Na seção **"Configurações de Notificações"**:
   - **Token do Bot**: Cole o token obtido no passo 1
   - **ID do Grupo**: Digite o ID do grupo (deve começar com -)
3. Clique em **"Testar Conexão"** para verificar se tudo está funcionando
4. Se o teste der certo, clique em **"Salvar Configurações"**

## 🎯 Funcionalidades

### Notificações Automáticas
O sistema enviará notificações para o grupo do Telegram quando:

- ✅ **Novo chamado** for criado
- 👤 **Chamado for atribuído** a um responsável
- 🔄 **Status do chamado** for alterado
- 🔓 **Chamado for reaberto**
- 📝 **Nova resposta** for adicionada

### Formato das Mensagens
As mensagens incluem:
- 🆔 **ID do chamado**
- 👤 **Nome do usuário**
- 📋 **Tipo do chamado**
- ⚡ **Prioridade**
- 📝 **Assunto**
- 🔄 **Tipo de evento**

## 🔒 Segurança

- ⚠️ **Token do bot**: Mantenha sempre seguro, não compartilhe
- 🔐 **Grupo privado**: Recomendamos usar um grupo privado apenas para admins
- 👥 **Permissões**: Certifique-se de que apenas administradores tenham acesso

## 🆘 Solução de Problemas

### ❌ "Token do bot inválido"
- Verifique se copiou o token completo
- Certifique-se de que não há espaços extras

### ❌ "Não foi possível enviar mensagem para o grupo"
- Verifique se o bot foi adicionado ao grupo
- Confirme se o ID do grupo está correto (deve começar com -)
- Certifique-se de que o bot tem permissão para enviar mensagens

### ❌ "Erro de conexão"
- Verifique sua conexão com a internet
- Certifique-se de que o Telegram não está bloqueado pela rede

## 📞 Suporte

Se precisar de ajuda, verifique:
1. Se o bot está ativo no grupo
2. Se as configurações estão salvas corretamente
3. Se o teste de conexão passou

---
*Sistema HelpDesk com notificações via Telegram* 🚀
