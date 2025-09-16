// static/js/user-dashboard.js
const UserDashboard = (function() {
    // Variáveis privadas
    let allUserTickets = [];
    let recentTickets = [];
    let currentPage = 1;
    let ticketsPerPage = 5;
    let currentSupportTicket = null;
    let evtSource = null;

    let sortState = {
    recent: { column: null, direction: 'asc' },
    all: { column: null, direction: 'asc' }
};

    function _createComparer(column, direction) {
        return (a, b) => {
            let valueA = a[column];
            let valueB = b[column];
            
            // Tratar casos especiais
            if (column === 'created_at') {
                valueA = new Date(valueA);
                valueB = new Date(valueB);
            }
            
            // Comparação
            if (valueA < valueB) return direction === 'asc' ? -1 : 1;
            if (valueA > valueB) return direction === 'asc' ? 1 : -1;
            return 0;
        };
    }

    function sortTable(column, tableType) {
        // Determinar a direção da ordenação
        let direction = 'asc';
        if (sortState[tableType].column === column) {
            direction = sortState[tableType].direction === 'asc' ? 'desc' : 'asc';
        }
        
        // Atualizar o estado da ordenação
        sortState[tableType].column = column;
        sortState[tableType].direction = direction;
        
        // Atualizar os indicadores de ordenação
        document.querySelectorAll(`[id^="sort-"][id$="-${tableType}"]`).forEach(span => {
            span.textContent = '↕';
        });
        
        const sortIndicator = document.getElementById(`sort-${column}-${tableType}`);
        if (sortIndicator) {
            sortIndicator.textContent = direction === 'asc' ? '↑' : '↓';
        }
        
        // Ordenar e renderizar
        if (tableType === 'recent') {
            recentTickets.sort(_createComparer(column, direction));
            renderRecentTickets();
        } else if (tableType === 'all') {
            allUserTickets.sort(_createComparer(column, direction));
            renderAllTickets();
        }
        bindTicketRowActions(); // Re-bind actions after re-rendering
    }

    // Função de navegação entre seções
    function showSection(sectionName, event) {
      const originalShowSection = window.showSection;
      window.showSection = function(sectionName, event) {
          originalShowSection(sectionName, event);
          if (sectionName === 'dashboard') {
            loadTicketsForSupportSelect();
          }
      };  
      
      const ev = event || window.event;
        if (ev && typeof ev.preventDefault === 'function') ev.preventDefault();
        
        // Hide all sections
        const sections = ['dashboard', 'tickets', 'new-ticket', 'settings', 'help'];
        sections.forEach(section => {
            const el = document.getElementById(section + '-section'); 
            if (el) el.classList.add('hidden');
        });
        
        // Show selected section
        const target = document.getElementById(sectionName + '-section'); 
        if (target) target.classList.remove('hidden');
        
        // Update page title
        const titles = {
            'dashboard': 'Dashboard',
            'tickets': 'Meus Chamados',
            'new-ticket': 'Abrir Chamado',
            'settings': 'Configurações',
            'help': 'Central de Ajuda'
        };
        const titleEl = document.getElementById('page-title'); 
        if (titleEl) titleEl.textContent = titles[sectionName];
        
        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('bg-primary-50', 'text-primary-600');
            link.classList.add('hover:bg-primary-50');
        });
        const clickedLink = document.querySelector(`[data-section="${sectionName}"]`);
        if (clickedLink) {
            clickedLink.classList.add('bg-primary-50', 'text-primary-600');
            clickedLink.classList.remove('hover:bg-primary-50');
        }
        
        // Bind FAQs when opening Help
        if (sectionName === 'help') bindFAQToggles();
        
        // Reload tickets when navigating to Dashboard or Tickets
        if (sectionName === 'dashboard' || sectionName === 'tickets') {
            loadTickets();
        }
    }

    function showSettingsTab(tabName, event) {
        const ev = event || window.event;
        if (ev && typeof ev.preventDefault === 'function') ev.preventDefault();
        
        // Hide all settings tabs
        const tabs = ['profile', 'security', 'notifications'];
        tabs.forEach(tab => {
            const tabElement = document.getElementById(tab + '-settings');
            if (tabElement) {
                tabElement.classList.add('hidden');
            }
        });
        
        // Show selected tab
        const selectedTab = document.getElementById(tabName + '-settings');
        if (selectedTab) {
            selectedTab.classList.remove('hidden');
        }
        
        // Update tab navigation
        document.querySelectorAll('.settings-tab').forEach(tab => {
            tab.classList.remove('border-primary-500', 'text-primary-600');
            tab.classList.add('border-transparent', 'text-gray-500');
        });
        
        if (ev && ev.target) {
            ev.target.classList.add('border-primary-500', 'text-primary-600');
            ev.target.classList.remove('border-transparent', 'text-gray-500');
        }
    }

    // Funções de carregamento de dados
    function loadTickets() {
        fetch('/api/tickets')
            .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar tickets'))
            .then(tickets => {
                if (!Array.isArray(tickets)) tickets = [];
                allUserTickets = [...tickets];
                recentTickets = [...tickets];

                // Re-apply sorting if a sort order is set
                if (sortState.recent.column) {
                    recentTickets.sort(_createComparer(sortState.recent.column, sortState.recent.direction));
                }
                if (sortState.all.column) {
                    allUserTickets.sort(_createComparer(sortState.all.column, sortState.all.direction));
                }

                updateDashboardStats(tickets);
                renderTicketsTable();
                updatePagination();
                bindTicketRowActions();
            })
            .catch(error => console.error('Error loading tickets:', error));
    }

    function loadTicketTypes() {
        fetch('/api/ticket-types')
            .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar tipos de chamados'))
            .then(types => {
                if (!Array.isArray(types)) types = [];
                updateTicketTypeSelect(types);
            })
            .catch(error => console.error('Error loading ticket types:', error));
    }

    function loadTicketsForSupportSelect() {
        fetch('/api/tickets')
            .then(response => response.json())
            .then(tickets => {
                const select = document.getElementById('support-ticket-select');
                if (select) {
                    select.innerHTML = '<option value="">Selecione um ticket</option>';
                    tickets.forEach(ticket => {
                        const option = document.createElement('option');
                        option.value = ticket.id;
                        option.textContent = `#${ticket.id} - ${ticket.subject || ticket.description.substring(0, 30) + '...'}`;
                        select.appendChild(option);
                    });
                }
            })
            .catch(error => console.error('Error loading tickets for support select:', error));
    }

    function loadSupportMessages(ticketId) {
        if (!ticketId) {
            const container = document.getElementById('support-messages-container');
            if (container) {
                container.innerHTML = '<div class="text-center text-gray-500 py-8">Selecione um ticket para ver as mensagens.</div>';
            }
            return;
        }

        fetch(`/api/tickets/${ticketId}/responses`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                renderSupportMessages(data);
            })
            .catch(error => {
                console.error('Error loading support messages:', error);
                const container = document.getElementById('support-messages-container');
                if (container) {
                    container.innerHTML = '<div class="text-center text-red-500 py-8">Erro ao carregar mensagens.</div>';
                }
            });
    }

    // Funções de renderização
    function updateDashboardStats(tickets) {
        const total = tickets.length;
        const resolved = tickets.filter(t => t.status === 'Resolvido' || t.status === 'Fechado').length;
        const pending = tickets.filter(t => t.status === 'Aberto' || t.status === 'Pendente').length;
        
        document.getElementById('total-tickets').textContent = total;
        document.getElementById('resolved-tickets').textContent = resolved;
        document.getElementById('pending-tickets').textContent = pending;
    }

    function renderTicketsTable() {
        renderRecentTickets();
        renderAllTickets();
    }

    function renderRecentTickets() {
        const tbody = document.getElementById('tickets-tbody');
        if (!tbody) return;
        
        // Calcular o índice inicial e final para a página atual
        const startIndex = (currentPage - 1) * ticketsPerPage;
        const endIndex = startIndex + ticketsPerPage;
        const ticketsToShow = recentTickets.slice(startIndex, endIndex);
        
        tbody.innerHTML = ticketsToShow.map(ticket => `
            <tr class="border-b hover:bg-gray-50 transition-colors">
                <td class="py-3 px-4">#${ticket.id}</td>
                <td class="py-3 px-4">${ticket.type}</td>
                <td class="py-3 px-4">${ticket.priority}</td>
                <td class="py-3 px-4">
                    <span class="px-2 py-1 rounded-full text-xs ${Common.getStatusColor(ticket.status)}">${ticket.status}</span>
                </td>
                <td class="py-3 px-4">${Common.formatDate(ticket.created_at)}</td>
                <td class="py-3 px-4">
                    <button class="view-ticket-btn p-1 hover:bg-gray-100 rounded-full transition-colors" data-ticket-id="${ticket.id}">
                        <span class="material-symbols-outlined text-gray-600">visibility</span>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    function renderAllTickets() {
        const allTbody = document.getElementById('all-tickets-tbody');
        if (!allTbody) return;
        
        allTbody.innerHTML = allUserTickets.map(ticket => `
            <tr class="border-b hover:bg-gray-50 transition-colors">
                <td class="py-3 px-4">#${ticket.id}</td>
                <td class="py-3 px-4">${ticket.subject || (ticket.description ? ticket.description.substring(0, 50) + '...' : '')}</td>
                <td class="py-3 px-4">${ticket.type}</td>
                <td class="py-3 px-4">${ticket.priority}</td>
                <td class="py-3 px-4">
                    <span class="px-2 py-1 rounded-full text-xs ${Common.getStatusColor(ticket.status)}">${ticket.status}</span>
                </td>
                <td class="py-3 px-4">${ticket.created_at ? Common.formatDate(ticket.created_at) : ''}</td>
                <td class="py-3 px-4">
                    <button class="view-ticket-btn p-1 hover:bg-gray-100 rounded-full transition-colors" data-ticket-id="${ticket.id}">
                        <span class="material-symbols-outlined text-gray-600">visibility</span>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    function updatePagination() {
        const showingCount = document.getElementById('showing-tickets-count');
        const totalCount = document.getElementById('total-tickets-count');
        const prevButton = document.getElementById('prev-page-btn');
        const nextButton = document.getElementById('next-page-btn');
        
        if (!showingCount || !totalCount || !prevButton || !nextButton) return;
        
        const totalPages = Math.ceil(recentTickets.length / ticketsPerPage);
        const startItem = (currentPage - 1) * ticketsPerPage + 1;
        const endItem = Math.min(currentPage * ticketsPerPage, recentTickets.length);
        
        showingCount.textContent = `${startItem}-${endItem}`;
        totalCount.textContent = recentTickets.length;
        
        prevButton.disabled = currentPage <= 1;
        nextButton.disabled = currentPage >= totalPages;
    }

    function updateTicketTypeSelect(types) {
        const select = document.getElementById('ticket-type');
        if (!select) return;
        
        // Manter apenas a opção padrão
        select.innerHTML = '<option value="">Selecione um tipo</option>';
        
        // Adicionar os tipos de chamados da API
        types.forEach(type => {
            const option = document.createElement('option');
            option.value = type.name;
            option.textContent = type.name;
            select.appendChild(option);
        });
    }

    function renderSupportMessages(messages) {
        const container = document.getElementById('support-messages-container');
        if (!container) return;
        
        if (messages.length === 0) {
            container.innerHTML = '<div class="text-center text-gray-500 py-8">Nenhuma mensagem encontrada para este ticket.</div>';
            return;
        }

        container.innerHTML = messages.map(message => {
            const isAdmin = message.user_role === 'admin';
            const messageClass = isAdmin ? 'bg-primary-100 text-primary-800' : 'bg-gray-100 text-gray-800';
            const alignmentClass = isAdmin ? 'justify-end' : 'justify-start';
            const avatar = isAdmin 
                ? `
                    <div class="h-10 w-10 rounded-full bg-primary-500 text-white flex items-center justify-center flex-shrink-0">
                        <span class="material-symbols-outlined text-sm">support_agent</span>
                    </div>
                `
                : `
                    <div class="h-10 w-10 rounded-full bg-blue-500 text-white flex items-center justify-center flex-shrink-0">
                        <span class="material-symbols-outlined text-sm">person</span>
                    </div>
                `;

            return `
                <div class="flex items-start space-x-3 mb-4 ${alignmentClass}">
                    ${!isAdmin ? avatar : ''}
                    <div class="${messageClass} rounded-lg p-3 max-w-xs md:max-w-md">
                        <div class="font-medium text-sm">${message.user_name} ${isAdmin ? '(Suporte)' : '(Você)'}</div>
                        <p class="text-sm mt-1">${message.message}</p>
                        <div class="text-xs opacity-70 mt-2 text-right">${Common.formatDate(message.created_at)}</div>
                    </div>
                    ${isAdmin ? avatar : ''}
                </div>
            `;
        }).join('');

        // Rolar para o final
        container.scrollTop = container.scrollHeight;
    }

    // Funções de eventos
    function bindTicketRowActions() {
        document.querySelectorAll('.view-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                if (!ticketId) return;
                
                fetch(`/api/tickets/${ticketId}`)
                    .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar detalhes'))
                    .then(ticket => openTicketModal(ticket))
                    .catch(err => Common.showToast(err));
            });
        });
    }

    function bindFAQToggles() {
        const list = document.getElementById('faq-list');
        if (!list) return;
        
        // Avoid rebinding
        if (list.dataset.bound === '1') return; 
        list.dataset.bound = '1';
        
        list.addEventListener('click', (e) => {
            const btn = e.target.closest('.faq-toggle');
            if (!btn) return;
            
            const item = btn.closest('.faq-item');
            const answer = item.querySelector('.faq-answer');
            const icon = btn.querySelector('.faq-icon');
            const expanded = btn.getAttribute('aria-expanded') === 'true';
            
            // Fechar outras perguntas ao abrir uma nova
            document.querySelectorAll('#faq-list .faq-toggle[aria-expanded="true"]').forEach(openBtn => {
                if (openBtn !== btn) {
                    openBtn.setAttribute('aria-expanded', 'false');
                    const openItem = openBtn.closest('.faq-item');
                    const openAnswer = openItem.querySelector('.faq-answer');
                    const openIcon = openBtn.querySelector('.faq-icon');
                    openAnswer.classList.add('hidden');
                    if (openIcon) openIcon.style.transform = 'rotate(0deg)';
                }
            });
            
            // Toggle atual
            btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
            answer.classList.toggle('hidden', expanded);
            if (icon) icon.style.transform = expanded ? 'rotate(0deg)' : 'rotate(180deg)';
        });
    }

    function initContactCard() {
        const toggleBtn = document.getElementById('contact-button');
        const card = document.getElementById('contact-card');
        const container = document.getElementById('contact-container');
        
        if (!toggleBtn || !card || !container) return;
        
        const openCard = () => card.classList.remove('hidden');
        const closeCard = () => card.classList.add('hidden');
        const toggleCard = () => card.classList.toggle('hidden');
        
        // apply spacing class to buttons (avoid overlap)
        card.querySelectorAll('.contact-whatsapp').forEach(btn => {
            btn.classList.add('space-y-2');
        });
        
        // Alterna visibilidade do card
        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleCard();
        });
        
        // Evita fechar ao clicar dentro do card
        card.addEventListener('click', (e) => e.stopPropagation());
        container.addEventListener('click', (e) => e.stopPropagation());
        
        // Clique fora fecha
        document.addEventListener('click', () => closeCard());
        
        // Tecla Esc fecha
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeCard();
        });
        
        // Clique em um contato abre o WhatsApp do número escolhido
        card.addEventListener('click', (e) => {
            const btn = e.target.closest('.contact-whatsapp');
            if (!btn) return;
            
            const number = btn.dataset.number; // incluir DDI, ex: 55 + DDD + numero
            const name = btn.dataset.name;
            const message = encodeURIComponent(`Olá, aqui é do HelpDesk. Gostaria de falar com ${name}.`);
            const url = `https://wa.me/${number}?text=${message}`; // API wa.me universal
            
            window.open(url, '_blank');
            closeCard();
        });
    }

    // Funções de modais
    function openTicketModal(ticket) {
        const modal = document.getElementById('ticket-modal');
        const modalBody = document.getElementById('ticket-modal-body');
        if (!modal || !modalBody) {
            Common.showToast('Não foi possível abrir o modal de detalhes.');
            return;
        }
        
        const subject = ticket.subject || '(Sem assunto)';
        const attachments = (ticket.attachments || [])
            .map(a => `<li class="flex items-center justify-between"><a class="text-primary-600 hover:underline" href="${a.url}" target="_blank">${a.filename}</a><span class="text-xs text-gray-500">${(a.filesize/1024).toFixed(1)} KB</span></li>`)
            .join('') || '<li class="text-gray-500">Nenhum anexo</li>';
        
        modalBody.innerHTML = `
            <div><span class="font-semibold">ID:</span> #${ticket.id}</div>
            <div><span class="font-semibold">Tipo:</span> ${ticket.type}</div>
            <div><span class="font-semibold">Classificação:</span> ${ticket.priority}</div>
            <div><span class="font-semibold">Assunto:</span> ${subject}</div>
            <div><span class="font-semibold">Descrição:</span><p class="mt-1 whitespace-pre-line">${ticket.description}</p></div>
            <div><span class="font-semibold">Anexos:</span><ul class="mt-1 space-y-1">${attachments}</ul></div>
        `;
        
        Common.showModal('ticket-modal');
    }

    // SSE + browser Notification API
    function startSSE() {
        if (evtSource) return;
        
        evtSource = new EventSource('/api/notifications/stream');
        evtSource.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'ticket_update') {
                    const msg = `Chamado #${data.ticket.id} (${data.ticket.priority}) - ${data.event}`;
                    Common.showToast(msg);
                    
                    if (Notification && Notification.permission === 'granted') {
                        new Notification('Atualização de Chamado', { body: msg });
                    }
                }
            } catch (_) {}
        };
        
        evtSource.onerror = () => {
            // retry simple
            stopSSE();
            setTimeout(startSSE, 3000);
        };
    }

    function stopSSE() {
        if (evtSource) {
            try { evtSource.close(); } catch(_) {}
            evtSource = null;
        }
        
        // Ask browser permission
        if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    // Setup event listeners
    function setupEventListeners() {
      // Carregar tickets quando a seção dashboard for exibida
        fetch('/api/tickets')
        .then(response => response.json())
        .then(tickets => {
            const select = document.getElementById('support-ticket-select');
            if (select) {
                select.innerHTML = '<option value="">Selecione um ticket</option>';
                tickets.forEach(ticket => {
                    const option = document.createElement('option');
                    option.value = ticket.id;
                    option.textContent = `#${ticket.id} - ${ticket.subject || ticket.description.substring(0, 30) + '...'}`;
                    select.appendChild(option);
                });
            }
        })
        .catch(error => console.error('Error loading tickets for support select:', error));

        // Set up dropzone for file uploads
        const dropzone = document.getElementById('attachments-dropzone');
        const fileInput = document.getElementById('ticket-attachments');
        const attachmentsList = document.getElementById('attachments-list');
        
        if (dropzone && fileInput) {
            dropzone.addEventListener('click', () => fileInput.click());
            fileInput.addEventListener('change', () => {
                const names = Array.from(fileInput.files).map(f => f.name).join(', ');
                if (attachmentsList) attachmentsList.textContent = names ? `Selecionados: ${names}` : '';
            });
        }
        
        // Handle new ticket form submission
        const newTicketForm = document.getElementById('new-ticket-form');
        if (newTicketForm) {
            newTicketForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const fd = new FormData();
                fd.append('type', document.getElementById('ticket-type').value);
                fd.append('priority', document.getElementById('ticket-priority').value);
                fd.append('subject', document.getElementById('ticket-subject').value);
                fd.append('description', document.getElementById('ticket-description').value);
                
                if (fileInput) {
                    Array.from(fileInput.files).forEach(f => fd.append('attachments', f));
                }
                
                fetch('/api/tickets', { method: 'POST', body: fd })
                    .then(async (response) => {
                        let data = null;
                        try { data = await response.json(); } catch (_) {}
                        if (!response.ok) {
                            const msg = (data && data.error) ? data.error : 'Erro ao criar chamado.';
                            throw new Error(msg);
                        }
                        return data;
                    })
                    .then((data) => {
                        if (data && data.success) {
                            Common.showToast('Chamado criado com sucesso!');
                            this.reset();
                            if (attachmentsList) attachmentsList.textContent = '';
                            loadTickets();
                            showSection('tickets');
                        } else {
                            Common.showToast((data && data.error) || 'Erro ao criar chamado.');
                        }
                    })
                    .catch(error => {
                        console.error('Error creating ticket:', error);
                        Common.showToast(error.message || 'Erro ao criar chamado. Tente novamente.');
                    });
            });
        }
        
        // Profile form submission
        const profileForm = document.getElementById('profile-form');
        if (profileForm) {
            profileForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const first = document.getElementById('profile-first-name').value.trim();
                const last = document.getElementById('profile-last-name').value.trim();
                const email = document.getElementById('profile-email').value.trim();
                const phone = document.getElementById('profile-phone').value.trim();
                const name = [first, last].filter(Boolean).join(' ');
                
                try {
                    const r = await fetch('/api/user/settings/profile', {
                        method: 'PUT', 
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name, email, phone })
                    });
                    
                    const data = await r.json().catch(() => null);
                    if (!r.ok || (data && data.error)) throw new Error((data && data.error) || 'Erro ao salvar.');
                    Common.showToast('Perfil atualizado com sucesso');
                } catch (err) {
                    Common.showToast(err.message);
                }
            });
        }
        
        // Security form submission
        const securityForm = document.getElementById('security-form');
        if (securityForm) {
            securityForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const current_password = document.getElementById('current-password').value;
                const new_password = document.getElementById('new-password').value;
                const confirm_password = document.getElementById('confirm-password').value;
                
                try {
                    const r = await fetch('/api/user/settings/security', {
                        method: 'PUT', 
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ current_password, new_password, confirm_password })
                    });
                    
                    const data = await r.json().catch(() => null);
                    if (!r.ok || (data && data.error)) throw new Error((data && data.error) || 'Erro ao alterar senha.');
                    Common.showToast('Senha alterada com sucesso');
                    e.target.reset();
                } catch (err) {
                    Common.showToast(err.message);
                }
            });
        }
        
        // Notifications form submission
        const notificationsForm = document.getElementById('notifications-form');
        if (notificationsForm) {
            notificationsForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const email_updates = document.getElementById('toggle-email-updates').checked;
                const sms_urgent = document.getElementById('toggle-sms-urgent').checked;
                const push_realtime = document.getElementById('toggle-push-realtime').checked;
                
                try {
                    const r = await fetch('/api/user/settings/notifications', {
                        method: 'PUT', 
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email_updates, sms_urgent, push_realtime })
                    });
                    
                    const data = await r.json().catch(() => null);
                    if (!r.ok || (data && data.error)) throw new Error((data && data.error) || 'Erro ao salvar preferências.');
                    Common.showToast('Preferências salvas');
                    
                    // Manage SSE based on toggle
                    if (push_realtime) startSSE(); else stopSSE();
                } catch (err) {
                    Common.showToast(err.message);
                }
            });
        }
        
        // Set up modal close handlers
        const modal = document.getElementById('ticket-modal');
        const closeBtn = document.getElementById('close-ticket-modal');
        if (closeBtn && modal) {
            closeBtn.addEventListener('click', () => Common.hideModal('ticket-modal'));
            modal.addEventListener('click', (e) => { 
                if (e.target.id === 'ticket-modal') Common.hideModal('ticket-modal'); 
            });
        }
        
        // Event listener para o seletor de ticket de suporte
        const supportTicketSelect = document.getElementById('support-ticket-select');
        if (supportTicketSelect) {
            supportTicketSelect.addEventListener('change', function() {
                const ticketId = this.value;
                currentSupportTicket = ticketId;
                loadSupportMessages(ticketId);
            });
        }

        // Configurar formulário de mensagem de suporte
        setupSupportMessageForm();

        // Pagination
        const prevButton = document.getElementById('prev-page-btn');
        const nextButton = document.getElementById('next-page-btn');

        if (prevButton) {
            prevButton.addEventListener('click', () => {
                if (currentPage > 1) {
                    currentPage--;
                    renderTicketsTable();
                    updatePagination();
                }
            });
        }

        if (nextButton) {
            nextButton.addEventListener('click', () => {
                const totalPages = Math.ceil(recentTickets.length / ticketsPerPage);
                if (currentPage < totalPages) {
                    currentPage++;
                    renderTicketsTable();
                    updatePagination();
                }
            });
        }
    }

    function setupSupportMessageForm() {
        const sendButton = document.getElementById('send-support-message');
        if (!sendButton) return;
        
        if (!sendButton._listenerAdded) {
            sendButton._listenerAdded = true;
            sendButton.addEventListener('click', function() {
                const ticketId = document.getElementById('support-ticket-select').value;
                const message = document.getElementById('support-message').value.trim();
                
                if (!ticketId) {
                    Common.showToast('Selecione um ticket para enviar a mensagem.');
                    return;
                }
                
                if (!message) {
                    Common.showToast('Digite uma mensagem.');
                    return;
                }

                // Guard de duplo clique: desabilita o botão durante o envio
                if (sendButton.disabled) return;
                sendButton.disabled = true;

                fetch(`/api/tickets/${ticketId}/responses`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ message: message }),
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        document.getElementById('support-message').value = '';
                        loadSupportMessages(ticketId);
                        Common.showToast('Mensagem enviada com sucesso!');
                    } else {
                        Common.showToast('Erro ao enviar mensagem: ' + (data.error || 'Erro desconhecido'));
                    }
                })
                .catch(error => {
                    console.error('Error sending message:', error);
                    Common.showToast('Erro ao enviar mensagem.');
                })
                .finally(() => { sendButton.disabled = false; });
            });
        }
    }

    // Load user settings into forms
    async function loadUserSettings() {
        try {
            const r = await fetch('/api/user/settings');
            if (!r.ok) return;
            const u = await r.json();
            
            // Split name into first/last (best-effort)
            const parts = (u.name || '').trim().split(' ');
            document.getElementById('profile-first-name').value = parts[0] || '';
            document.getElementById('profile-last-name').value = parts.slice(1).join(' ');
            document.getElementById('profile-email').value = u.email || '';
            document.getElementById('profile-phone').value = u.phone || '';
            document.getElementById('toggle-email-updates').checked = !!u.email_updates;
            document.getElementById('toggle-sms-urgent').checked = !!u.sms_urgent;
            document.getElementById('toggle-push-realtime').checked = !!u.push_realtime;
            
            // Start SSE if enabled
            if (u.push_realtime) {
                startSSE();
            }
        } catch (e) {
            console.error('Erro ao carregar configurações do usuário', e);
        }
    }

    // Aplica configurações da Central de Ajuda salvas no admin (via API)
    function applyHelpCenterConfig() {
        fetch('/api/help-center')
            .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar Central de Ajuda'))
            .then(cfg => {
                if (!cfg || typeof cfg !== 'object') return;
                
                // Atualiza cards superiores
                const grid = document.getElementById('help-top-cards');
                if (grid && Array.isArray(cfg.topCards) && cfg.topCards.length) {
                    grid.innerHTML = cfg.topCards.slice(0, 4).map(c => `
                        <div class="bg-white rounded-lg shadow p-6 text-center hover:shadow-lg transition-shadow cursor-pointer">
                            <div class="w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 ${c.icon === 'phone' ? 'bg-purple-100 text-purple-600' : c.icon === 'mail' ? 'bg-red-100 text-red-600' : 'bg-blue-100 text-blue-600'}">
                                <span class="material-symbols-outlined text-2xl">${c.icon || 'help'}</span>
                            </div>
                            <h3 class="font-bold text-lg mb-2">${c.title || ''}</h3>
                            <p class="text-gray-600 text-sm">${c.desc || ''}</p>
                        </div>
                    `).join('');
                }
                
                // Atualiza FAQ
                const faqList = document.getElementById('faq-list');
                if (faqList && Array.isArray(cfg.faq) && cfg.faq.length) {
                    faqList.innerHTML = cfg.faq.map(item => `
                        <div class="border rounded-lg faq-item">
                            <button class="faq-toggle w-full text-left p-4 font-medium hover:bg-gray-50 flex justify-between items-center" aria-expanded="false">
                                <span>${item.q}</span>
                                <span class="material-symbols-outlined faq-icon transition-transform">expand_more</span>
                            </button>
                            <div class="faq-answer hidden px-4 pb-4 text-gray-600">${item.a}</div>
                        </div>
                    `).join('');
                    
                    // rebind o acordeon
                    const list = document.getElementById('faq-list');
                    if (list) list.dataset.bound = '';
                }
                
                // Atualiza contatos do card "Entre em contato"
                const card = document.getElementById('contact-card');
                if (card && Array.isArray(cfg.contacts) && cfg.contacts.length) {
                    const btns = cfg.contacts.slice(0, 2).map(c => `
                        <button type="button" class="flex flex-col items-center space-y-2 contact-whatsapp" data-number="${c.number}" data-name="${c.name}">
                            <img src="/static/img/wppicon.png" alt="WhatsApp Icon" class="w-14 h-14">
                            <span class="text-sm font-medium">${c.name}</span>
                        </button>
                    `).join('');
                    
                    const grid = card.querySelector('.grid');
                    if (grid) grid.innerHTML = `
                        <div>
                            <h5 class="font-semibold text-sm mb-3">Contatos</h5>
                            <div class="grid grid-cols-2 gap-6 text-center">${btns}</div>
                        </div>
                        <div class="pl-4">
                            <h5 class="font-semibold text-sm mb-2">Informações</h5>
                            <p class="text-xs text-gray-600">Atendimento via WhatsApp. Clique em um contato ao lado.</p>
                        </div>
                    `;
                }
            })
            .catch(error => console.error('Error loading help center config:', error));
    }

    // Funções públicas
    function init() {
        // Make showSection globally available
        window.showSection = showSection;
        
        // Initialize page
        showSection('dashboard');
        loadTickets();
        loadTicketTypes();
        loadUserSettings();
        applyHelpCenterConfig();
        initContactCard();
        setupEventListeners();
        
        
        // If help is visible by default, bind FAQs
        if (!document.getElementById('help-section').classList.contains('hidden')) {
            bindFAQToggles();
        }
        
        // Adicione esta função para recarregar tickets periodicamente
        function setupPeriodicRefresh() {
            // Recarregar tickets a cada 30 segundos
            setInterval(() => {
                const currentSection = document.querySelector('[data-section].bg-primary-50');
                if (currentSection) {
                    const sectionName = currentSection.getAttribute('data-section');
                    if (sectionName === 'dashboard' || sectionName === 'tickets') {
                        loadTickets();
                    }
                }
            }, 30000);
        }
        // Inicie o refresh periódico
        setupPeriodicRefresh();
    }

    // Exportar funções públicas
    return {
        init,
        showSection,
        showSettingsTab,
        sortTable,
        loadTickets,
        loadTicketTypes,
        loadSupportMessages,
        startSSE,
        stopSSE,
        loadUserSettings,
        applyHelpCenterConfig,
        bindFAQToggles,
        initContactCard,
        setupEventListeners
    };
})();

// Inicializar quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', function() {
    UserDashboard.init();
});