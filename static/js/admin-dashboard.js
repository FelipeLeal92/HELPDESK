// static/js/admin-dashboard.js
const AdminDashboard = (function() {
    // Variáveis privadas
    let allTickets = [];
    let ticketTypes = [];
    let ticketStatuses = [];
    let recentTickets = [];
    let openTickets = [];
    let closedTickets = [];
    let recentTicketsAll = [];
    let recentTicketsView = [];
    let currentMessageTicket = null;
    let users = [];

    let sortState = {
    recent: { column: null, direction: 'asc' },
    open: { column: null, direction: 'asc' },
    closed: { column: null, direction: 'asc' }
};

    function sortTable(column, tableType) {
    // Determinar qual array de tickets usar
    let tickets;
    if (tableType === 'recent') {
        tickets = [...recentTickets];
    } else if (tableType === 'open') {
        tickets = [...openTickets];
    } else if (tableType === 'closed') {
        tickets = [...closedTickets];
    } else {
        return;
    }
    
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
    
    // Função de comparação baseada no tipo de coluna
    const compare = (a, b) => {
        let valueA = a[column];
        let valueB = b[column];
        
        // Tratar casos especiais
        if (column === 'user_name') {
            valueA = a.user_name || '';
            valueB = b.user_name || '';
        } else if (column === 'duration') {
            // Calcular duração em minutos
            const createdA = new Date(a.created_at);
            const closedA = new Date(a.closed_at || a.updated_at);
            const durationA = Math.floor((closedA - createdA) / 60000);
            
            const createdB = new Date(b.created_at);
            const closedB = new Date(b.closed_at || b.updated_at);
            const durationB = Math.floor((closedB - createdB) / 60000);
            
            valueA = durationA;
            valueB = durationB;
        } else if (column === 'created_at' || column === 'closed_at') {
            valueA = new Date(valueA);
            valueB = new Date(valueB);
        }
        
        // Comparação
        if (valueA < valueB) return direction === 'asc' ? -1 : 1;
        if (valueA > valueB) return direction === 'asc' ? 1 : -1;
        return 0;
    };
    
    // Ordenar os tickets
    tickets.sort(compare);
    
    // Renderizar a tabela apropriada
    if (tableType === 'recent') {
        renderRecentTickets(tickets);
    } else if (tableType === 'open') {
        updateOpenTicketsTable(tickets);
    } else if (tableType === 'closed') {
        updateClosedTicketsTable(tickets);
    }
}
    // Função de navegação entre seções
    function showSection(sectionName, event) {
        if (event) {
            event.preventDefault();
        }
        
        // Hide all sections
        const sections = ['dashboard', 'open-tickets', 'closed-tickets', 'ticket-types', 'users', 'user-messages', 'settings'];
        sections.forEach(section => {
            const sectionElement = document.getElementById(section + '-section');
            if (sectionElement) {
                sectionElement.classList.add('hidden');
            }
        });
        
        // Show selected section
        const selectedSection = document.getElementById(sectionName + '-section');
        if (selectedSection) {
            selectedSection.classList.remove('hidden');
        }
        
        // Update page title
        const titles = {
            'dashboard': 'Painel Administrativo',
            'open-tickets': 'Chamados Abertos',
            'closed-tickets': 'Chamados Fechados',
            'ticket-types': 'Tipos de Chamados',
            'users': 'Gerenciar Usuários',
            'user-messages': 'Mensagens do Usuário',
            'settings': 'Configurações'
        };
        document.getElementById('page-title').textContent = titles[sectionName];
        
        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('bg-primary-50', 'text-primary-700');
            link.classList.add('text-gray-700', 'hover:bg-gray-100');
        });
        
        const currentLink = document.querySelector(`.nav-link[onclick="AdminDashboard.showSection('${sectionName}')"]`);
        if (currentLink) {
            currentLink.classList.add('bg-primary-50', 'text-primary-700');
            currentLink.classList.remove('text-gray-700', 'hover:bg-gray-100');
        }
        
        // Load section-specific data
        if (sectionName === 'dashboard') {
            loadDashboardData();
        } else if (sectionName === 'open-tickets') {
            loadOpenTickets();
        } else if (sectionName === 'closed-tickets') {
            loadClosedTickets();
        } else if (sectionName === 'ticket-types') {
            loadTicketTypes();
        } else if (sectionName === 'users') {
            loadUsers();
        } else if (sectionName === 'user-messages') {
            loadUserMessagesSection();
        } else if (sectionName === 'settings') {
            bindAdminSettingsHandlers();
            initHelpCenterSettings();
        }
    }

    // Funções de carregamento de dados
    function loadDashboardData() {
        fetch('/api/admin/stats')
            .then(response => response.json())
            .then(data => {
                document.getElementById('total-tickets-admin').textContent = data.total || 0;
                document.getElementById('open-tickets-admin').textContent = data.open || 0;
                document.getElementById('resolved-tickets-admin').textContent = data.resolved || 0;
            })
            .catch(error => console.error('Error loading dashboard data:', error));
        
        loadRecentTickets();
    }

    function loadRecentTickets() {
        fetch('/api/admin/tickets/recent')
            .then(response => response.json())
            .then(tickets => {
                recentTickets = tickets;
                renderRecentTickets(tickets);
            })
            .catch(error => console.error('Error loading recent tickets:', error));
    }

    function loadOpenTickets() {
        fetch('/api/tickets')
            .then(response => response.json())
            .then(tickets => {
                allTickets = tickets;
                openTickets = tickets.filter(t => ['Aberto', 'Em Andamento', 'Pendente'].includes(t.status));
                updateOpenTicketsTable(openTickets);
                populateTicketTypeFilters();
            })
            .catch(error => console.error('Error loading open tickets:', error));
    }

    function loadClosedTickets() {
        fetch('/api/tickets')
            .then(response => response.json())
            .then(tickets => {
                closedTickets = tickets.filter(t => ['Resolvido', 'Fechado'].includes(t.status));
                updateClosedTicketsTable(closedTickets);
            })
            .catch(error => console.error('Error loading closed tickets:', error));
    }

    function loadTicketTypes() {
        Promise.all([
            fetch('/api/ticket-types').then(r => r.json()),
            fetch('/api/ticket-statuses').then(r => r.json())
        ])
        .then(([types, statuses]) => {
            ticketTypes = types;
            ticketStatuses = statuses;
            updateTicketTypesList(types);
            updateTicketStatusesList(statuses);
        })
        .catch(error => console.error('Error loading ticket types/statuses:', error));
    }

    function loadUsers() {
        fetch('/api/admin/users')
            .then(response => response.json())
            .then(usersData => {
                users = usersData;
                updateUsersTable(usersData);
            })
            .catch(error => console.error('Error loading users:', error));
    }

    function loadUserMessagesSection() {
        loadTicketsForMessageSelect();
    }
    
    function loadAdministrators() {
        fetch('/api/admin/administrators')
            .then(response => response.json())
            .then(administrators => {
                const select = document.getElementById('assign-admin-select');
                if (select) {
                    select.innerHTML = '<option value="">Selecione um administrador</option>';
                    administrators.forEach(admin => {
                        const option = document.createElement('option');
                        option.value = admin.id;
                        option.textContent = `${admin.name} (${admin.email})`;
                        select.appendChild(option);
                    });
                }
            })
            .catch(error => console.error('Error loading administrators:', error));
    }

    function loadTicketsForMessageSelect() {
        fetch('/api/tickets')
            .then(response => response.json())
            .then(tickets => {
                const select = document.getElementById('message-ticket-select');
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
            .catch(error => console.error('Error loading tickets for message select:', error));
    }

    function loadUserMessages(ticketId) {
        if (!ticketId) {
            const tbody = document.getElementById('user-messages-tbody');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="4" class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">Selecione um ticket para ver as mensagens.</td></tr>';
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
                updateUserMessagesTable(data);
            })
            .catch(error => {
                console.error('Error loading user messages:', error);
                const tbody = document.getElementById('user-messages-tbody');
                if (tbody) {
                    tbody.innerHTML = '<tr><td colspan="4" class="px-6 py-4 whitespace-nowrap text-sm text-red-500 text-center">Erro ao carregar mensagens.</td></tr>';
                }
            });
    }

    // Funções de renderização
    function renderRecentTickets(tickets) {
        const tbody = document.getElementById('recent-tickets-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = tickets.map(ticket => `
            <tr class="hover:bg-gray-50 transition-all">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#${ticket.id}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${ticket.subject || ticket.description.substring(0, 50) + '...'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <div class="flex items-center">
                        <div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-blue-700 font-medium">
                            ${ticket.user_name ? ticket.user_name.substring(0, 2).toUpperCase() : 'U'}
                        </div>
                        <span class="ml-2">${ticket.user_name || 'Usuário'}</span>
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <span class="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">${ticket.type}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <span class="px-2 py-1 text-xs rounded-full ${Common.getStatusColor(ticket.status)}">${ticket.status}</span>
                    ${ticket.assigned_to_name ? `<br><span class="px-2 py-1 text-xs rounded-full bg-indigo-100 text-indigo-800 mt-1 inline-block" title="Responsável">👤 ${ticket.assigned_to_name}</span>` : ''}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${Common.formatDate(ticket.created_at)}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div class="flex space-x-2">
                        <button class="reply-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Responder" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-blue-600">reply</span>
                        </button>
                        <button class="admin-view-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Ver detalhes" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-gray-600">visibility</span>
                        </button>
                        <button class="view-attachments-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Ver anexos" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-gray-600">attach_file</span>
                        </button>
                        <button class="close-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Finalizar" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-green-600">check_circle</span>
                        </button>
                        <button class="assign-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Atribuir" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-blue-600">person_add</span>
                        </button>
                        <button class="view-messages-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Ver Mensagens" onclick="AdminDashboard.showSection('user-messages'); AdminDashboard.loadUserMessages(${ticket.id}); document.getElementById('current-message-ticket-id').textContent = '${ticket.id}';">
                            <span class="material-symbols-outlined text-purple-600">message</span>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
        
        // Add event listeners for buttons
        addTicketActionEventListeners();
    }

    function updateOpenTicketsTable(tickets) {
        const tbody = document.getElementById('open-tickets-tbody');
        if (!tbody) return;
        
        if (tickets.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="px-6 py-4 text-center text-gray-500">
                        Nenhum chamado aberto encontrado
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = tickets.map(ticket => `
            <tr class="hover:bg-gray-50 transition-all">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#${ticket.id}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${ticket.subject || ticket.description.substring(0, 50) + '...'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <div class="flex items-center">
                        <div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-blue-700 font-medium">
                            ${ticket.user_name ? ticket.user_name.substring(0, 2).toUpperCase() : 'U'}
                        </div>
                        <span class="ml-2">${ticket.user_name || 'Usuário'}</span>
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <span class="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">${ticket.type}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <span class="px-2 py-1 text-xs rounded-full ${Common.getPriorityColor(ticket.priority)}">${ticket.priority}</span>
                    ${ticket.assigned_to_name ? `<br><span class="px-2 py-1 text-xs rounded-full bg-indigo-100 text-indigo-800 mt-1 inline-block" title="Responsável">👤 ${ticket.assigned_to_name}</span>` : ''}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${Common.formatDate(ticket.created_at)}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div class="flex space-x-2">
                        <button class="admin-view-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Ver detalhes" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-gray-600">visibility</span>
                        </button>
                        <button class="assign-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Atribuir" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-blue-600">person_add</span>
                        </button>
                        <button class="open-ticket-close-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Finalizar" data-ticket-id="${ticket.id}">
                            <span class="material-symbols-outlined text-green-600">check_circle</span>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
        
        // Add event listeners for buttons
        addOpenTicketsEventListeners();
    }

    function updateClosedTicketsTable(tickets) {
        const tbody = document.getElementById('closed-tickets-tbody');
        if (!tbody) return;
        
        if (tickets.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="px-6 py-4 text-center text-gray-500">
                        Nenhum chamado fechado encontrado
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = tickets.map(ticket => {
            // Calculate time difference
            const created = new Date(ticket.created_at);
            const closed = ticket.closed_at ? new Date(ticket.closed_at) : new Date();
            const diffTime = Math.abs(closed - created);
            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
            const diffHours = Math.floor((diffTime % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            
            return `
                <tr class="hover:bg-gray-50 transition-all">
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#${ticket.id}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${ticket.subject || ticket.description.substring(0, 50) + '...'}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                        <div class="flex items-center">
                            <div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-blue-700 font-medium">
                                ${ticket.user_name ? ticket.user_name.substring(0, 2).toUpperCase() : 'U'}
                            </div>
                            <span class="ml-2">${ticket.user_name || 'Usuário'}</span>
                        </div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                        <span class="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">${ticket.type}</span>
                        ${ticket.assigned_to_name ? `<br><span class="px-2 py-1 text-xs rounded-full bg-indigo-100 text-indigo-800 mt-1 inline-block" title="Responsável">👤 ${ticket.assigned_to_name}</span>` : ''}
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${ticket.closed_at ? Common.formatDate(ticket.closed_at) : 'N/A'}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${diffDays}d ${diffHours}h</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <div class="flex space-x-2">
                            <button class="admin-view-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Ver detalhes" data-ticket-id="${ticket.id}">
                                <span class="material-symbols-outlined text-gray-600">visibility</span>
                            </button>
                            <button class="reopen-ticket-btn p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Reabrir" data-ticket-id="${ticket.id}">
                                <span class="material-symbols-outlined text-blue-600">refresh</span>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
        
        // Add event listeners for view buttons
        document.querySelectorAll('.admin-view-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                fetch(`/api/tickets/${ticketId}`)
                    .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar detalhes'))
                    .then(ticket => openAdminTicketModal(ticket))
                    .catch(err => Common.showToast(err.message));
            });
        });
        
        // Add event listeners for reopen buttons
        document.querySelectorAll('.reopen-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                if (confirm(`Tem certeza que deseja reabrir o chamado #${ticketId}?`)) {
                    fetch(`/api/admin/tickets/${ticketId}/reopen`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            Common.showToast(`Chamado #${ticketId} reaberto com sucesso`);
                            loadClosedTickets();
                            loadRecentTickets();
                        } else {
                            Common.showToast(data.error || 'Erro ao reabrir chamado');
                        }
                    })
                    .catch(error => {
                        console.error('Error reopening ticket:', error);
                        Common.showToast('Erro ao reabrir chamado');
                    });
                }
            });
        });
    }

    function updateTicketTypesList(types) {
        const container = document.getElementById('ticket-types-list');
        if (!container) return;
        
        if (types.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8 text-gray-500">
                    Nenhum tipo de chamado encontrado
                </div>
            `;
            return;
        }
        
        container.innerHTML = types.map(type => `
            <div class="border rounded-lg p-4 flex justify-between items-center">
                <div>
                    <h4 class="font-medium">${type.name}</h4>
                    <p class="text-sm text-gray-500">${type.description || 'Sem descrição'}</p>
                </div>
                <div class="flex space-x-2">
                    <button class="p-2 rounded-full hover:bg-gray-100 transition-all" onclick="AdminDashboard.editTicketType(${type.id}, '${type.name.replace(/'/g, "'")}', '${type.description ? type.description.replace(/'/g, "'") : ''}')">
                        <span class="material-symbols-outlined text-blue-600">edit</span>
                    </button>
                    <button class="p-2 rounded-full hover:bg-gray-100 transition-all" onclick="AdminDashboard.deleteTicketType(${type.id}, '${type.name.replace(/'/g, "'")}')">
                        <span class="material-symbols-outlined text-red-600">delete</span>
                    </button>
                </div>
            </div>
        `).join('');
    }

    function updateTicketStatusesList(statuses) {
        const container = document.getElementById('ticket-statuses-list');
        if (!container) return;
        
        if (statuses.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8 text-gray-500">
                    Nenhum status de chamado encontrado
                </div>
            `;
            return;
        }
        
        container.innerHTML = statuses.map(status => `
            <div class="border rounded-lg p-4 flex justify-between items-center">
                <div class="flex items-center">
                    <span class="w-3 h-3 rounded-full mr-3" style="background-color: ${status.color}"></span>
                    <div>
                        <h4 class="font-medium">${status.name}</h4>
                    </div>
                </div>
                <div class="flex space-x-2">
                    <button class="p-2 rounded-full hover:bg-gray-100 transition-all" onclick="AdminDashboard.editTicketStatus(${status.id}, '${status.name.replace(/'/g, "'")}', '${status.color}')">
                        <span class="material-symbols-outlined text-blue-600">edit</span>
                    </button>
                    <button class="p-2 rounded-full hover:bg-gray-100 transition-all" onclick="AdminDashboard.deleteTicketStatus(${status.id}, '${status.name.replace(/'/g, "'")}')">
                        <span class="material-symbols-outlined text-red-600">delete</span>
                    </button>
                </div>
            </div>
        `).join('');
    }

    function updateUsersTable(usersData) {
        const tbody = document.getElementById('users-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = usersData.map(user => `
            <tr class="hover:bg-gray-50 transition-all">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${user.name}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${user.email}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${user.phone || '-'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                    <span class="px-2 py-1 text-xs rounded-full ${
                        user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 
                        user.role === 'manager' ? 'bg-green-100 text-green-800' : 
                        'bg-blue-100 text-blue-800'
                    }">
                        ${
                            user.role === 'admin' ? 'Administrador' : 
                            user.role === 'manager' ? 'Gerente' : 
                            'Usuário'
                        }
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${Common.formatDate(user.created_at)}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div class="flex space-x-2">
                        <button class="p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Editar" onclick="AdminDashboard.editUser(${user.id}, '${user.name.replace(/'/g, "'")}', '${user.email.replace(/'/g, "'")}', '${user.phone ? user.phone.replace(/'/g, "'") : ''}', '${user.role || 'user'}')">
                            <span class="material-symbols-outlined text-blue-600">edit</span>
                        </button>
                        <button class="p-1.5 rounded-full hover:bg-gray-100 transition-all" title="Excluir" onclick="AdminDashboard.deleteUser(${user.id}, '${user.name.replace(/'/g, "'")}')">
                            <span class="material-symbols-outlined text-red-600">delete</span>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    function updateUserMessagesTable(messages) {
        const tbody = document.getElementById('user-messages-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (messages.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">Nenhuma mensagem encontrada para este ticket.</td></tr>';
            return;
        }
        
        messages.forEach(message => {
            const row = tbody.insertRow();
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#${message.ticket_id || message.id}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${message.user_name} ${message.is_admin ? '<span class="text-xs bg-purple-100 text-purple-800 px-2 py-1 rounded">Admin</span>' : ''}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${message.message}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${Common.formatDate(message.created_at)}</td>
            `;
        });
    }

    // Funções de eventos
    function addTicketActionEventListeners() {
        // View ticket details
        document.querySelectorAll('.admin-view-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                fetch(`/api/tickets/${ticketId}`)
                    .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar detalhes'))
                    .then(ticket => openAdminTicketModal(ticket))
                    .catch(err => Common.showToast(err.message));
            });
        });
        
        // Reply to ticket
        document.querySelectorAll('.reply-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                document.getElementById('reply-ticket-id').textContent = ticketId;
                document.getElementById('reply-ticket-id-input').value = ticketId;
                document.getElementById('reply-message').value = '';
                Common.showModal('reply-ticket-modal');
            });
        });
        
        // View attachments
        document.querySelectorAll('.view-attachments-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                document.getElementById('attachments-ticket-id').textContent = ticketId;
                document.getElementById('attachments-list').innerHTML = '<p class="text-gray-500 text-center py-4">Carregando anexos...</p>';
                Common.showModal('attachments-modal');
                
                // Fetch attachments
                fetch(`/api/tickets/${ticketId}`)
                    .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar anexos'))
                    .then(ticket => {
                        const attachments = ticket.attachments || [];
                        if (attachments.length === 0) {
                            document.getElementById('attachments-list').innerHTML = 
                                '<p class="text-gray-500 text-center py-4">Nenhum anexo encontrado para este chamado.</p>';
                            return;
                        }
                        
                        const attachmentsList = attachments.map(attachment => `
                            <div class="flex items-center justify-between p-3 border rounded-lg">
                                <div class="flex items-center">
                                    <span class="material-symbols-outlined text-gray-500 mr-2">description</span>
                                    <span>${attachment.filename}</span>
                                </div>
                                <a href="/uploads/${attachment.filepath}" download class="p-1.5 rounded-full hover:bg-gray-100 transition-all">
                                    <span class="material-symbols-outlined text-primary-600">download</span>
                                </a>
                            </div>
                        `).join('');
                        
                        document.getElementById('attachments-list').innerHTML = attachmentsList;
                    })
                    .catch(error => {
                        console.error('Error loading attachments:', error);
                        document.getElementById('attachments-list').innerHTML = 
                            '<p class="text-red-500 text-center py-4">Erro ao carregar anexos. Tente novamente.</p>';
                    });
            });
        });
        
        // Assign ticket to admin (from main dashboard)
        document.querySelectorAll('.assign-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                document.getElementById('assign-ticket-id').textContent = ticketId;
                document.getElementById('assign-ticket-id-input').value = ticketId;
                
                // Load administrators for the select dropdown
                loadAdministrators();
                
                Common.showModal('assign-ticket-modal');
            });
        });
        
        // Close ticket
        document.querySelectorAll('.close-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                document.getElementById('close-ticket-id').textContent = ticketId;
                document.getElementById('close-ticket-id-input').value = ticketId;
                document.getElementById('close-ticket-note').value = '';
                Common.showModal('close-ticket-modal');
            });
        });
    }

    function addOpenTicketsEventListeners() {
        // View ticket details
        document.querySelectorAll('.admin-view-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                fetch(`/api/tickets/${ticketId}`)
                    .then(r => r.ok ? r.json() : Promise.reject('Falha ao carregar detalhes'))
                    .then(ticket => openAdminTicketModal(ticket))
                    .catch(err => Common.showToast(err.message));
            });
        });
        
        // Assign ticket to admin
        document.querySelectorAll('.assign-ticket-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                document.getElementById('assign-ticket-id').textContent = ticketId;
                document.getElementById('assign-ticket-id-input').value = ticketId;
                
                // Load administrators for the select dropdown
                loadAdministrators();
                
                Common.showModal('assign-ticket-modal');
            });
        });
        
        // Close ticket
        document.querySelectorAll('.open-ticket-close-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ticketId = this.getAttribute('data-ticket-id');
                document.getElementById('close-ticket-id').textContent = ticketId;
                document.getElementById('close-ticket-id-input').value = ticketId;
                document.getElementById('close-ticket-note').value = '';
                Common.showModal('close-ticket-modal');
            });
        });
    }

    // Funções de modais
    function openAdminTicketModal(ticket) {
        const modal = document.getElementById('admin-ticket-modal');
        const modalBody = document.getElementById('admin-ticket-modal-body');
        if (!modal || !modalBody) return;
        
        const subject = ticket.subject || '(Sem assunto)';
        const attachments = (ticket.attachments || [])
            .map(a => `<li class="flex items-center justify-between"><a class="text-primary-600 hover:underline" href="${a.url}" target="_blank">${a.filename}</a><span class="text-xs text-gray-500">${(a.filesize/1024).toFixed(1)} KB</span></li>`)
            .join('') || '<li class="text-gray-500">Nenhum anexo</li>';
        
        modalBody.innerHTML = `
            <div class="grid grid-cols-2 gap-2">
                <div><span class="font-semibold">ID:</span> #${ticket.id}</div>
                <div><span class="font-semibold">Status:</span> ${ticket.status}</div>
                <div><span class="font-semibold">Tipo:</span> ${ticket.type}</div>
                <div><span class="font-semibold">Classificação:</span> ${ticket.priority}</div>
                <div class="col-span-2"><span class="font-semibold">Assunto:</span> ${subject}</div>
                <div class="col-span-2"><span class="font-semibold">Descrição:</span><p class="mt-1 whitespace-pre-line">${ticket.description}</p></div>
                <div class="col-span-2"><span class="font-semibold">Anexos:</span><ul class="mt-1 space-y-1">${attachments}</ul></div>
            </div>
        `;
        Common.showModal('admin-ticket-modal');
    }

    // Funções de CRUD
    function editTicketType(id, name, description) {
        document.getElementById('type-modal-title').textContent = 'Editar Tipo de Chamado';
        document.getElementById('type-id').value = id;
        document.getElementById('type-name').value = name;
        document.getElementById('type-description').value = description;
        Common.showModal('type-modal');
    }

    function deleteTicketType(id, name) {
        if (confirm(`Tem certeza que deseja excluir o tipo de chamado "${name}"?`)) {
            fetch(`/api/ticket-types/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    Common.showToast('Tipo de chamado excluído com sucesso');
                    loadTicketTypes();
                } else {
                    Common.showToast('Erro ao excluir tipo de chamado');
                }
            })
            .catch(error => {
                console.error('Error deleting ticket type:', error);
                Common.showToast('Erro ao excluir tipo de chamado');
            });
        }
    }

    function editTicketStatus(id, name, color) {
        document.getElementById('status-modal-title').textContent = 'Editar Status de Chamado';
        document.getElementById('status-id').value = id;
        document.getElementById('status-name').value = name;
        document.getElementById('status-color').value = color;
        Common.showModal('status-modal');
    }

    function deleteTicketStatus(id, name) {
        if (confirm(`Tem certeza que deseja excluir o status de chamado "${name}"?`)) {
            fetch(`/api/ticket-statuses/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    Common.showToast('Status de chamado excluído com sucesso');
                    loadTicketTypes();
                } else {
                    Common.showToast('Erro ao excluir status de chamado');
                }
            })
            .catch(error => {
                console.error('Error deleting ticket status:', error);
                Common.showToast('Erro ao excluir status de chamado');
            });
        }
    }

    function editUser(id, name, email, phone, role) {
        document.getElementById('user-modal-title').textContent = 'Editar Usuário';
        document.getElementById('user-id').value = id;
        document.getElementById('user-name').value = name;
        document.getElementById('user-email').value = email;
        document.getElementById('user-phone').value = phone;
        document.getElementById('user-role').value = role || 'user';
        document.getElementById('user-password').value = ''; // Clear password for security
        Common.showModal('add-user-modal'); // Reusing the add-user-modal
    }

    function showAddUserModal() {
        document.getElementById('user-modal-title').textContent = 'Adicionar Novo Usuário';
        document.getElementById('user-id').value = ''; // Clear ID for new user
        document.getElementById('user-name').value = '';
        document.getElementById('user-email').value = '';
        document.getElementById('user-password').value = '';
        document.getElementById('user-phone').value = '';
        document.getElementById('user-role').value = 'user';
        Common.showModal('add-user-modal');
    }

    function deleteUser(id, name) {
        if (confirm(`Tem certeza que deseja excluir o usuário "${name}"?`)) {
            fetch(`/api/admin/users/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    Common.showToast('Usuário excluído com sucesso');
                    loadUsers();
                } else {
                    Common.showToast('Erro ao excluir usuário');
                }
            })
            .catch(error => {
                console.error('Error deleting user:', error);
                Common.showToast('Erro ao excluir usuário');
            });
        }
    }

    function loadAdministrators() {
        fetch('/api/admin/users')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Falha ao carregar administradores');
                }
                return response.json();
            })
            .then(usersData => {
                const adminSelect = document.getElementById('assign-admin-select');
                // Limpar opções existentes, mantendo apenas a opção padrão
                adminSelect.innerHTML = '<option value="">Selecione um administrador</option>';
                
                // Filtrar apenas administradores e managers
                const admins = usersData.filter(user => user.role === 'admin' || user.role === 'manager');
                
                if (admins.length === 0) {
                    adminSelect.innerHTML += '<option disabled>Nenhum administrador encontrado</option>';
                    return;
                }
                
                // Adicionar opções de administradores
                admins.forEach(admin => {
                    adminSelect.innerHTML += `<option value="${admin.id}">${admin.name}</option>`;
                });
            })
            .catch(error => {
                console.error('Erro ao carregar administradores:', error);
                document.getElementById('assign-admin-select').innerHTML = 
                    '<option value="">Selecione um administrador</option><option disabled>Erro ao carregar administradores</option>';
            });
    }

    function populateTicketTypeFilters() {
        const typeFilter = document.getElementById('open-tickets-type-filter');
        if (!typeFilter) return;
        
        // Get unique ticket types
        const uniqueTypes = [...new Set(allTickets.map(ticket => ticket.type))];
        
        typeFilter.innerHTML = '<option value="">Todos os tipos</option>';
        uniqueTypes.forEach(type => {
            typeFilter.innerHTML += `<option value="${type}">${type}</option>`;
        });
    }

    // Funções de configurações
    function bindAdminSettingsHandlers() {
        const btn = document.getElementById('btn-admin-change-password');
        if (!btn) return;
        if (btn._bound) return; // prevent multiple binds
        btn._bound = true;
        
        btn.addEventListener('click', async () => {
            const current_password = document.getElementById('admin-current-password').value;
            const new_password = document.getElementById('admin-new-password').value;
            const confirm_password = document.getElementById('admin-confirm-password').value;
            
            try {
                const r = await fetch('/api/user/settings/security', {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_password, new_password, confirm_password })
                });
                const data = await r.json().catch(() => null);
                if (!r.ok || (data && data.error)) throw new Error((data && data.error) || 'Erro ao alterar senha.');
                Common.showToast('Senha do administrador alterada com sucesso');
                document.getElementById('admin-current-password').value = '';
                document.getElementById('admin-new-password').value = '';
                document.getElementById('admin-confirm-password').value = '';
            } catch (err) {
                Common.showToast(err.message);
            }
        });
        
        // load settings values whenever admin opens the tab
        loadAdminSettings();
    }

    async function loadAdminSettings() {
        try {
            const r = await fetch('/api/admin/settings');
            if (!r.ok) return;
            const s = await r.json();
            document.getElementById('company-name').value = s.company_name || '';
            document.getElementById('support-email').value = s.support_email || '';
            document.getElementById('support-phone').value = s.support_phone || '';
        } catch (e) { console.error(e); }
    }

    function initHelpCenterSettings() {
        const form = document.getElementById('help-center-settings-form');
        if (!form) return; 
        if (form._bound) return; form._bound = true;
        let cfg = null;
        
        // Top cards
        const topContainer = document.getElementById('top-cards-container');
        const tmplTop = document.getElementById('tmpl-top-card-fieldset');
        
        function renderTopCards() {
            topContainer.innerHTML = '';
            cfg.topCards.forEach((card, idx) => {
                const wrap = document.createElement('div');
                const node = tmplTop.content.cloneNode(true);
                wrap.appendChild(node);
                const fs = wrap.querySelector('fieldset');
                const inputs = fs.querySelectorAll('input');
                inputs[0].value = card.title;
                inputs[1].value = card.desc;
                inputs[2].value = card.icon;
                inputs[0].addEventListener('input', e => cfg.topCards[idx].title = e.target.value);
                inputs[1].addEventListener('input', e => cfg.topCards[idx].desc = e.target.value);
                inputs[2].addEventListener('input', e => cfg.topCards[idx].icon = e.target.value);
                fs.querySelector('.btn-remove-top-card').addEventListener('click', () => { cfg.topCards.splice(idx, 1); renderTopCards(); });
                topContainer.appendChild(wrap);
            });
        }
        
        document.getElementById('btn-add-top-card').addEventListener('click', () => {
            cfg.topCards.push({ title: 'Novo Card', desc: 'Descrição', icon: 'help' });
            renderTopCards();
        });
        
        // FAQ
        const faqContainer = document.getElementById('faq-items-container');
        const tmplFaq = document.getElementById('tmpl-faq-item');
        
        function renderFaq() {
            faqContainer.innerHTML = '';
            cfg.faq.forEach((item, idx) => {
                const wrap = document.createElement('div');
                const node = tmplFaq.content.cloneNode(true);
                wrap.appendChild(node);
                const qInput = wrap.querySelector('input');
                const aInput = wrap.querySelector('textarea');
                qInput.value = item.q;
                aInput.value = item.a;
                qInput.addEventListener('input', e => cfg.faq[idx].q = e.target.value);
                aInput.addEventListener('input', e => cfg.faq[idx].a = e.target.value);
                wrap.querySelector('.btn-remove-faq').addEventListener('click', () => { cfg.faq.splice(idx, 1); renderFaq(); });
                faqContainer.appendChild(wrap);
            });
        }
        
        document.getElementById('btn-add-faq').addEventListener('click', () => {
            cfg.faq.push({ q: 'Nova pergunta', a: 'Resposta' });
            renderFaq();
        });
        
        // Contacts
        const contactsContainer = document.getElementById('contact-items-container');
        const tmplContact = document.getElementById('tmpl-contact-item');
        
        function renderContacts() {
            contactsContainer.innerHTML = '';
            cfg.contacts.forEach((c, idx) => {
                const wrap = document.createElement('div');
                const node = tmplContact.content.cloneNode(true);
                wrap.appendChild(node);
                const inputs = wrap.querySelectorAll('input');
                inputs[0].value = c.name;
                inputs[1].value = c.number;
                inputs[0].addEventListener('input', e => cfg.contacts[idx].name = e.target.value);
                inputs[1].addEventListener('input', e => cfg.contacts[idx].number = e.target.value);
                wrap.querySelector('.btn-remove-contact').addEventListener('click', () => { cfg.contacts.splice(idx, 1); renderContacts(); });
                contactsContainer.appendChild(wrap);
            });
        }
        
        async function loadConfigAndRender() {
            try {
                const r = await fetch('/api/help-center');
                if (!r.ok) throw new Error('Falha ao carregar Central de Ajuda');
                cfg = await r.json();
            } catch (err) {
                Common.showToast(err.message || 'Falha ao carregar Central de Ajuda');
                cfg = { topCards: [], faq: [], contacts: [] };
            }
            renderTopCards();
            renderFaq();
            renderContacts();
        }
        
        document.getElementById('btn-add-contact').addEventListener('click', () => {
            cfg.contacts.push({ name: 'Novo Contato', number: '5599999999999' });
            renderContacts();
        });
        
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
                const r = await fetch('/api/help-center', {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(cfg)
                });
                const data = await r.json().catch(() => null);
                if (!r.ok || (data && data.error)) throw new Error((data && data.error) || 'Falha ao salvar Central de Ajuda');
                Common.showToast('Central de Ajuda salva');
            } catch (err) { Common.showToast(err.message || 'Falha ao salvar Central de Ajuda'); }
        });
        
        document.getElementById('btn-reset-help-center').addEventListener('click', async () => {
            try {
                await fetch('/api/help-center', {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ topCards: [], faq: [], contacts: [] })
                });
                Common.showToast('Central de Ajuda restaurada');
                window.location.reload();
            } catch (err) { Common.showToast(err.message || 'Falha ao restaurar'); }
        });
        
        loadConfigAndRender();
    }

    // Setup event listeners
    function setupEventListeners() {
        // Event listener para o seletor de ticket
        const messageTicketSelect = document.getElementById('message-ticket-select');
        if (messageTicketSelect) {
            messageTicketSelect.addEventListener('change', function() {
                const ticketId = this.value;
                document.getElementById('current-message-ticket-id').textContent = ticketId || 'N/A';
                document.getElementById('message-ticket-id').value = ticketId;
                currentMessageTicket = ticketId;
                loadUserMessages(ticketId);
            });
        }

        // Configurar formulário de mensagem
        setupMessageForm();

        // Form handlers
        const typeForm = document.getElementById('ticket-type-form');
        if (typeForm) {
            typeForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const id = document.getElementById('type-id').value;
                const name = document.getElementById('type-name').value;
                const description = document.getElementById('type-description').value;
                
                const url = id ? `/api/ticket-types/${id}` : '/api/ticket-types';
                const method = id ? 'PUT' : 'POST';
                
                fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name, description })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Common.showToast(id ? 'Tipo de chamado atualizado com sucesso' : 'Tipo de chamado adicionado com sucesso');
                        Common.hideModal('type-modal');
                        loadTicketTypes();
                    } else {
                        Common.showToast(data.error || 'Erro ao salvar tipo de chamado');
                    }
                })
                .catch(error => {
                    console.error('Error saving ticket type:', error);
                    Common.showToast('Erro ao salvar tipo de chamado');
                });
            });
        }
        
        const statusForm = document.getElementById('ticket-status-form');
        if (statusForm) {
            statusForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const id = document.getElementById('status-id').value;
                const name = document.getElementById('status-name').value;
                const color = document.getElementById('status-color').value;
                
                const url = id ? `/api/ticket-statuses/${id}` : '/api/ticket-statuses';
                const method = id ? 'PUT' : 'POST';
                
                fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name, color })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Common.showToast(id ? 'Status de chamado atualizado com sucesso' : 'Status de chamado adicionado com sucesso');
                        Common.hideModal('status-modal');
                        loadTicketTypes();
                    } else {
                        Common.showToast(data.error || 'Erro ao salvar status de chamado');
                    }
                })
                .catch(error => {
                    console.error('Error saving ticket status:', error);
                    Common.showToast('Erro ao salvar status de chamado');
                });
            });
        }
        
        const userForm = document.getElementById('add-user-form');
        if (userForm) {
            userForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const userId = document.getElementById('user-id').value;
                const name = document.getElementById('user-name').value;
                const email = document.getElementById('user-email').value;
                const password = document.getElementById('user-password').value;
                const phone = document.getElementById('user-phone').value;
                const role = document.getElementById('user-role').value;
                
                const url = userId ? `/api/admin/users/${userId}` : '/api/admin/users';
                const method = userId ? 'PUT' : 'POST';
                
                const body = { name, email, phone, role: role };
                if (password) { // Only include password if it's provided (for new user or password change)
                    body.password = password;
                }

                fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(body)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Common.showToast(userId ? 'Usuário atualizado com sucesso' : 'Usuário adicionado com sucesso');
                        Common.hideModal('add-user-modal');
                        loadUsers();
                    } else {
                        Common.showToast(data.error || 'Erro ao salvar usuário');
                    }
                })
                .catch(error => {
                    console.error('Error saving user:', error);
                    Common.showToast('Erro ao salvar usuário');
                });
            });
        }
        
        // Filter handlers
        const applyOpenTicketsFilters = document.getElementById('apply-open-tickets-filters');
        if (applyOpenTicketsFilters) {
            applyOpenTicketsFilters.addEventListener('click', function() {
                const typeFilter = document.getElementById('open-tickets-type-filter').value;
                const priorityFilter = document.getElementById('open-tickets-priority-filter').value;
                
                let filteredTickets = allTickets.filter(t => ['Aberto', 'Em Andamento', 'Pendente'].includes(t.status));
                
                if (typeFilter) {
                    filteredTickets = filteredTickets.filter(t => t.type === typeFilter);
                }
                
                if (priorityFilter) {
                    filteredTickets = filteredTickets.filter(t => t.priority === priorityFilter);
                }
                
                updateOpenTicketsTable(filteredTickets);
            });
        }
        
        const applyClosedTicketsFilters = document.getElementById('apply-closed-tickets-filters');
        if (applyClosedTicketsFilters) {
            applyClosedTicketsFilters.addEventListener('click', function() {
                const startDate = document.getElementById('closed-tickets-start-date').value;
                const endDate = document.getElementById('closed-tickets-end-date').value;
                
                let filteredTickets = allTickets.filter(t => ['Resolvido', 'Fechado'].includes(t.status));
                
                if (startDate) {
                    filteredTickets = filteredTickets.filter(t => new Date(t.closed_at) >= new Date(startDate));
                }
                
                if (endDate) {
                    filteredTickets = filteredTickets.filter(t => new Date(t.closed_at) <= new Date(endDate));
                }
                
                updateClosedTicketsTable(filteredTickets);
            });
        }
        
        // Modal close handlers
        const modal = document.getElementById('admin-ticket-modal');
        const closeBtn = document.getElementById('admin-close-ticket-modal');
        if (closeBtn && modal) {
            closeBtn.addEventListener('click', () => Common.hideModal('admin-ticket-modal'));
            modal.addEventListener('click', (e) => { 
                if (e.target.id === 'admin-ticket-modal') Common.hideModal('admin-ticket-modal'); 
            });
        }
        
        // Form handlers for ticket actions
        const replyTicketForm = document.getElementById('reply-ticket-form');
        if (replyTicketForm) {
            replyTicketForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const ticketId = document.getElementById('reply-ticket-id-input').value;
                const message = document.getElementById('reply-message').value;
                
                if (!ticketId || !message) {
                    Common.showToast('Por favor, preencha a mensagem.');
                    return;
                }
                
                fetch(`/api/tickets/${ticketId}/responses`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ message })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Common.showToast('Resposta enviada com sucesso');
                        Common.hideModal('reply-ticket-modal');
                        loadRecentTickets();
                    } else {
                        Common.showToast(data.error || 'Erro ao enviar resposta');
                    }
                })
                .catch(error => {
                    console.error('Error sending reply:', error);
                    Common.showToast('Erro ao enviar resposta');
                });
            });
        }
        
        // Form handler para atribuir chamado
        const assignTicketForm = document.getElementById('assign-ticket-form');
        if (assignTicketForm) {
            assignTicketForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const ticketId = document.getElementById('assign-ticket-id-input').value;
                const adminId = document.getElementById('assign-admin-select').value;
                
                if (!ticketId || !adminId) {
                    Common.showToast('Por favor, selecione um administrador.');
                    return;
                }
                
                fetch(`/api/admin/tickets/${ticketId}/assign`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ assigned_to: adminId })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Common.showToast(`Chamado atribuído a ${data.assigned_to} com sucesso`);
                        Common.hideModal('assign-ticket-modal');
                        loadOpenTickets();
                        loadRecentTickets();
                    } else {
                        Common.showToast(data.error || 'Erro ao atribuir chamado');
                    }
                })
                .catch(error => {
                    console.error('Error assigning ticket:', error);
                    Common.showToast('Erro ao atribuir chamado');
                });
            });
        }
        
        const closeTicketForm = document.getElementById('close-ticket-form');
        if (closeTicketForm) {
            closeTicketForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const ticketId = document.getElementById('close-ticket-id-input').value;
                const note = document.getElementById('close-ticket-note').value;
                
                if (!ticketId) {
                    Common.showToast('ID do chamado não encontrado.');
                    return;
                }
                
                fetch(`/api/admin/tickets/${ticketId}/status`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ status: 'Resolvido' })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Common.showToast('Chamado resolvido com sucesso');
                        Common.hideModal('close-ticket-modal');
                        loadRecentTickets();
                        // If we're in the open tickets section, reload that too
                        const currentSection = document.querySelector('.nav-link.bg-primary-50');
                        if (currentSection && currentSection.getAttribute('onclick').includes('open-tickets')) {
                            loadOpenTickets();
                        }
                    } else {
                        Common.showToast(data.error || 'Erro ao resolver chamado');
                    }
                })
                .catch(error => {
                    console.error('Error resolving ticket:', error);
                    Common.showToast('Erro ao resolver chamado');
                });
            });
        }
        
        // Admin settings form
        const adminSettingsForm = document.getElementById('admin-settings-form');
        if (adminSettingsForm) {
            adminSettingsForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const company_name = document.getElementById('company-name').value.trim();
                const support_email = document.getElementById('support-email').value.trim();
                const support_phone = document.getElementById('support-phone').value.trim();
                
                try {
                    const r = await fetch('/api/admin/settings', {
                        method: 'PUT', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ company_name, support_email, support_phone })
                    });
                    const data = await r.json().catch(() => null);
                    if (!r.ok || (data && data.error)) throw new Error((data && data.error) || 'Erro ao salvar configurações.');
                    Common.showToast('Configurações salvas');
                } catch (err) { Common.showToast(err.message); }
            });
        }
    }

    function sortRecentTickets() {
        const sortOrder = document.getElementById('dashboard-sort-order').value;
        let sortedTickets = [...recentTickets];
        
        switch(sortOrder) {
            case 'newest':
                sortedTickets.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                break;
            case 'oldest':
                sortedTickets.sort((a, b) => new Date(a.created_at) - new Date(a.created_at));
                break;
            case 'priority':
                const priorityOrder = {'Alta': 3, 'Média': 2, 'Baixa': 1};
                sortedTickets.sort((a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]);
                break;
            case 'type':
                sortedTickets.sort((a, b) => a.type.localeCompare(b.type));
                break;
            case 'status':
                sortedTickets.sort((a, b) => a.status.localeCompare(b.status));
                break;
        }
        
        renderRecentTickets(sortedTickets);
    }

    function sortOpenTickets() {
        const sortOrder = document.getElementById('open-tickets-sort-order').value;
        let sortedTickets = [...openTickets];
        
        switch(sortOrder) {
            case 'newest':
                sortedTickets.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                break;
            case 'oldest':
                sortedTickets.sort((a, b) => new Date(a.created_at) - new Date(a.created_at));
                break;
            case 'priority':
                const priorityOrder = {'Alta': 3, 'Média': 2, 'Baixa': 1};
                sortedTickets.sort((a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]);
                break;
            case 'type':
                sortedTickets.sort((a, b) => a.type.localeCompare(b.type));
                break;
            case 'status':
                sortedTickets.sort((a, b) => a.status.localeCompare(b.status));
                break;
        }
        
        updateOpenTicketsTable(sortedTickets);
    }

    function sortClosedTickets() {
        const sortOrder = document.getElementById('closed-tickets-sort-order').value;
        let sortedTickets = [...closedTickets];
        
        switch(sortOrder) {
            case 'newest':
                sortedTickets.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                break;
            case 'oldest':
                sortedTickets.sort((a, b) => new Date(a.created_at) - new Date(a.created_at));
                break;
            case 'priority':
                const priorityOrder = {'Alta': 3, 'Média': 2, 'Baixa': 1};
                sortedTickets.sort((a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]);
                break;
            case 'type':
                sortedTickets.sort((a, b) => a.type.localeCompare(b.type));
                break;
            case 'closed_date':
                sortedTickets.sort((a, b) => new Date(b.closed_at || b.updated_at) - new Date(a.closed_at || a.updated_at));
                break;
        }
        
        updateClosedTicketsTable(sortedTickets);
    }

    // Adicionar também os event listeners para os filtros
    document.addEventListener('DOMContentLoaded', function() {
        const applyOpenTicketsFilters = document.getElementById('apply-open-tickets-filters');
        if (applyOpenTicketsFilters) {
            applyOpenTicketsFilters.addEventListener('click', function() {
                const typeFilter = document.getElementById('open-tickets-type-filter').value;
                const priorityFilter = document.getElementById('open-tickets-priority-filter').value;
                
                let filteredTickets = allTickets.filter(t => ['Aberto', 'Em Andamento', 'Pendente'].includes(t.status));
                
                if (typeFilter) {
                    filteredTickets = filteredTickets.filter(t => t.type === typeFilter);
                }
                
                if (priorityFilter) {
                    filteredTickets = filteredTickets.filter(t => t.priority === priorityFilter);
                }
                
                updateOpenTicketsTable(filteredTickets);
            });
        }
        
        const applyClosedTicketsFilters = document.getElementById('apply-closed-tickets-filters');
        if (applyClosedTicketsFilters) {
            applyClosedTicketsFilters.addEventListener('click', function() {
                const startDate = document.getElementById('closed-tickets-start-date').value;
                const endDate = document.getElementById('closed-tickets-end-date').value;
                
                let filteredTickets = allTickets.filter(t => ['Resolvido', 'Fechado'].includes(t.status));
                
                if (startDate) {
                    filteredTickets = filteredTickets.filter(t => new Date(t.closed_at) >= new Date(startDate));
                }
                
                if (endDate) {
                    filteredTickets = filteredTickets.filter(t => new Date(t.closed_at) <= new Date(endDate));
                }
                
                updateClosedTicketsTable(filteredTickets);
            });
        }
    })
    function setupMessageForm() {
        const form = document.getElementById('send-message-form');
        if (!form) return;
        
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const ticketId = document.getElementById('message-ticket-id').value;
            const message = document.getElementById('message-content').value.trim();
            
            if (!ticketId) {
                Common.showToast('Selecione um ticket para enviar a mensagem.');
                return;
            }
            
            if (!message) {
                Common.showToast('Digite uma mensagem.');
                return;
            }

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
                    document.getElementById('message-content').value = '';
                    loadUserMessages(ticketId);
                    Common.showToast('Mensagem enviada com sucesso!');
                } else {
                    Common.showToast('Erro ao enviar mensagem: ' + (data.error || 'Erro desconhecido'));
                }
            })
            .catch(error => {
                console.error('Error sending message:', error);
                Common.showToast('Erro ao enviar mensagem.');
            });
        });
    }

    // Funções públicas
    function init() {
        // Make helpers globally available for inline handlers
        window.showSection = showSection;
        window.hideModal = Common.hideModal;
        window.showModal = Common.showModal;
        
        // Initialize dashboard
        showSection('dashboard');
        
        // Bind close button for ticket details modal (no inline handler in HTML)
        const adminCloseBtn = document.getElementById('admin-close-ticket-modal');
        if (adminCloseBtn && !adminCloseBtn._bound) {
            adminCloseBtn._bound = true;
            adminCloseBtn.addEventListener('click', () => Common.hideModal('admin-ticket-modal'));
        }
        
        // Guard optional listeners
        if (typeof setupEventListeners === 'function') {
            setupEventListeners();
        }
        
        // Set up periodic refresh for dashboard data
        setInterval(() => {
            const currentSection = document.querySelector('.nav-link.bg-primary-50');
            if (currentSection) {
                const sectionName = currentSection.getAttribute('onclick').match(/showSection\('([^']+)'\)/)[1];
                if (sectionName === 'dashboard') {
                    loadDashboardData();
                } else if (sectionName === 'open-tickets') {
                    loadOpenTickets();
                } else if (sectionName === 'closed-tickets') {
                    loadClosedTickets();
                }
            }
        }, 30000); // Refresh every 30 seconds
    }

    // Exportar funções públicas
    return {
        init,
        showSection,
        loadDashboardData,
        loadOpenTickets,
        loadClosedTickets,
        loadTicketTypes,
        loadUsers,
        loadUserMessages,
        loadUserMessagesSection,
        editTicketType,
        deleteTicketType,
        editTicketStatus,
        deleteTicketStatus,
        editUser,
        deleteUser,
        sortTable,
        showAddUserModal // Expose the function globally
    };
})();

// Inicializar quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', function() {
    AdminDashboard.init();
});
