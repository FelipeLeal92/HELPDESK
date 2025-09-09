// static/js/common.js
const Common = (function() {
    // Funções compartilhadas entre todos os dashboards
    function showToast(message, duration = 4000) {
        const toast = document.createElement('div');
        toast.className = 'fixed bottom-4 right-4 bg-black text-white px-4 py-2 rounded shadow z-50';
        toast.textContent = message;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, duration);
    }

    function showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            
            // Foco no primeiro elemento focável
            const focusableElements = modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (focusableElements.length) {
                focusableElements[0].focus();
            }
            
            // Tratamento de teclado
            modal.addEventListener('keydown', handleModalKeydown);
        }
    }

    function hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
            modal.removeEventListener('keydown', handleModalKeydown);
            
            // Retornar foco para o elemento que abriu o modal
            const opener = document.querySelector(`[data-opens-modal="${modalId}"]`);
            if (opener) {
                opener.focus();
            }
        }
    }

    function handleModalKeydown(e) {
        if (e.key === 'Escape') {
            const modal = e.currentTarget;
            hideModal(modal.id);
        }
    }

    // Função para gerenciar foco em modais
    function trapFocus(element) {
        const focusableElements = element.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        const firstFocusableElement = focusableElements[0];
        const lastFocusableElement = focusableElements[focusableElements.length - 1];

        element.addEventListener('keydown', function(e) {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstFocusableElement) {
                        lastFocusableElement.focus();
                        e.preventDefault();
                    }
                } else {
                    if (document.activeElement === lastFocusableElement) {
                        firstFocusableElement.focus();
                        e.preventDefault();
                    }
                }
            }
        });
    }

    // Função para formatar datas
    function formatDate(dateString) {
        const options = { 
            year: 'numeric', 
            month: '2-digit', 
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        };
        return new Date(dateString).toLocaleDateString('pt-BR', options);
    }

    // Função para obter cor do status
    function getStatusColor(status) {
        const colors = {
            'Aberto': 'bg-blue-100 text-blue-800',
            'Em Andamento': 'bg-yellow-100 text-yellow-800',
            'Pendente': 'bg-orange-100 text-orange-800',
            'Resolvido': 'bg-green-100 text-green-800',
            'Fechado': 'bg-gray-100 text-gray-800'
        };
        return colors[status] || 'bg-gray-100 text-gray-800';
    }

    // Função para obter cor da prioridade
    function getPriorityColor(priority) {
        const colors = {
            'Baixa': 'bg-green-100 text-green-800',
            'Média': 'bg-yellow-100 text-yellow-800',
            'Alta': 'bg-orange-100 text-orange-800',
            'Urgente': 'bg-red-100 text-red-800'
        };
        return colors[priority] || 'bg-gray-100 text-gray-800';
    }

    // Exportar funções públicas
    return {
        showToast,
        showModal,
        hideModal,
        trapFocus,
        formatDate,
        getStatusColor,
        getPriorityColor
    };
})();