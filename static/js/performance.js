// static/js/performance.js
const Performance = (function() {
  // Lazy loading para imagens
  function initLazyLoading() {
    const lazyImages = document.querySelectorAll('img[data-src]');
    
    if ('IntersectionObserver' in window) {
      const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const img = entry.target;
            img.src = img.dataset.src;
            img.classList.remove('lazy');
            imageObserver.unobserve(img);
          }
        });
      });
      
      lazyImages.forEach(img => {
        imageObserver.observe(img);
      });
    } else {
      // Fallback para navegadores antigos
      lazyImages.forEach(img => {
        img.src = img.dataset.src;
      });
    }
  }

  // Debounce para otimizar eventos de busca
  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  // Otimização de carregamento de scripts
  function loadScript(src, async = true, defer = true) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = src;
      script.async = async;
      script.defer = defer;
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  // Inicializar todas as otimizações
  function init() {
    initLazyLoading();
    
    // Otimizar eventos de scroll
    let scrollTimeout;
    window.addEventListener('scroll', () => {
      if (scrollTimeout) {
        window.cancelAnimationFrame(scrollTimeout);
      }
      scrollTimeout = window.requestAnimationFrame(() => {
        // Lógica de scroll otimizada
      });
    }, { passive: true });
  }

  return {
    init,
    debounce,
    loadScript
  };
})();

// Inicializar quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', Performance.init);