// PhishGuard AI — Landing Page Script

document.addEventListener('DOMContentLoaded', () => {
  // ═══════════════════════════════════════════
  // FOOTER CLOCK (UTC)
  // ═══════════════════════════════════════════
  function updateClock() {
    const now = new Date();
    const utc = now.toISOString().slice(11, 19) + ' UTC';
    const el = document.getElementById('footerTime');
    if (el) el.textContent = utc;
  }
  updateClock();
  setInterval(updateClock, 1000);

  // ═══════════════════════════════════════════
  // COUNTER ANIMATION
  // ═══════════════════════════════════════════
  function animateCounters() {
    const counters = document.querySelectorAll('[data-target]');
    counters.forEach(counter => {
      if (counter.dataset.animated) return;
      
      const target = parseInt(counter.dataset.target);
      const duration = 1200;
      const start = performance.now();
      
      function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        counter.textContent = Math.round(target * eased).toLocaleString();
        
        if (progress < 1) {
          requestAnimationFrame(update);
        } else {
          counter.dataset.animated = 'true';
        }
      }
      requestAnimationFrame(update);
    });
  }

  // ═══════════════════════════════════════════
  // SCROLL ANIMATIONS
  // ═══════════════════════════════════════════
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        
        // Trigger counters when hero stats become visible
        if (entry.target.classList.contains('hero-stats')) {
          animateCounters();
        }
      }
    });
  }, observerOptions);

  // Add animation classes to elements
  document.querySelectorAll('.evidence-card, .timeline-entry, .module-card, .section-header, .hero-content, .hero-stats, .cta-inner').forEach((el, i) => {
    el.classList.add('animate-in');
    el.style.transitionDelay = `${Math.min(i * 0.05, 0.4)}s`;
    observer.observe(el);
  });

  // ═══════════════════════════════════════════
  // ACTIVE NAV LINK ON SCROLL
  // ═══════════════════════════════════════════
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  const navObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        navLinks.forEach(link => {
          link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
        });
      }
    });
  }, { threshold: 0.3, rootMargin: '-80px 0px -50% 0px' });

  sections.forEach(section => navObserver.observe(section));

  // ═══════════════════════════════════════════
  // SMOOTH SCROLL FOR NAV LINKS
  // ═══════════════════════════════════════════
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // ═══════════════════════════════════════════
  // HEADER SCROLL EFFECT
  // ═══════════════════════════════════════════
  const header = document.querySelector('.site-header');
  let lastScroll = 0;

  window.addEventListener('scroll', () => {
    const scroll = window.scrollY;
    
    if (scroll > 100) {
      header.style.borderBottomColor = 'rgba(26, 29, 35, 0.8)';
      header.style.background = 'rgba(8, 10, 13, 0.95)';
    } else {
      header.style.borderBottomColor = '';
      header.style.background = '';
    }
    
    lastScroll = scroll;
  }, { passive: true });

  // ═══════════════════════════════════════════
  // FLOATING CARD SUBTLE HOVER
  // ═══════════════════════════════════════════
  const floatingCards = document.querySelectorAll('.floating-card');
  floatingCards.forEach(card => {
    card.addEventListener('mouseenter', () => {
      card.style.transform = 'translateY(-2px)';
      card.style.boxShadow = '0 8px 32px rgba(0, 0, 0, 0.6)';
    });
    card.addEventListener('mouseleave', () => {
      card.style.transform = '';
      card.style.boxShadow = '';
    });
  });

  // ═══════════════════════════════════════════
  // PROGRESS BAR ANIMATION
  // ═══════════════════════════════════════════
  const progressBars = document.querySelectorAll('.progress-fill');
  const progressObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const bar = entry.target;
        const width = bar.style.width;
        bar.style.width = '0%';
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            bar.style.width = width;
          });
        });
        progressObserver.unobserve(bar);
      }
    });
  }, { threshold: 0.5 });

  progressBars.forEach(bar => progressObserver.observe(bar));

  // ═══════════════════════════════════════════
  // SCAN POINTS RANDOM DELAY
  // ═══════════════════════════════════════════
  document.querySelectorAll('.scan-point').forEach((point, i) => {
    point.querySelector('span').style.animationDelay = `${i * 0.7}s`;
  });
});
