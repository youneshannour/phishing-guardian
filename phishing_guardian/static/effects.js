/**
 * Visual effects — animated network background + UI helpers
 */
const FX = (() => {
  let canvas, ctx, particles, animId;
  let mouse = { x: -1000, y: -1000 };
  const PARTICLE_COUNT = 80;
  const CONNECT_DIST = 140;
  const MOUSE_DIST = 180;

  function init() {
    canvas = document.getElementById("fx-canvas");
    if (!canvas) {
      initOrbs();
      initPageEntrance();
      return;
    }
    ctx = canvas.getContext("2d");
    resize();
    initParticles();
    window.addEventListener("resize", resize);
    document.addEventListener("mousemove", (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    });
    animate();
    initOrbs();
    initPageEntrance();
  }

  function resize() {
    if (!canvas) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function initParticles() {
    particles = Array.from({ length: PARTICLE_COUNT }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.5 + 0.2,
    }));
  }

  function animate() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    particles.forEach((p) => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      const dx = mouse.x - p.x;
      const dy = mouse.y - p.y;
      const dist = Math.hypot(dx, dy);
      if (dist < MOUSE_DIST) {
        p.x -= dx * 0.008;
        p.y -= dy * 0.008;
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(59, 130, 246, ${p.alpha})`;
      ctx.fill();
    });

    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < CONNECT_DIST) {
          const alpha = (1 - d / CONNECT_DIST) * 0.15;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(99, 102, 241, ${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }

    animId = requestAnimationFrame(animate);
  }

  function initOrbs() {
    /* Orbes désactivés — fond Matrix uniquement */
  }

  function initPageEntrance() {
    document.querySelectorAll("[data-anim]").forEach((el, i) => {
      el.style.animationDelay = `${i * 0.06}s`;
    });
  }

  /** Count-up animation for numbers */
  function countUp(el, end, duration = 800) {
    if (!el) return;
    const start = 0;
    const startTime = performance.now();
    function tick(now) {
      const t = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(start + (end - start) * eased);
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /** Stagger children with animation class */
  function staggerChildren(parent, childSelector, animClass, baseDelay = 0.08) {
    if (!parent) return;
    parent.querySelectorAll(childSelector).forEach((child, i) => {
      child.style.animationDelay = `${i * baseDelay}s`;
      child.classList.add(animClass);
    });
  }

  /** Animate risk ring SVG */
  function animateRiskRing(svgCircle, circumference, targetOffset, duration = 1200) {
    if (!svgCircle) return;
    svgCircle.style.setProperty("--ring-circ", circumference);
    svgCircle.style.setProperty("--ring-offset", targetOffset);
    svgCircle.style.strokeDashoffset = circumference;
    svgCircle.classList.add("ring-animate");
    setTimeout(() => {
      svgCircle.style.strokeDashoffset = targetOffset;
    }, 50);
  }

  /** Ripple on button click */
  function ripple(e, btn) {
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement("span");
    ripple.className = "btn-ripple";
    const size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = `${size}px`;
    ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
    ripple.style.top = `${e.clientY - rect.top - size / 2}px`;
    btn.appendChild(ripple);
    ripple.addEventListener("animationend", () => ripple.remove());
  }

  return { init, countUp, staggerChildren, animateRiskRing, ripple };
})();

document.addEventListener("DOMContentLoaded", () => FX.init());
window.FX = FX;
