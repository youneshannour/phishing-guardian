/**
 * Visual effects — particles, boot, ripples, topbar clock
 */
const FX = (() => {
  let canvas, ctx, particles, animId;
  let mouse = { x: -1000, y: -1000 };
  const PARTICLE_COUNT = 55;
  const CONNECT_DIST = 130;
  const MOUSE_DIST = 160;

  function init() {
    initBoot();
    initClock();
    initRipples();
    canvas = document.getElementById("fx-canvas");
    if (!canvas) {
      initPageEntrance();
      return;
    }
    ctx = canvas.getContext("2d");
    resize();
    initParticles();
    window.addEventListener("resize", resize);
    document.addEventListener("mousemove", (e) => {
      const wrap = document.querySelector(".main-wrapper");
      if (!wrap) return;
      const r = wrap.getBoundingClientRect();
      mouse.x = e.clientX - r.left;
      mouse.y = e.clientY - r.top;
    });
    animate();
    initPageEntrance();
    window.addEventListener("pg-theme-change", () => { /* palette mise à jour à chaque frame */ });
  }

  function isLight() {
    return document.documentElement.getAttribute("data-theme") === "light";
  }

  function initBoot() {
    const overlay = document.getElementById("bootOverlay");
    if (!overlay) return;
    setTimeout(() => {
      overlay.classList.add("boot-done");
      setTimeout(() => overlay.remove(), 700);
    }, 1500);
  }

  function initClock() {
    const el = document.getElementById("topbarClock");
    if (!el) return;
    const tick = () => {
      el.textContent = new Date().toLocaleTimeString("fr-FR", {
        hour: "2-digit", minute: "2-digit", second: "2-digit",
      });
    };
    tick();
    setInterval(tick, 1000);
  }

  function initRipples() {
    document.addEventListener("click", (e) => {
      const btn = e.target.closest(".pb-run-btn, .ai-send-btn, .btn-hacking, .nav-item, .ai-prompt-chip");
      if (btn && typeof ripple === "function") ripple(e, btn);
    });
  }

  function resize() {
    if (!canvas) return;
    const wrap = canvas.parentElement;
    const r = wrap ? wrap.getBoundingClientRect() : { width: window.innerWidth, height: window.innerHeight };
    canvas.width = Math.max(1, Math.floor(r.width));
    canvas.height = Math.max(1, Math.floor(r.height));
    if (particles) initParticles();
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
    const light = isLight();
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
      const nearMouse = Math.hypot(mouse.x - p.x, mouse.y - p.y) < MOUSE_DIST;
      ctx.fillStyle = nearMouse
        ? (light ? "rgba(5, 150, 105, 0.55)" : `rgba(0, 255, 100, ${p.alpha + 0.3})`)
        : (light ? `rgba(79, 131, 241, ${p.alpha * 0.8})` : `rgba(79, 131, 241, ${p.alpha})`);
      ctx.fill();
    });

    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < CONNECT_DIST) {
          const alpha = (1 - d / CONNECT_DIST) * (light ? 0.08 : 0.12);
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = light
            ? `rgba(79, 131, 241, ${alpha})`
            : `rgba(0, 230, 118, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    if (mouse.x > 0) {
      ctx.beginPath();
      ctx.arc(mouse.x, mouse.y, 80, 0, Math.PI * 2);
      const g = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 80);
      g.addColorStop(0, "rgba(77, 128, 255, 0.06)");
      g.addColorStop(1, "transparent");
      ctx.fillStyle = g;
      ctx.fill();
    }

    animId = requestAnimationFrame(animate);
  }

  function initPageEntrance() {
    document.querySelectorAll("[data-anim]").forEach((el, i) => {
      el.style.animationDelay = `${i * 0.08}s`;
    });
    document.querySelectorAll(".sidebar-nav .nav-item").forEach((el, i) => {
      el.style.animation = "fadeInLeft 0.45s cubic-bezier(0.16, 1, 0.3, 1) both";
      el.style.animationDelay = `${0.04 + i * 0.025}s`;
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
