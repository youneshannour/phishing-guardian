/**
 * Matrix Rain — zone principale (adapté au thème sombre / clair)
 */
(function () {
  const wrap = document.querySelector(".main-matrix");
  const canvas = document.getElementById("matrixCanvas");
  if (!wrap || !canvas) return;

  const ctx = canvas.getContext("2d");
  const glyphs = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝ01アイウエオ";
  const size = 15;
  let cols = [];
  let w = 0;
  let h = 0;
  let mouseX = -999;
  let mouseY = -999;

  function isLight() {
    return document.documentElement.getAttribute("data-theme") === "light";
  }

  function palette() {
    if (isLight()) {
      return {
        fade: "rgba(232, 238, 248, 0.14)",
        head: "#047857",
        headMouse: "#059669",
        trail: (a) => `rgba(5, 150, 105, ${a})`,
      };
    }
    return {
      fade: "rgba(3, 5, 8, 0.06)",
      head: "#d4ffe0",
      headMouse: "#ffffff",
      trail: (a) => `rgba(0, 255, ${55 + Math.floor(Math.random() * 50)}, ${a})`,
    };
  }

  wrap.addEventListener("mousemove", (e) => {
    const r = wrap.getBoundingClientRect();
    mouseX = e.clientX - r.left;
    mouseY = e.clientY - r.top;
  });
  wrap.addEventListener("mouseleave", () => { mouseX = -999; mouseY = -999; });

  function resize() {
    const r = wrap.getBoundingClientRect();
    w = Math.max(1, Math.floor(r.width));
    h = Math.max(1, Math.floor(r.height));
    canvas.width = w;
    canvas.height = h;
    const n = Math.ceil(w / size);
    cols = Array.from({ length: n }, (_, i) => (cols[i] ?? Math.random()) * (h / size));
  }

  function frame() {
    const p = palette();
    ctx.fillStyle = p.fade;
    ctx.fillRect(0, 0, w, h);
    ctx.font = `${size}px "JetBrains Mono", monospace`;

    for (let i = 0; i < cols.length; i++) {
      const ch = glyphs[Math.floor(Math.random() * glyphs.length)];
      const x = i * size;
      const y = cols[i] * size;
      const nearMouse = mouseX > 0 && Math.hypot(x - mouseX, y - mouseY) < 120;
      const head = Math.random() > 0.988 || nearMouse;
      const alpha = 0.28 + Math.random() * 0.45;

      if (head) {
        ctx.fillStyle = nearMouse ? p.headMouse : p.head;
      } else {
        ctx.fillStyle = isLight()
          ? p.trail(alpha * 0.7)
          : p.trail(alpha);
      }

      ctx.fillText(ch, x, y);
      if (y > h && Math.random() > 0.972) cols[i] = 0;
      cols[i]++;
    }
    requestAnimationFrame(frame);
  }

  resize();
  frame();
  window.addEventListener("resize", resize);
  window.addEventListener("pg-theme-change", resize);
  if (window.ResizeObserver) new ResizeObserver(resize).observe(wrap);
})();
