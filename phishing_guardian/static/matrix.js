/**
 * Matrix Rain — zone principale uniquement (style capture)
 */
(function () {
  const wrap = document.querySelector(".main-matrix");
  const canvas = document.getElementById("matrixCanvas");
  if (!wrap || !canvas) return;

  const ctx = canvas.getContext("2d");
  const glyphs = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝ01";
  const size = 15;
  let cols = [];
  let w = 0;
  let h = 0;

  function resize() {
    const r = wrap.getBoundingClientRect();
    w = Math.max(1, Math.floor(r.width));
    h = Math.max(1, Math.floor(r.height));
    canvas.width = w;
    canvas.height = h;
    const n = Math.ceil(w / size);
    cols = Array.from({ length: n }, (_, i) => cols[i] ?? Math.random() * (h / size));
  }

  function frame() {
    ctx.fillStyle = "rgba(3, 5, 8, 0.06)";
    ctx.fillRect(0, 0, w, h);
    ctx.font = `${size}px "JetBrains Mono", monospace`;

    for (let i = 0; i < cols.length; i++) {
      const ch = glyphs[Math.floor(Math.random() * glyphs.length)];
      const x = i * size;
      const y = cols[i] * size;
      const head = Math.random() > 0.988;
      ctx.fillStyle = head
        ? "#d4ffe0"
        : `rgba(0, 255, ${55 + Math.floor(Math.random() * 50)}, ${0.28 + Math.random() * 0.45})`;
      ctx.fillText(ch, x, y);
      if (y > h && Math.random() > 0.972) cols[i] = 0;
      cols[i]++;
    }
    requestAnimationFrame(frame);
  }

  resize();
  frame();
  window.addEventListener("resize", resize);
  if (window.ResizeObserver) new ResizeObserver(resize).observe(wrap);
})();
