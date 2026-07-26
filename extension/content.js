/**
 * Content script — détecte la sélection et expose l'URL de la page au popup.
 */
(function () {
  document.addEventListener("mouseup", () => {
    const text = (window.getSelection()?.toString() || "").trim();
    if (text.length >= 3 && text.length <= 200) {
      chrome.runtime.sendMessage({ type: "PG_SELECTION", text }).catch(() => {});
    }
  });
})();
