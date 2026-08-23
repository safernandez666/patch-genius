/* Selector de tema claro/oscuro
 * (el original soporta varios "brands" de cliente; acá solo hay dos temas
 * visuales, sin logos ni paletas de marca).
 *
 * El estado se guarda en localStorage('soc.theme'); default = "soc" (oscuro).
 * El <head> ya fija data-theme ANTES de pintar para no parpadear; acá
 * reaplicamos (idempotente) + favicon + meta + hook de página. */
(function () {
  var KEY = "soc.theme";
  var THEMES = {
    light: {
      mode: "light",
      favicon: "/static/assets/genie.svg",
      faviconType: "image/svg+xml",
      metaColor: "#465fff",
      label: "Claro",
    },
    soc: {
      mode: "dark",
      favicon: "/static/assets/genie.svg",
      faviconType: "image/svg+xml",
      metaColor: "#0b1020",
      label: "Oscuro",
    },
  };
  var ORDER = ["light", "soc"];

  function get() {
    try {
      var v = localStorage.getItem(KEY);
      return THEMES[v] ? v : "soc";
    } catch (e) {
      return "soc";
    }
  }

  function apply(name, silent) {
    var t = THEMES[name] || THEMES.light;
    var root = document.documentElement;
    root.setAttribute("data-theme", t.mode);
    root.setAttribute("data-brand", name);

    document.querySelectorAll('link[rel="icon"]').forEach(function (l) {
      l.setAttribute("type", t.faviconType);
      l.setAttribute("href", t.favicon);
    });
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", t.metaColor);

    try {
      localStorage.setItem(KEY, name);
    } catch (e) {
      /* sin persistencia: el tema sigue en memoria. */
    }
    updateUI(name);
    if (!silent && typeof window.__onThemeChange === "function") {
      try {
        window.__onThemeChange(name);
      } catch (e) {}
    }
  }

  function set(name) {
    apply(name);
  }
  function toggle() {
    var i = ORDER.indexOf(get());
    apply(ORDER[(i + 1) % ORDER.length]);
  }

  function updateUI(name) {
    var btn = document.getElementById("themeToggle");
    if (btn) {
      var idx = ORDER.indexOf(THEMES[name] ? name : "soc");
      var other = THEMES[ORDER[(idx + 1) % ORDER.length]].label;
      btn.setAttribute("title", "Cambiar a tema " + other);
      btn.setAttribute("aria-label", "Cambiar a tema " + other);
    }
  }

  window.setTheme = set;
  window.toggleTheme = toggle;
  window.getTheme = get;

  function init() {
    apply(get(), true);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
