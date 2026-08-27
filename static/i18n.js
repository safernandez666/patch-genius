/* Interface translation.
 *
 * The language is a global setting for the installation, not a per-user
 * preference: in a SOC the same screen is read by the whole team, and having it
 * differ per person costs more than it gives.
 *
 * The markup is written in English and translatable nodes carry data-i18n. A
 * missing key falls back to the text already in the HTML, so an incomplete
 * translation shows English — never a raw key and never a gap.
 */
(function (global) {
  // El panel se entrega en ingles. `es` esta vacio a proposito: las claves que
  // habia eran todas el texto ingles, asi que elegir "Espanol" devolvia ingles
  // igual — una traduccion que parecia existir y no existia. Aca es donde va una
  // traduccion de verdad el dia que se escriba; mientras tanto cada nodo se
  // queda con el texto del HTML, que ya es el idioma correcto.
  var DICT = {
    es: {},
  };

  var lang = "en";

  function t(key, fallback) {
    if (lang === "en") return fallback !== undefined ? fallback : key;
    var d = DICT[lang];
    return (d && d[key]) || (fallback !== undefined ? fallback : key);
  }

  function apply(root) {
    (root || document).querySelectorAll("[data-i18n]").forEach(function (el) {
      var key = el.getAttribute("data-i18n");
      // El texto del HTML es el fallback, y el HTML esta en ingles: una clave
      // que falta deja ingles, nunca un hueco ni la clave cruda.
      if (!el.dataset.i18nEn) el.dataset.i18nEn = el.innerHTML;
      var v = lang === "en" ? el.dataset.i18nEn : (DICT[lang] || {})[key];
      if (v) el.innerHTML = v;
    });
    // El atributo lang le dice al lector de pantalla como pronunciar. Mientras
    // no exista la traduccion, el contenido sigue siendo ingles aunque la
    // instalacion este en "es": marcarlo como "es" lo haria leer ingles con
    // fonetica castellana.
    var translated = lang === "en" || Object.keys(DICT[lang] || {}).length > 0;
    document.documentElement.lang = translated ? lang : "en";
  }

  function set(next) {
    lang = (DICT[next] || next === "en") ? next : "en";
    apply();
    global.dispatchEvent(new CustomEvent("i18n:changed", { detail: { lang: lang } }));
  }

  // El idioma sale de la config del servidor. Se pide una sola vez y no bloquea
  // el render: la pagina ya esta en ingles, asi que un fallo la deja en ingles.
  async function init() {
    try {
      var r = await fetch("/api/lang");
      if (r.ok) { var d = await r.json(); set(d.lang || "en"); return; }
    } catch (e) { /* sin respuesta del servidor: se queda en ingles */ }
    apply();
  }

  global.t = t;
  global.i18n = { set: set, apply: apply, get lang() { return lang; }, init: init };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else { init(); }
})(window);
