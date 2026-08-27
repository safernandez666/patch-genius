/* Restaura el tema y el estado del menú antes del primer paint, para que la
 * página no parpadee.
 *
 * Tiene que ser un <script> clásico en el <head> (sin defer ni async): así
 * corre mientras el parser está bloqueado, antes de que se pinte nada. Un
 * módulo o un defer llegarían tarde y se vería el flash del tema anterior.
 *
 * Vive en un archivo aparte porque lo cargan las ocho páginas. Estaba escrito a
 * mano en el <head> de index.html nada más, y ese era justamente el motivo por
 * el que el resto del panel ignoraba el tema elegido y se veía siempre oscuro.
 *
 * theme.js vuelve a aplicar lo mismo cuando carga (es idempotente) y además se
 * ocupa del favicon, del meta y del botón. Acá sólo van los atributos, que es
 * lo único que necesita el CSS.
 */
(function () {
  try {
    /* El menú colapsado es el mismo problema: si se restaura después del paint
       se ve la barra abrirse y cerrarse sola en cada navegación. */
    if (localStorage.getItem("soc.navCollapsed") === "1") {
      document.documentElement.classList.add("nav-collapsed");
    }
  } catch (e) {
    /* sin persistencia el menú arranca abierto, que es el default */
  }
  try {
    var t = localStorage.getItem("soc.theme");
    if (t !== "soc" && t !== "light") t = "soc";
    document.documentElement.setAttribute("data-theme", t === "soc" ? "dark" : "light");
    document.documentElement.setAttribute("data-brand", t);
  } catch (e) {
    /* localStorage bloqueado: el default del panel es el tema oscuro. */
    document.documentElement.setAttribute("data-theme", "dark");
    document.documentElement.setAttribute("data-brand", "soc");
  }
})();
