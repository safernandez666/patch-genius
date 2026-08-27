/* Colapso del sidebar (compartido por todas las páginas del panel).
 *
 * - toggleNav(): alterna la clase `nav-collapsed` sobre <html> y persiste el
 *   estado en localStorage. El <head> de cada página ya restaura el estado al
 *   cargar (para no parpadear); acá sólo inyectamos los botones y el toggle.
 * - Inyecta un botón "colapsar" dentro del sidebar y un botón flotante
 *   "mostrar" que sólo se ve cuando está colapsado. */
(function () {
  var STORE_KEY = "soc.navCollapsed";
  // Mismo punto de corte que el @media de sidebar.css.
  var NARROW = "(max-width: 900px)";

  function isNarrow() {
    return window.matchMedia && window.matchMedia(NARROW).matches;
  }

  /* En pantallas angostas el menú es un panel que se desliza por encima del
     contenido, así que el botón abre y cierra (clase `nav-open`) en vez de
     alternar el colapso del escritorio. El estado NO se persiste: dejar el
     menú abierto entre páginas taparía el contenido al volver. */
  function closeNav() {
    document.documentElement.classList.remove("nav-open");
  }

  function toggleNav() {
    if (isNarrow()) {
      document.documentElement.classList.toggle("nav-open");
      return;
    }
    var collapsed = document.documentElement.classList.toggle("nav-collapsed");
    try {
      localStorage.setItem(STORE_KEY, collapsed ? "1" : "0");
    } catch (e) {
      /* localStorage no disponible: el toggle sigue funcionando en memoria. */
    }
  }
  window.toggleNav = toggleNav;

  var COLLAPSE_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/></svg>';
  var REOPEN_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';

  function init() {
    var sidebar = document.querySelector(".sidebar");
    if (!sidebar) return;

    if (!sidebar.querySelector(".nav-collapse-btn")) {
      var collapseBtn = document.createElement("button");
      collapseBtn.type = "button";
      collapseBtn.className = "nav-collapse-btn";
      collapseBtn.title = "Colapsar menú";
      collapseBtn.setAttribute("aria-label", "Colapsar menú");
      collapseBtn.innerHTML = COLLAPSE_ICON;
      collapseBtn.addEventListener("click", toggleNav);
      sidebar.appendChild(collapseBtn);
    }

    if (!document.querySelector(".nav-reopen")) {
      var reopenBtn = document.createElement("button");
      reopenBtn.type = "button";
      reopenBtn.className = "nav-reopen";
      reopenBtn.title = "Mostrar menú";
      reopenBtn.setAttribute("aria-label", "Mostrar menú");
      reopenBtn.innerHTML = REOPEN_ICON;
      reopenBtn.addEventListener("click", toggleNav);
      document.body.appendChild(reopenBtn);
    }

    // Segundo botón de colapsar AL PIE del sidebar (en flujo, antes del footer),
    // para no tener que subir hasta arriba. Pedido del usuario: "arriba y abajo".
    if (!sidebar.querySelector(".nav-collapse-foot")) {
      var foot = sidebar.querySelector(".sidebar-foot");
      var footBtn = document.createElement("button");
      footBtn.type = "button";
      footBtn.className = "nav-collapse-foot";
      footBtn.title = "Colapsar menú";
      footBtn.setAttribute("aria-label", "Colapsar menú");
      footBtn.innerHTML = COLLAPSE_ICON + "<span>Colapsar</span>";
      footBtn.addEventListener("click", toggleNav);
      if (foot) sidebar.insertBefore(footBtn, foot);
      else sidebar.appendChild(footBtn);
    }

    // Segundo botón flotante de "mostrar" ABAJO a la izquierda (sólo visible al
    // estar colapsado), espejo del de arriba.
    if (!document.querySelector(".nav-reopen-bottom")) {
      var reopenBottom = document.createElement("button");
      reopenBottom.type = "button";
      reopenBottom.className = "nav-reopen nav-reopen-bottom";
      reopenBottom.title = "Mostrar menú";
      reopenBottom.setAttribute("aria-label", "Mostrar menú");
      reopenBottom.innerHTML = REOPEN_ICON;
      reopenBottom.addEventListener("click", toggleNav);
      document.body.appendChild(reopenBottom);
    }

    // Fondo para cerrar tocando afuera (sólo se ve en pantallas angostas).
    if (!document.querySelector(".nav-backdrop")) {
      var backdrop = document.createElement("div");
      backdrop.className = "nav-backdrop";
      backdrop.setAttribute("aria-hidden", "true");
      backdrop.addEventListener("click", closeNav);
      document.body.appendChild(backdrop);
    }

    // Tocar una sección navega a otra página: el panel tiene que quedar cerrado
    // en la siguiente, no tapando lo que el analista fue a ver.
    sidebar.querySelectorAll(".side-nav a").forEach(function (a) {
      a.addEventListener("click", closeNav);
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeNav();
    });

    // Al pasar a una pantalla ancha el panel deja de tener sentido: el sidebar
    // vuelve al flujo y `nav-open` quedaría pegado sin nada que lo cierre.
    if (window.matchMedia) {
      var mq = window.matchMedia(NARROW);
      var onChange = function (e) { if (!e.matches) closeNav(); };
      if (mq.addEventListener) mq.addEventListener("change", onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
  }

  /* Perfil de la sesión.
   *
   * El servidor es el que manda: un perfil de solo lectura tiene bloqueado
   * TODO método que muta, por middleware, aunque el botón siga en pantalla.
   * Esto es para que la persona sepa en qué perfil está antes de intentar algo
   * y comerse un 403 sin contexto — no es el control de acceso.
   *
   * Marca <html class="role-readonly"> y expone window.SOC_ROLE, así cualquier
   * elemento con [data-requires-admin] desaparece por CSS. */
  var ROLES = {
    admin: {
      texto: "Administrador",
      ayuda: "Podés aprobar acciones y cambiar la configuración.",
    },
    readonly: {
      texto: "Solo lectura",
      ayuda: "Podés ver todo el panel; no ejecutar acciones ni cambiar la configuración.",
    },
  };

  function marcarPerfil() {
    fetch("/auth/me", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var u = d && d.user;
        var rol = u && u.role;
        if (!rol) return;
        window.SOC_ROLE = rol;
        if (rol === "readonly") document.documentElement.classList.add("role-readonly");

        var pie = document.querySelector(".sidebar-foot");
        if (!pie || document.getElementById("userBox")) return;

        // Quién está operando. En un panel donde se aprueban acciones que se
        // ejecutan de verdad, la sesión no puede ser anónima para el que la
        // usa: el nombre de arriba es el que va a quedar en la auditoría.
        var meta = ROLES[rol] || { texto: rol, ayuda: "" };
        var caja = document.createElement("div");
        caja.id = "userBox";
        caja.className = "user-box";

        var nombre = (u.name || "").trim();
        var cuenta = (u.username || "").trim();
        var inicial = (nombre || cuenta || "?").trim().charAt(0).toUpperCase();

        var av = document.createElement("span");
        av.className = "user-avatar";
        av.setAttribute("aria-hidden", "true");
        av.textContent = inicial;

        var datos = document.createElement("span");
        datos.className = "user-datos";

        var n = document.createElement("span");
        n.className = "user-name";
        // En modo básico no hay nombre para mostrar, sólo el usuario.
        n.textContent = nombre || cuenta;
        n.title = cuenta;

        var b = document.createElement("span");
        b.id = "rolBadge";
        b.className = "rol-badge rol-" + rol;
        b.textContent = meta.texto;
        b.title = meta.ayuda;

        datos.appendChild(n);
        datos.appendChild(b);
        caja.appendChild(av);
        caja.appendChild(datos);
        // Va ARRIBA del pie (tema + salir), no adentro: ese pie es una fila y
        // meterle la identidad la aprieta contra los botones.
        pie.parentNode.insertBefore(caja, pie);
      })
      .catch(function () { /* el panel funciona igual sin esto */ });
  }

  /* Salir. Estaba en el JS inline de index.html, asi que el boton del pie
     funcionaba en el dashboard y era un no-op en las demas pantallas — que
     hasta ahora no tenian menu, y ahora si. */
  function doLogout() {
    fetch("/api/logout", { method: "POST", credentials: "same-origin" })
      .catch(function () { /* igual salimos */ })
      .then(function () { window.location = "/login"; });
  }
  window.doLogout = doLogout;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { init(); marcarPerfil(); });
  } else {
    init();
    marcarPerfil();
  }
})();
