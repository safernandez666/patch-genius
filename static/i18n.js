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
  var DICT = {
    es: {
      "brand.tagline": "Vulnerability and patch tracking on top of your own Wazuh. Prioritised with CISA KEV and EPSS.",

      "login.title": "Sign in",
      "login.sub": "Sign in to your account to see the vulnerability inventory.",
      "login.user": "Username",
      "login.pass": "Password",
      "login.submit": "Sign in",
      "login.bad": "Wrong username or password.",
      "login.down": "Could not reach the server.",

      "signup.title": "Create your account",
      "signup.sub": "This installation has no account yet. The first one you create is the administrator.",
      "signup.user": "Username *",
      "signup.pass": "Password *",
      "signup.pass2": "Repeat password *",
      "signup.submit": "Create account and sign in",
      "signup.note": "This page closes itself as soon as an account exists. It is not open registration — nobody else will be able to sign up here.",
      "signup.mismatch": "The passwords do not match.",
      "signup.short": "The password needs at least 12 characters.",
      "signup.taken": "An account already exists. Go to Sign in.",
      "signup.fail": "Could not create the account.",

      "nav.vulns": "Vulnerabilities",
      "nav.config": "Configuration",
      "nav.integrations": "Integrations",
      "nav.help": "Help",
      "nav.logout": "Sign out",
      "nav.source": "Source",

      "page.title": "Vulnerabilities — patch tracking",
      "page.desc.pre": "Fleet state read from your Wazuh, prioritised by",
      "page.desc.link": "How prioritisation, aging and the SLA work",

      "stat.kev": "In CISA KEV",
      "stat.kev.hint": "confirmed active exploitation",
      "stat.prio": "Critical priority",
      "stat.sla": "Criticals past SLA",
      "stat.ca": "Critical + high",
      "stat.ca.hint": "of the fleet's unique CVEs",
      "stat.total": "Active vulnerabilities",
      "stat.cves": "Unique CVEs",
      "stat.srv": "Servers",
      "stat.ransom": "Known ransomware",
      "stat.epss": "High EPSS",
      "stat.new": "New (7 days)",
      "stat.resolved": "Resolved (7 days)",
      "stat.reopened": "Reopened (7 days)",
      "stat.aging": "Average aging",
      "stat.aging.hint": "days since detection (active)",
      "stat.slapct": "Criticals resolved in SLA",
      "stat.slapct.hint": "% remediated within the window",

      "chart.evolution": "Trend",
      "chart.severity": "By severity",
      "chart.platform": "By platform",
      "chart.platform.sub": "A CVE present on Linux and Windows counts in both, so the total can exceed the unique CVE count.",
      "chart.packages": "Top vulnerable packages",
      "chart.os": "Operating-system level vulnerabilities",
      "chart.servers": "By server",

      "filter.severities": "All severities",
      "filter.platforms": "All platforms",
      "filter.owners": "All owners",
      "filter.statuses": "All statuses",
      "filter.servers": "All servers",
      "filter.kev": "CISA KEV only (active exploitation)",
      "filter.ransom": "With known ransomware",
      "filter.search": "Search CVE / package…",
      "filter.quick": "Quick views:",
      "filter.clear": "Clear all",

      "qf.kev": "Active exploitation (KEV)",
      "qf.score": "Priority ≥ 80",
      "qf.sla": "Criticals past SLA",
      "qf.os": "Operating-system patches",
      "qf.untriaged": "Untriaged",

      "sev.Critical": "Critical", "sev.High": "High", "sev.Medium": "Medium",
      "sev.Low": "Low", "sev.Untriaged": "Untriaged",

      "table.title": "Fleet CVEs",
      "table.cve": "CVE", "table.sev": "Severity", "table.prio": "Priority",
      "table.pkgs": "Packages / Servers", "table.detected": "Detected",
      "table.owner": "Owner", "table.status": "Status",
      "table.empty.h": "No CVEs match those filters",
      "table.empty.p": "Try widening the search or removing filters.",
      "table.track": "Track",

      "pager.size": "Rows per page",
      "pager.prev": "Previous",
      "pager.next": "Next",
      "pager.showing": "Showing",
      "pager.of": "of",

      "setup.title": "No data yet.",
      "setup.body": "Connect your Wazuh in Configuration and run the first refresh.",
      "updated": "Updated",
    },
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
      // El texto del HTML es el fallback: una clave que falta deja el español.
      if (!el.dataset.i18nEn) el.dataset.i18nEn = el.innerHTML;
      var v = lang === "en" ? el.dataset.i18nEn : (DICT[lang] || {})[key];
      if (v) el.innerHTML = v;
    });
    document.documentElement.lang = lang;
  }

  function set(next) {
    lang = DICT[next] || next === "en" ? next : "en";
    apply();
    global.dispatchEvent(new CustomEvent("i18n:changed", { detail: { lang: lang } }));
  }

  // El idioma sale de la config del servidor. Se pide una sola vez y no bloquea
  // el render: la página ya está en español, así que un fallo deja español.
  async function init() {
    try {
      var r = await fetch("/api/lang");
      if (r.ok) { var d = await r.json(); set(d.lang || "en"); return; }
    } catch (e) { /* offline: stays English */ }
    apply();
  }

  global.t = t;
  global.i18n = { set: set, apply: apply, get lang() { return lang; }, init: init };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else { init(); }
})(window);
