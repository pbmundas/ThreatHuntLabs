(() => {
  const shellStylesheet = "/assets/stylesheets/site-shell.css";
  const links = [
    { label: "Home", href: "/", match: (path) => path === "/" || path === "/index.html" },
    { label: "Foundations", href: "/foundations/Threat-Hunting-Explained-Beyond-Alerts-Dashboards-and-SIEM-Queries/", match: (path) => path.startsWith("/foundations/") || path.startsWith("/Start-Hunting/") },
    { label: "Hypothesis", href: "/hypothesis/", match: (path) => path.startsWith("/hypothesis/") },
    { label: "Learn Attacks", href: "/learn-known-cyber-attacks/", match: (path) => path.startsWith("/learn-known-cyber-attacks/") || path.startsWith("/attack-encyclopedia/") },
    { label: "Case Studies", href: "/case-studies/2010-Stuxnet-Retrospective-Threat-Hunt-Report/", match: (path) => path.startsWith("/case-studies/") },
    { label: "Products", href: "/products/AI-Agentic-THOS-Threat-Hunting-Operating-System.html", match: (path) => path.startsWith("/products/") },
    { label: "Resources", href: "/threat-hunting-reports/", match: (path) => path.startsWith("/threat-hunting-reports/") || path.startsWith("/threat-hunting-lab/") || path.startsWith("/Downloads/") },
    { label: "Blog", href: "https://blog.threathuntlabs.com", external: true, match: () => false }
  ];

  function addStylesheet() {
    if (document.querySelector(`link[href="${shellStylesheet}"]`)) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = shellStylesheet;
    document.head.appendChild(link);
  }

  function projectHeaders() {
    const selectors = [
      "body > header:not(.thl-site-chrome)",
      "main > .site-header",
      "body > .site-header",
      "body > .topbar"
    ];
    document.querySelectorAll(selectors.join(",")).forEach((header) => {
      header.classList.add("thl-project-header");
    });
  }

  function createChrome() {
    if (document.querySelector(".thl-site-chrome") || document.querySelector(".md-header")) return;

    addStylesheet();
    const path = window.location.pathname || "/";
    const isWide = path.startsWith("/threat-hunting-lab/") || path.includes("threat-hunting-device-logs-telemetry-details");
    document.body.classList.add("thl-shell-ready", isWide ? "thl-layout-wide" : "thl-layout-standard");

    const chrome = document.createElement("header");
    chrome.className = "thl-site-chrome";
    chrome.dataset.menuOpen = "false";
    chrome.innerHTML = `
      <div class="thl-global-masthead">
        <div class="thl-global-masthead__inner">
          <a class="thl-global-brand" href="/" aria-label="Threat Hunt Labs home">
            <span class="thl-global-brand__mark" aria-hidden="true">THL</span>
            <span>Threat Hunt Labs</span>
          </a>
          <span class="thl-global-context">Open defender knowledge base</span>
          <button class="thl-global-menu-button" type="button" aria-expanded="false" aria-controls="thl-global-navigation">Menu</button>
        </div>
      </div>
      <div class="thl-global-nav">
        <nav class="thl-global-nav__inner" id="thl-global-navigation" aria-label="Global navigation"></nav>
      </div>`;

    const nav = chrome.querySelector("nav");
    links.forEach((item) => {
      const anchor = document.createElement("a");
      anchor.href = item.href;
      anchor.textContent = item.label;
      if (item.match(path)) anchor.setAttribute("aria-current", "page");
      if (item.external) {
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer";
      }
      nav.appendChild(anchor);
    });

    const toggle = chrome.querySelector("button");
    toggle.addEventListener("click", () => {
      const open = chrome.dataset.menuOpen !== "true";
      chrome.dataset.menuOpen = String(open);
      toggle.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || chrome.dataset.menuOpen !== "true") return;
      chrome.dataset.menuOpen = "false";
      toggle.setAttribute("aria-expanded", "false");
      toggle.focus();
    });

    document.body.prepend(chrome);
    projectHeaders();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", createChrome, { once: true });
  } else {
    createChrome();
  }
})();
