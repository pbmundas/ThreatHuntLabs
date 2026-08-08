(() => {
  const shellStylesheet = "/assets/stylesheets/site-shell.css";
  const links = [
    { label: "Home", href: "/", match: (path) => path === "/" || path === "/index.html" },
    {
      label: "Foundations",
      href: "/foundations/2025-07-20-unknown-facts-about-threat-hunting/",
      match: (path) => path.startsWith("/foundations/") || path.startsWith("/Start-Hunting/"),
      children: [
        ["Unknown Facts", "/foundations/2025-07-20-unknown-facts-about-threat-hunting/"],
        ["10 Common Mistakes", "/foundations/10-Common-Mistakes-Every-Beginner-Makes-When-Learning-Threat-Hunting/"],
        ["Cybersecurity Fundamentals", "/foundations/Cybersecurity-Fundamentals-The-Foundation-Every-Threat-Hunter-Needs-part-1/"],
        ["Why and Where Threat Hunting", "/foundations/Why-Every-Organization-Needs-Threat-Hunting/"],
        ["Threat Hunting Explained", "/foundations/Threat-Hunting-Explained-Beyond-Alerts-Dashboards-and-SIEM-Queries/"],
        ["Data Pipeline", "/foundations/Threat-Hunting-Data-Pipeline/"],
        ["Life Cycle", "/foundations/Inside-a-Threat-Hunt-Understanding-the-Threat-Hunting-Lifecycle/"],
        ["Types", "/foundations/Types-of-Threat-Hunting-Choosing-the-Right-Hunting-Strategy/"],
        ["Data Analysis Techniques", "/foundations/Threat-Hunting-Data-Analysis-Techniques/"],
        ["Hypothesis Development", "/foundations/Hypothesis-Development-Thinking-Like-a-Threat-Hunter-Before-Writing-a-Single-Query/"],
        ["Methodologies", "/foundations/Threat-Hunting-Methodologies-Choosing-the-Right-Hunting-Approach/"],
        ["Mindset", "/foundations/The-Threat-Hunting-Mindset-Thinking-Like-an-Attacker/"],
        ["Maturity Model", "/foundations/The-Threat-Hunting-Maturity-Model-Explained/"],
        ["Lab Setup", "/Start-Hunting/threat-hunting-lab/"],
        ["Reading Logs", "/Start-Hunting/Reading-Raw-Logs-Like-a-Threat-Hunter/"],
        ["Solo Hunter to Enterprise", "/Start-Hunting/threat-hunting-program-models/"],
        ["Reporting", "/Start-Hunting/threat-hunting-documentation/"],
        ["Telemetry & Logs to collect", "/Start-Hunting/threat-hunting-device-logs-telemetry-details.html"],
        ["Low Hanging Fruits", "/Start-Hunting/low-hanging-fruits-threat-hunting/"]
      ]
    },
    { label: "Hypothesis", href: "/hypothesis/", match: (path) => path.startsWith("/hypothesis/") },
    {
      label: "Learn Attacks",
      href: "/learn-known-cyber-attacks/",
      external: true,
      match: (path) => path.startsWith("/learn-known-cyber-attacks/") || path.startsWith("/attack-encyclopedia/"),
      children: [
        ["Attacks in History", "/learn-known-cyber-attacks/", true],
        ["Attacks Encyclopedia", "/attack-encyclopedia/"]
      ]
    },
    {
      label: "Case Studies",
      href: "/case-studies/2010-Stuxnet-Retrospective-Threat-Hunt-Report/",
      match: (path) => path.startsWith("/case-studies/"),
      children: [
        ["Stuxnet (2010)", "/case-studies/2010-Stuxnet-Retrospective-Threat-Hunt-Report/"],
        ["RSA-SecurID (2011)", "/case-studies/2011-RSA-SecurID-Retrospective-Threat-Hunt-Report/"],
        ["Linkedin (2012)", "/case-studies/2012-linkedin-threat-hunt-report/"],
        ["Adobe (2013)", "/case-studies/2013-adobe-threat-hunt-report/"],
        ["Hugging Face & OpenAI (2026)", "/case-studies/2026-openai-huggingface-incident-explainer/"]
      ]
    },
    {
      label: "Products",
      href: "/products/AI-Agentic-THOS-Threat-Hunting-Operating-System.html",
      match: (path) => path.startsWith("/products/"),
      children: [
        ["THOS", "/products/AI-Agentic-THOS-Threat-Hunting-Operating-System.html"],
        ["Walkthrough", "/products/THOS-Walkthrough-Blog/"]
      ]
    },
    {
      label: "Resources",
      href: "https://intel.threathuntlabs.com",
      external: true,
      match: (path) => path.startsWith("/threat-hunting-reports/") || path.startsWith("/threat-hunting-lab/") || path.startsWith("/Downloads/"),
      children: [
        ["🎯Daily Intel", "https://intel.threathuntlabs.com", true],
        ["Hunting Reports", "/threat-hunting-reports/"],
        ["Challenges", "/threat-hunting-lab/"],
        ["Downloads", "/Downloads/threat-hunting-related-document-references/"]
      ]
    },
    { label: "Blog", href: "https://blog.threathuntlabs.com", external: true, match: () => false }
  ];

  const icons = {
    book: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8a3 3 0 0 0 3-3 3 3 0 0 0-3-3 3 3 0 0 0-3 3 3 3 0 0 0 3 3m0 3.54C9.64 9.35 6.5 8 3 8v11c3.5 0 6.64 1.35 9 3.54 2.36-2.19 5.5-3.54 9-3.54V8c-3.5 0-6.64 1.35-9 3.54"></path></svg>',
    menu: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z"></path></svg>',
    search: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9.5 3A6.5 6.5 0 0 1 16 9.5c0 1.61-.59 3.09-1.56 4.23l.27.27h.79l5 5-1.5 1.5-5-5v-.79l-.27-.27A6.52 6.52 0 0 1 9.5 16 6.5 6.5 0 0 1 3 9.5 6.5 6.5 0 0 1 9.5 3m0 2C7 5 5 7 5 9.5S7 14 9.5 14 14 12 14 9.5 12 5 9.5 5"></path></svg>'
  };

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
    document.querySelectorAll(selectors.join(",")).forEach((header) => header.classList.add("thl-project-header"));
  }

  function normalizePath(value) {
    const path = value.replace(/index\.html$/, "").replace(/\/$/, "");
    return path || "/";
  }

  function isCurrentLink(href, path) {
    return href.startsWith("/") && normalizePath(href) === normalizePath(path);
  }

  function setExternal(anchor, external) {
    if (!external) return;
    anchor.target = "_blank";
    anchor.rel = "noopener noreferrer";
  }

  function closeDropdowns(list, except = null) {
    list.querySelectorAll(".md-tabs__item--dropdown-open").forEach((item) => {
      if (item === except) return;
      item.classList.remove("md-tabs__item--dropdown-open");
      item.querySelector(":scope > .md-tabs__link")?.setAttribute("aria-expanded", "false");
    });
  }

  function buildDesktopTabs(list, path) {
    links.forEach((item) => {
      const tab = document.createElement("li");
      tab.className = "md-tabs__item";
      if (item.match(path)) tab.classList.add("md-tabs__item--active");

      const anchor = document.createElement("a");
      anchor.className = "md-tabs__link";
      anchor.href = item.href;
      anchor.textContent = item.label;
      setExternal(anchor, item.external);
      tab.appendChild(anchor);

      if (item.children) {
        tab.classList.add("md-tabs__item--has-dropdown");
        anchor.setAttribute("aria-haspopup", "true");
        anchor.setAttribute("aria-expanded", "false");

        const dropdown = document.createElement("div");
        dropdown.className = "thl-tab-dropdown";
        dropdown.setAttribute("aria-label", `${item.label} submenu`);
        item.children.forEach(([label, href, external]) => {
          const child = document.createElement("a");
          child.className = "thl-tab-dropdown__link";
          child.href = href;
          child.textContent = label;
          if (isCurrentLink(href, path)) {
            child.classList.add("thl-tab-dropdown__link--active");
            child.setAttribute("aria-current", "page");
          }
          setExternal(child, external);
          dropdown.appendChild(child);
        });
        tab.appendChild(dropdown);

        anchor.addEventListener("click", (event) => {
          event.preventDefault();
          const open = !tab.classList.contains("md-tabs__item--dropdown-open");
          closeDropdowns(list, tab);
          tab.classList.toggle("md-tabs__item--dropdown-open", open);
          anchor.setAttribute("aria-expanded", String(open));
        });
      } else if (item.match(path)) {
        anchor.setAttribute("aria-current", "page");
      }
      list.appendChild(tab);
    });
  }

  function buildMobileNavigation(nav, path) {
    links.forEach((item, index) => {
      const group = document.createElement("div");
      group.className = "thl-mobile-nav__group";

      if (item.children) {
        const trigger = document.createElement("button");
        const panelId = `thl-mobile-panel-${index}`;
        trigger.className = "thl-mobile-nav__trigger";
        trigger.type = "button";
        trigger.textContent = item.label;
        trigger.setAttribute("aria-expanded", "false");
        trigger.setAttribute("aria-controls", panelId);
        if (item.match(path)) trigger.classList.add("is-active");

        const panel = document.createElement("div");
        panel.className = "thl-mobile-nav__panel";
        panel.id = panelId;
        item.children.forEach(([label, href, external]) => {
          const child = document.createElement("a");
          child.href = href;
          child.textContent = label;
          if (isCurrentLink(href, path)) child.setAttribute("aria-current", "page");
          setExternal(child, external);
          panel.appendChild(child);
        });
        trigger.addEventListener("click", () => {
          const open = group.classList.toggle("is-open");
          trigger.setAttribute("aria-expanded", String(open));
        });
        group.append(trigger, panel);
      } else {
        const anchor = document.createElement("a");
        anchor.className = "thl-mobile-nav__link";
        anchor.href = item.href;
        anchor.textContent = item.label;
        if (item.match(path)) anchor.setAttribute("aria-current", "page");
        setExternal(anchor, item.external);
        group.appendChild(anchor);
      }
      nav.appendChild(group);
    });
  }

  function createChrome() {
    if (document.querySelector(".thl-site-chrome") || document.querySelector(".md-header")) return;
    addStylesheet();

    const path = window.location.pathname || "/";
    const isWide = path.startsWith("/threat-hunting-lab/") || path.includes("threat-hunting-device-logs-telemetry-details");
    document.body.classList.add("thl-shell-ready", isWide ? "thl-layout-wide" : "thl-layout-standard");

    const chrome = document.createElement("header");
    chrome.className = "thl-site-chrome md-header";
    chrome.dataset.menuOpen = "false";
    chrome.innerHTML = `
      <nav class="md-header__inner thl-md-grid" aria-label="Header">
        <a href="/" title="Threat Hunt Labs" class="md-header__button md-logo" aria-label="Threat Hunt Labs">${icons.book}</a>
        <button class="md-header__button md-icon thl-drawer-button" type="button" aria-label="Open navigation" aria-expanded="false" aria-controls="thl-mobile-drawer">${icons.menu}</button>
        <div class="md-header__title">
          <div class="md-header__ellipsis"><div class="md-header__topic"><span class="md-ellipsis">Threat Hunt Labs</span></div></div>
        </div>
        <button class="md-header__button md-icon thl-search-button" type="button" aria-label="Search">${icons.search}</button>
        <div class="md-search" role="search">
          <div class="md-search__inner">
            <form class="md-search__form" action="/" method="get">
              <span class="md-search__icon md-icon">${icons.search}</span>
              <input class="md-search__input" type="text" name="q" aria-label="Search" placeholder="Search" autocomplete="off" spellcheck="false">
            </form>
          </div>
        </div>
      </nav>
      <nav class="md-tabs" aria-label="Tabs">
        <div class="thl-md-grid"><ul class="md-tabs__list"></ul></div>
      </nav>
      <aside class="thl-mobile-drawer" id="thl-mobile-drawer" aria-label="Navigation"><nav class="thl-mobile-nav"></nav></aside>
      <button class="thl-mobile-overlay" type="button" aria-label="Close navigation"></button>`;

    const tabList = chrome.querySelector(".md-tabs__list");
    buildDesktopTabs(tabList, path);
    buildMobileNavigation(chrome.querySelector(".thl-mobile-nav"), path);

    const drawerButton = chrome.querySelector(".thl-drawer-button");
    const overlay = chrome.querySelector(".thl-mobile-overlay");
    const setDrawer = (open) => {
      chrome.dataset.menuOpen = String(open);
      drawerButton.setAttribute("aria-expanded", String(open));
      drawerButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    };
    drawerButton.addEventListener("click", () => setDrawer(chrome.dataset.menuOpen !== "true"));
    overlay.addEventListener("click", () => setDrawer(false));
    chrome.querySelector(".thl-search-button").addEventListener("click", () => {
      chrome.classList.toggle("thl-search-open");
      chrome.querySelector(".md-search__input")?.focus();
    });

    document.addEventListener("click", (event) => {
      if (!chrome.contains(event.target)) closeDropdowns(tabList);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      const openTab = tabList.querySelector(".md-tabs__item--dropdown-open");
      closeDropdowns(tabList);
      setDrawer(false);
      chrome.classList.remove("thl-search-open");
      openTab?.querySelector(":scope > .md-tabs__link")?.focus();
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
