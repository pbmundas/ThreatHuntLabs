(() => {
  const shellStylesheet = "/assets/stylesheets/site-shell.css";
  const links = [
    { label: "Home", href: "/", match: (path) => path === "/" || path === "/index.html" },
    {
      label: "Foundations",
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
        ["Telemetry & Logs", "/Start-Hunting/threat-hunting-device-logs-telemetry-details.html"],
        ["Low Hanging Fruits", "/Start-Hunting/low-hanging-fruits-threat-hunting/"]
      ]
    },
    { label: "Hypothesis", href: "/hypothesis/", match: (path) => path.startsWith("/hypothesis/") },
    {
      label: "Learn Attacks",
      match: (path) => path.startsWith("/learn-known-cyber-attacks/") || path.startsWith("/attack-encyclopedia/"),
      children: [
        ["Attacks in History", "/learn-known-cyber-attacks/"],
        ["Attack Encyclopedia", "/attack-encyclopedia/"]
      ]
    },
    {
      label: "Case Studies",
      match: (path) => path.startsWith("/case-studies/"),
      children: [
        ["Stuxnet", "/case-studies/2010-Stuxnet-Retrospective-Threat-Hunt-Report/"],
        ["RSA SecurID", "/case-studies/2011-RSA-SecurID-Retrospective-Threat-Hunt-Report/"],
        ["LinkedIn", "/case-studies/2012-linkedin-threat-hunt-report/"],
        ["Adobe", "/case-studies/2013-adobe-threat-hunt-report/"],
        ["Hugging Face & OpenAI", "/case-studies/2026-openai-huggingface-incident-explainer/"]
      ]
    },
    {
      label: "Products",
      match: (path) => path.startsWith("/products/"),
      children: [
        ["THOS", "/products/AI-Agentic-THOS-Threat-Hunting-Operating-System.html"],
        ["THOS Walkthrough", "/products/THOS-Walkthrough-Blog/"]
      ]
    },
    {
      label: "Resources",
      match: (path) => path.startsWith("/threat-hunting-reports/") || path.startsWith("/threat-hunting-lab/") || path.startsWith("/Downloads/"),
      children: [
        ["Daily Intel", "https://intel.threathuntlabs.com", true],
        ["Hunting Reports", "/threat-hunting-reports/"],
        ["Challenges", "/threat-hunting-lab/"],
        ["Downloads", "/Downloads/threat-hunting-related-document-references/"]
      ]
    },
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

  function normalizePath(value) {
    const path = value.replace(/index\.html$/, "").replace(/\/$/, "");
    return path || "/";
  }

  function isCurrentLink(href, path) {
    if (!href.startsWith("/")) return false;
    return normalizePath(href) === normalizePath(path);
  }

  function closeDropdowns(nav, except = null) {
    nav.querySelectorAll(".thl-global-nav__item.is-open").forEach((item) => {
      if (item === except) return;
      item.classList.remove("is-open");
      item.querySelector(":scope > .thl-global-nav__trigger")?.setAttribute("aria-expanded", "false");
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
    links.forEach((item, index) => {
      const navItem = document.createElement("div");
      navItem.className = "thl-global-nav__item";

      if (item.children) {
        const trigger = document.createElement("button");
        const dropdownId = `thl-global-dropdown-${index}`;
        trigger.className = "thl-global-nav__trigger";
        trigger.type = "button";
        trigger.textContent = item.label;
        trigger.setAttribute("aria-expanded", "false");
        trigger.setAttribute("aria-haspopup", "true");
        trigger.setAttribute("aria-controls", dropdownId);
        if (item.match(path)) trigger.setAttribute("aria-current", "page");

        const dropdown = document.createElement("div");
        dropdown.className = "thl-global-dropdown";
        dropdown.id = dropdownId;
        item.children.forEach(([label, href, external]) => {
          const anchor = document.createElement("a");
          anchor.className = "thl-global-dropdown__link";
          anchor.href = href;
          anchor.textContent = label;
          if (isCurrentLink(href, path)) anchor.setAttribute("aria-current", "page");
          if (external) {
            anchor.target = "_blank";
            anchor.rel = "noopener noreferrer";
          }
          dropdown.appendChild(anchor);
        });

        trigger.addEventListener("click", () => {
          const open = !navItem.classList.contains("is-open");
          closeDropdowns(nav, navItem);
          navItem.classList.toggle("is-open", open);
          trigger.setAttribute("aria-expanded", String(open));
        });
        navItem.append(trigger, dropdown);
      } else {
        const anchor = document.createElement("a");
        anchor.className = "thl-global-nav__link";
        anchor.href = item.href;
        anchor.textContent = item.label;
        if (item.match(path)) anchor.setAttribute("aria-current", "page");
        if (item.external) {
          anchor.target = "_blank";
          anchor.rel = "noopener noreferrer";
        }
        navItem.appendChild(anchor);
      }
      nav.appendChild(navItem);
    });

    const menuToggle = chrome.querySelector(".thl-global-menu-button");
    menuToggle.addEventListener("click", () => {
      const open = chrome.dataset.menuOpen !== "true";
      chrome.dataset.menuOpen = String(open);
      menuToggle.setAttribute("aria-expanded", String(open));
      if (!open) closeDropdowns(nav);
    });

    document.addEventListener("click", (event) => {
      if (!chrome.contains(event.target)) closeDropdowns(nav);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      const openTrigger = nav.querySelector(".thl-global-nav__item.is-open > .thl-global-nav__trigger");
      closeDropdowns(nav);
      if (chrome.dataset.menuOpen === "true") {
        chrome.dataset.menuOpen = "false";
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.focus();
      } else {
        openTrigger?.focus();
      }
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
