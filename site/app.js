(() => {
  const cfg = window.SITE_CONFIG || {};
  const repo = (cfg.repo || "").replace(/\/$/, "");
  const links = {
    repo,
    releases: repo + "/releases",
    issues: repo + "/issues",
    download: cfg.download || repo + "/releases/latest",
    dashboard: cfg.dashboard || "http://127.0.0.1:5050/",
  };

  document.querySelectorAll("[data-link]").forEach((a) => {
    const href = links[a.dataset.link];
    if (!href) return;
    a.href = href;
    if (/^https?:/.test(href) && a.dataset.link !== "dashboard") {
      a.target = "_blank";
      a.rel = "noopener";
    }
  });
  document.querySelectorAll('[data-text="exe-name"]').forEach((el) => {
    if (cfg.exeName) el.textContent = cfg.exeName;
  });
  document.querySelectorAll('[data-text="repo-url"]').forEach((el) => {
    if (repo) el.textContent = repo + ".git";
  });

  // mobile nav
  const toggle = document.querySelector(".nav-toggle");
  const menu = document.getElementById("nav-links");
  toggle?.addEventListener("click", () => {
    const open = menu.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });
  menu?.addEventListener("click", (e) => {
    if (e.target.closest("a")) { menu.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); }
  });

  // active nav state follows the section in view
  const navLinks = [...document.querySelectorAll('.nav-links a[href^="#"]')];
  const sections = navLinks.map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
  if ("IntersectionObserver" in window) {
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return;
        navLinks.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + en.target.id));
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    sections.forEach((s) => obs.observe(s));
  }

  // copy buttons
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const src = document.querySelector(btn.dataset.copy);
      try {
        await navigator.clipboard.writeText(src.innerText.trim());
        btn.textContent = "Copied";
      } catch {
        btn.textContent = "Select & copy";
      }
      setTimeout(() => (btn.textContent = "Copy"), 1600);
    });
  });
})();
