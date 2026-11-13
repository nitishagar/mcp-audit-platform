/* Install tabs, copy buttons, theme switcher. No dependencies. */
(() => {
  // Install tabs
  const tabs = document.querySelectorAll('[role="tab"]');
  const panes = document.querySelectorAll("[data-pane]");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        t.classList.remove("active");
      });
      tab.classList.add("active");
      const want = tab.getAttribute("data-tab");
      panes.forEach((pane) => {
        pane.classList.toggle("hidden", pane.getAttribute("data-pane") !== want);
      });
    });
  });

  // Copy buttons (clipboard API with execCommand fallback)
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const text = btn.getAttribute("data-copy") ?? "";
      const done = () => {
        const prev = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = prev;
        }, 1200);
      };
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(text).then(done, () => {});
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
          done();
        } catch {
          /* clipboard unavailable; leave the button as-is */
        }
        document.body.removeChild(ta);
      }
    });
  });

  // Theme: auto (prefers-color-scheme) / light / dark, persisted.
  const root = document.documentElement;
  const apply = (mode) => {
    const resolved =
      mode === "auto"
        ? window.matchMedia("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark"
        : mode;
    root.setAttribute("data-theme", resolved);
    root.setAttribute("data-theme-mode", mode);
  };
  let saved = null;
  try {
    saved = window.localStorage.getItem("mcp-audit-theme");
  } catch {
    saved = null;
  }
  apply(saved ?? "auto");
  document.querySelectorAll("[data-theme-set]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-theme-set") ?? "auto";
      try {
        window.localStorage.setItem("mcp-audit-theme", mode);
      } catch {
        /* storage unavailable; still apply for this visit */
      }
      apply(mode);
    });
  });
})();
