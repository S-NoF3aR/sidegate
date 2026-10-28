/* SPDX-License-Identifier: AGPL-3.0-only */
(() => {
  const input = document.getElementById("filter");
  const root = document.getElementById("apps");
  if (!input || !root) return;
  const apps = [...root.querySelectorAll("li.app")];
  const sections = [...root.querySelectorAll("details.cat-section")];
  const links = [...document.querySelectorAll(".cat-link")];
  const empty = document.getElementById("no-match");

  // Collapsed sections are remembered per browser.
  const storeKey = "sidegate.collapsed";
  let collapsed = new Set();
  try { collapsed = new Set(JSON.parse(localStorage.getItem(storeKey) || "[]")); } catch {}
  const save = () => { try { localStorage.setItem(storeKey, JSON.stringify([...collapsed])); } catch {} };

  let active = ""; // selected category path, "" = all

  const inScope = (cat) => !active || cat === active || cat.startsWith(active + "/");

  function apply() {
    const q = input.value.trim().toLowerCase();
    let shown = 0;
    for (const li of apps) {
      const visible = inScope(li.dataset.cat || "") && (!q || li.dataset.search.toLowerCase().includes(q));
      li.hidden = !visible;
      if (visible) shown++;
    }
    // Innermost sections first, so parents see their children's state.
    for (const sec of [...sections].reverse()) {
      const hasApps = !!sec.querySelector("li.app:not([hidden])");
      sec.hidden = !hasApps;
      const cat = sec.dataset.cat;
      // While searching or browsing a category, open everything relevant;
      // otherwise restore what the user collapsed.
      const forceOpen = q || (active && (active === cat || active.startsWith(cat + "/") || cat.startsWith(active + "/")));
      sec.open = forceOpen ? true : !collapsed.has(cat);
    }
    for (const a of links) {
      a.toggleAttribute("aria-current", a.dataset.cat === active);
    }
    if (empty) empty.hidden = shown > 0;
  }

  function select(cat) {
    active = cat;
    apply();
  }

  // Category selection lives in the URL hash ("#/Monitoring/Logs"), so it
  // can be bookmarked and survives reloads.
  function fromHash() {
    const h = decodeURIComponent(location.hash.slice(1));
    select(h.startsWith("/") ? h.slice(1) : "");
  }
  for (const a of links) {
    a.href = a.dataset.cat ? "#/" + a.dataset.cat.split("/").map(encodeURIComponent).join("/") : "#";
    a.addEventListener("click", (e) => {
      e.preventDefault();
      history.replaceState(null, "", a.dataset.cat ? a.getAttribute("href") : location.pathname + location.search);
      select(a.dataset.cat);
      root.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  }
  for (const sec of sections) {
    sec.addEventListener("toggle", () => {
      // Only record toggles the user made, not ones apply() forced.
      if (input.value.trim() || active) return;
      if (sec.open) collapsed.delete(sec.dataset.cat); else collapsed.add(sec.dataset.cat);
      save();
    });
  }
  window.addEventListener("hashchange", fromHash);
  input.addEventListener("input", apply);

  // "/" focuses the filter, Escape clears it.
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== input) {
      e.preventDefault();
      input.focus();
    } else if (e.key === "Escape" && document.activeElement === input) {
      input.value = "";
      apply();
    }
  });

  fromHash();
})();
