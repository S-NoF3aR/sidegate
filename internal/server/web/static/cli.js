/* SPDX-License-Identifier: AGPL-3.0-only */
(() => {
  // Preselect the visitor's operating system.
  const ua = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || navigator.userAgent;
  const guess = /win/i.test(ua) ? "windows" : /mac|iphone|ipad/i.test(ua) ? "darwin" : "linux";
  const tabs = [...document.querySelectorAll(".os-tabs [data-os]")];
  const panels = [...document.querySelectorAll("[data-os-panel]")];
  const show = (os) => {
    for (const t of tabs) t.setAttribute("aria-selected", String(t.dataset.os === os));
    for (const p of panels) p.hidden = p.dataset.osPanel !== os;
  };
  for (const t of tabs) t.addEventListener("click", () => show(t.dataset.os));
  if (tabs.length) show(guess);

  for (const btn of document.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", () => {
      const text = btn.parentElement.querySelector("code").textContent;
      navigator.clipboard?.writeText(text).then(() => {
        btn.textContent = "Copied";
        setTimeout(() => (btn.textContent = "Copy"), 1500);
      });
    });
  }
})();
