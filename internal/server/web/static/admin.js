/* SPDX-License-Identifier: AGPL-3.0-only */
(() => {
  for (const form of document.querySelectorAll("form[data-confirm]")) {
    form.addEventListener("submit", (e) => {
      if (!confirm(form.dataset.confirm)) e.preventDefault();
    });
  }
  for (const input of document.querySelectorAll("input[data-select]")) {
    input.addEventListener("focus", () => input.select());
  }
  const filter = document.getElementById("admin-filter");
  const table = document.getElementById("admin-apps");
  if (filter && table) {
    const rows = [...table.querySelectorAll("tbody tr[data-search]")];
    const groups = [...table.querySelectorAll("tbody tr.group-row")];
    filter.addEventListener("input", () => {
      const q = filter.value.trim().toLowerCase();
      for (const row of rows) row.hidden = q && !row.dataset.search.toLowerCase().includes(q);
      for (const g of groups) {
        g.hidden = !rows.some((r) => !r.hidden && r.dataset.group === g.dataset.group);
      }
    });
  }
})();
