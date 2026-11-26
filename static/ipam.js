/* Addressing pages — "Show interfaces without a plan / scope" toggles (remembered per browser).
   <input data-toggle-target="<element id>" data-toggle-class="<class>" data-toggle-key="<storage key>"> */
(function () {
  document.querySelectorAll('input[data-toggle-target]').forEach(toggle => {
    const page = document.getElementById(toggle.dataset.toggleTarget);
    if (!page) return;
    const key = toggle.dataset.toggleKey;
    try { toggle.checked = localStorage.getItem(key) === 'true'; } catch (error) { /* private mode */ }
    const apply = () => page.classList.toggle(toggle.dataset.toggleClass, toggle.checked);
    toggle.addEventListener('change', () => {
      try { localStorage.setItem(key, String(toggle.checked)); } catch (error) { /* private mode */ }
      apply();
    });
    apply();
  });
})();
