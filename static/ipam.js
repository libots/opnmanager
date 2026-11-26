/* Addressing: Address Plan — show or hide interfaces without a plan (remembered per browser). */
(function () {
  const page = document.getElementById('ipam-plan');
  const toggle = document.getElementById('ipam-show-unplanned');
  if (!page || !toggle) return;
  const key = 'opn.ipam.showUnplanned';
  try { toggle.checked = localStorage.getItem(key) === 'true'; } catch (error) { /* private mode */ }
  function apply() { page.classList.toggle('show-unplanned', toggle.checked); }
  toggle.addEventListener('change', () => {
    try { localStorage.setItem(key, String(toggle.checked)); } catch (error) { /* private mode */ }
    apply();
  });
  apply();
})();
