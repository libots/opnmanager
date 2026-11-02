document.addEventListener('DOMContentLoaded', () => {
  const forms = Array.from(document.querySelectorAll('[data-pull-form]'));
  const enabled = forms.filter(form => !form.querySelector('button').disabled);
  const all = document.querySelector('[data-pull-all]');
  const summary = document.querySelector('[data-pull-summary]');
  let busy = false;
  if (all) all.disabled = !enabled.length;
  function lock(value) {
    busy = value;
    for (const form of enabled) form.querySelector('button').disabled = value;
    if (all) all.disabled = value || !enabled.length;
  }
  async function pull(form) {
    const status = form.querySelector('[data-pull-status]');
    status.textContent = ' Pulling…';
    status.className = '';
    try {
      const response = await fetch(form.action, {method: 'POST', body: new FormData(form), headers: {'Accept': 'application/json'}, credentials: 'same-origin'});
      if (!(response.headers.get('content-type') || '').includes('application/json')) throw new Error('Unable to pull. Check your session and refresh permission.');
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.error || 'Pull failed.');
      const row = form.closest('[data-firewall-row]');
      const observed = row?.querySelector('[data-pull-observed]');
      if (observed) observed.textContent = new Date(result.observed_at).toLocaleString();
      const policy = row?.querySelector('[data-pull-policy]');
      if (policy) {
        const badge = document.createElement('span');
        badge.className = 'pill ' + (result.attention ? 'warning' : 'good');
        badge.textContent = result.policy;
        policy.replaceChildren(badge);
      }
      status.textContent = ' Updated';
      return true;
    } catch (error) {
      status.textContent = ' ' + error.message;
      status.className = 'pull-failed';
      return false;
    }
  }
  for (const form of forms) form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !enabled.includes(form)) return;
    lock(true);
    try { await pull(form); } finally { lock(false); }
  });
  all?.addEventListener('click', async () => {
    if (busy) return;
    lock(true);
    let completed = 0, successes = 0, index = 0;
    async function worker() {
      while (index < enabled.length) {
        const form = enabled[index++];
        if (await pull(form)) successes++;
        completed++;
        summary.textContent = ` ${completed}/${enabled.length} finished · ${successes} updated · ${completed-successes} failed`;
      }
    }
    summary.textContent = ` Pulling ${enabled.length} enabled firewalls…`;
    try { await Promise.all([worker(), worker()]); } finally { lock(false); }
  });
});
