/* Fleet: Review & Deploy — live counts per firewall and for the whole form. */
(function () {
  const form = document.querySelector('[data-deploy-form]');
  if (!form) return;
  const summary = document.getElementById('deploy-summary');
  const submit = document.getElementById('deploy-submit');
  const plural = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');

  function count(section) {
    const p = section.dataset.prefix || '';
    const q = (sel) => Array.from(section.querySelectorAll(sel));
    const sync = Number(section.dataset.sync || 0);
    const rules = q('input[name="' + p + 'selected_rules"]:checked').length;
    const retire = q('select[name="' + p + 'selected_rules"]').filter((s) => s.value).length;
    const removals = q('input[name="' + p + 'remove_definition"]:checked').length;
    const parts = [];
    if (sync) parts.push(plural(sync, 'definition change'));
    if (removals) parts.push(plural(removals, 'definition removal'));
    if (rules) parts.push(plural(rules, 'rule'));
    if (retire) parts.push(plural(retire, 'retired rule'));
    return parts;
  }

  function update() {
    let firewalls = 0, single = null;
    form.querySelectorAll('[data-deploy-firewall]').forEach((section) => {
      const include = section.querySelector('[data-deploy-include]');
      const parts = count(section);
      const line = section.querySelector('[data-deploy-summary]');
      const included = include ? include.checked : true;
      section.classList.toggle('deploy-excluded', !included);
      if (line) line.textContent = parts.length ? (included ? 'Deploys ' : 'Not included: ') + parts.join(', ') + '.' : 'Nothing selected.';
      if (included && parts.length) { firewalls += 1; single = parts; }
    });
    const multi = !!form.querySelector('[data-deploy-include]');
    if (!firewalls) summary.textContent = 'Nothing selected to deploy.';
    else if (multi) summary.textContent = 'This queues ' + plural(firewalls, 'deployment') + ', one per checked firewall.';
    else summary.textContent = 'This deployment applies ' + single.join(', ') + '.';
    submit.disabled = !firewalls;
  }
  form.addEventListener('change', update);
  update();
})();
