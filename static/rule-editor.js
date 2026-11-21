/* Rule editor behavior mirroring OPNsense's Firewall: Rules dialog. */
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('rule_form');
  if (!form) return;
  form.classList.add('rule-editor-enhanced');
  const sections = Array.from(form.querySelectorAll('.rule-editor-section'));
  const search = document.getElementById('rule-form-search');
  const advanced = document.getElementById('rule-advanced');
  const fullHelp = document.getElementById('rule-full-help');
  const field = name => document.getElementById('id_' + name);
  const row = name => field(name)?.closest('.form-row');
  const store = {
    get(key) { try { return localStorage.getItem(key); } catch (error) { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch (error) { /* private mode */ } },
  };

  // --- advanced mode / full help switches (remembered, as in OPNsense) ---
  function setSwitch(button, on) { button.setAttribute('aria-checked', String(on)); }
  function applyModes() {
    form.classList.toggle('rule-advanced-mode', advanced.getAttribute('aria-checked') === 'true');
    form.classList.toggle('rule-full-help-visible', fullHelp.getAttribute('aria-checked') === 'true');
    filterFields();
  }
  // Advanced fields that hold a value are never hidden: the form opens in advanced mode then.
  setSwitch(advanced, advanced.dataset.force === 'true' || store.get('opn.rule.advanced') === 'true');
  setSwitch(fullHelp, store.get('opn.rule.fullhelp') === 'true');
  for (const [button, key] of [[advanced, 'opn.rule.advanced'], [fullHelp, 'opn.rule.fullhelp']]) {
    button.addEventListener('click', () => {
      const on = button.getAttribute('aria-checked') !== 'true';
      setSwitch(button, on);
      store.set(key, String(on));
      applyModes();
    });
  }
  for (const button of form.querySelectorAll('button.rule-help-toggle')) {
    if (button.classList.contains('no-help')) { button.tabIndex = -1; continue; }
    button.addEventListener('click', () => {
      const target = button.closest('.form-row');
      target.classList.toggle('rule-help-open');
      button.setAttribute('aria-expanded', String(target.classList.contains('rule-help-open')));
    });
  }

  // --- protocol-dependent fields: ICMP types only for ICMP, as OPNsense does ---
  function protocolRows() {
    const protocol = field('protocol');
    const values = protocol ? Array.from(protocol.selectedOptions, option => option.value.toLowerCase()) : [];
    for (const [name, needle] of [['icmp_types', 'icmp'], ['icmp6_types', 'ipv6-icmp']]) {
      const target = row(name);
      if (target) target.classList.toggle('rule-protocol-hidden', !values.includes(needle));
    }
  }

  // --- search form ---
  function filterFields() {
    protocolRows();
    const query = search.value.trim().toLocaleLowerCase();
    const showAdvanced = form.classList.contains('rule-advanced-mode');
    let count = 0;
    for (const section of sections) {
      let visible = false;
      for (const target of section.querySelectorAll('.rule-editor-row')) {
        const input = target.querySelector('select, input, textarea');
        const current = input?.tagName === 'SELECT' ? Array.from(input.selectedOptions, option => option.textContent).join(' ') : input?.value || '';
        const text = [section.querySelector('summary').textContent, target.querySelector('.rule-field-label')?.textContent, target.querySelector('.help')?.textContent, current].join(' ').toLocaleLowerCase();
        const errors = target.classList.contains('errors');
        const hidden = (!errors && target.classList.contains('advanced') && !showAdvanced)
          || target.classList.contains('rule-protocol-hidden')
          || (query && !errors && !text.includes(query));
        target.hidden = Boolean(hidden);
        if (!hidden) { visible = true; count++; }
      }
      section.hidden = !visible;
      if (query && visible) section.querySelector('details').open = true;
    }
    document.getElementById('rule-search-status').textContent = query ? `${count} matching settings` : '';
    document.getElementById('rule-editor-empty').hidden = count > 0;
  }
  search.addEventListener('input', filterFields);
  search.addEventListener('keydown', event => {
    if (event.key === 'Enter') event.preventDefault();
    if (event.key === 'Escape') { search.value = ''; filterFields(); }
  });
  document.getElementById('rule-empty-clear').addEventListener('click', () => { search.value = ''; filterFields(); search.focus(); });

  // --- placement follows the number of rule interfaces ---
  function updatePlacement() {
    const bindings = field('bindings');
    const output = document.getElementById('rule-placement');
    if (!bindings || !output) return;
    const chosen = Array.from(bindings.selectedOptions, option => option.value);
    const groups = chosen.filter(value => value.startsWith('group:')).length;
    output.textContent = chosen.length === 0 ? 'Floating — all interfaces'
      : chosen.length === 1 ? (groups ? 'Interface group rule' : 'Interface rule')
      : `Floating — ${chosen.length} interfaces/groups`;
  }

  // --- action side effects, copied from OPNsense's filter_rule view ---
  function setValue(name, value) {
    const select = field(name);
    if (!select || select.value === value) return;
    select.value = value;
    select.dispatchEvent(new Event('change', {bubbles: true}));
  }
  field('action')?.addEventListener('change', event => {
    if (!event.isTrusted && !event.target.dataset.opnSyncing) return;
    const action = event.target.value;
    // Match rules are usually not quick, since a match would stop further ruleset evaluation.
    if (action === 'match' && field('quick')) field('quick').checked = false;
    if (action !== 'pass') { setValue('state_type', 'none'); setValue('gateway', ''); }
  });

  form.addEventListener('change', event => {
    if (event.target.id === 'id_bindings') updatePlacement();
    if (event.target.id === 'id_protocol') filterFields();
  });
  // Search and hidden sections never clear fields; every value is saved.
  form.addEventListener('submit', () => {
    search.value = '';
    for (const target of form.querySelectorAll('.form-row.errors')) target.closest('details').open = true;
  });
  // --- editing several rules: track which fields change; differing fields start locked ---
  const bulk = document.getElementById('rule-bulk');
  if (bulk) {
    const changed = new Set(bulk.dataset.changed.split(',').filter(Boolean));
    const holder = document.getElementById('rule-bulk-changed');
    const sync = () => {
      holder.replaceChildren(...Array.from(changed, name => Object.assign(document.createElement('input'), {type: 'hidden', name: '_changed', value: name})));
      for (const target of form.querySelectorAll('.rule-editor-row[data-field]')) target.classList.toggle('bulk-changed', changed.has(target.dataset.field));
    };
    const unlock = target => {
      target.classList.remove('bulk-mixed');
      target.querySelector('.rule-bulk-control')?.removeAttribute('inert');
      target.querySelector('.rule-bulk-unlock')?.remove();
    };
    for (const target of form.querySelectorAll('.rule-editor-row.bulk-mixed')) {
      if (changed.has(target.dataset.field)) { unlock(target); continue; }
      target.querySelector('.rule-bulk-control')?.setAttribute('inert', '');
      target.querySelector('.rule-bulk-unlock').addEventListener('click', () => {
        unlock(target);
        changed.add(target.dataset.field);
        sync();
        target.querySelector('.rule-bulk-control input:not([type=hidden]), .rule-bulk-control select, .rule-bulk-control textarea, .rule-bulk-control button')?.focus();
      });
    }
    // Pickers set up their own values on load; only count edits made afterwards.
    setTimeout(() => {
      const mark = event => {
        const target = event.target.closest?.('.rule-editor-row[data-field]');
        if (!target || event.target.id === 'rule-form-search') return;
        unlock(target);
        changed.add(target.dataset.field);
        sync();
      };
      form.addEventListener('change', mark);
      form.addEventListener('input', mark);
    }, 0);
    sync();
  }

  updatePlacement();
  applyModes();
});
