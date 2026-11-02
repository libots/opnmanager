document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('rule_form');
  if (!form) return;
  form.classList.add('rule-editor-enhanced');
  document.getElementById('rule-editor-tools').hidden = false;
  const $ = window.django?.jQuery;
  const sections = Array.from(form.querySelectorAll('.rule-editor-section'));
  const search = document.getElementById('rule-form-search');
  const expanded = new Map();
  let searching = false;

  function filterFields() {
    const query = search.value.trim().toLocaleLowerCase();
    if (query && !searching) {
      for (const section of sections) expanded.set(section, section.querySelector('details').open);
    }
    let count = 0;
    for (const section of sections) {
      let visible = false;
      for (const row of section.querySelectorAll('.rule-editor-row')) {
        const input = row.querySelector('input, select, textarea');
        const current = input?.tagName === 'SELECT' ? Array.from(input.selectedOptions, option => option.textContent).join(' ') : input?.value || '';
        const text = [section.querySelector('summary').textContent, row.querySelector('.rule-field-label')?.textContent, row.querySelector('.help')?.textContent, current].join(' ').toLocaleLowerCase();
        // Validation errors must stay visible even when a search is active.
        const matches = !query || text.includes(query) || row.classList.contains('errors');
        row.classList.toggle('rule-search-hidden', !matches);
        // Protocol visibility is controlled separately by selections.js.
        row.style.display = matches ? '' : 'none';
        if (matches && !row.hidden) { visible = true; count++; }
      }
      section.hidden = !visible;
      if (query && visible) section.querySelector('details').open = true;
      if (!query && searching) section.querySelector('details').open = expanded.get(section) ?? true;
    }
    searching = Boolean(query);
    document.getElementById('rule-search-status').textContent = query ? `${count} matching settings` : '';
    document.getElementById('rule-editor-empty').hidden = count > 0;
  }
  search.addEventListener('input', filterFields);
  search.addEventListener('keydown', event => {
    if (event.key === 'Enter') event.preventDefault();
    if (event.key === 'Escape') { search.value = ''; filterFields(); }
  });
  for (const id of ['rule-search-clear', 'rule-empty-clear']) {
    document.getElementById(id).addEventListener('click', () => { search.value = ''; filterFields(); search.focus(); });
  }
  document.getElementById('rule-full-help').addEventListener('change', event => {
    form.classList.toggle('rule-full-help-visible', event.target.checked);
    for (const button of form.querySelectorAll('.rule-help-toggle')) {
      button.setAttribute('aria-expanded', String(event.target.checked || button.closest('.form-row').classList.contains('rule-help-open')));
    }
  });
  for (const button of form.querySelectorAll('.rule-help-toggle')) {
    button.hidden = false;
    button.addEventListener('click', () => {
      const row = button.closest('.form-row');
      row.classList.toggle('rule-help-open');
      button.setAttribute('aria-expanded', String(row.classList.contains('rule-help-open') || document.getElementById('rule-full-help').checked));
    });
  }
  const bindings = ['id_interfaces', 'id_interface_groups'].map(id => document.getElementById(id)).filter(Boolean);
  function updatePlacement() {
    if (!bindings.length) { filterFields(); return; }
    const count = bindings.reduce((total, select) => total + select.selectedOptions.length, 0);
    const groupCount = document.getElementById('id_interface_groups')?.selectedOptions.length || 0;
    document.getElementById('rule-placement').textContent = count === 0 ? 'Floating — all interfaces' : count === 1 ? (groupCount ? 'Interface group rule' : 'Interface rule') : `Floating — ${count} interface/group bindings`;
    filterFields();
  }
  for (const select of bindings) {
    if ($) $(select).on('change', updatePlacement); else select.addEventListener('change', updatePlacement);
  }
  // Model-backed selections get OPNsense-style all/none actions. Free text and
  // protocol/port fields keep their existing per-item and text-list controls.
  for (const name of ['categories', 'interfaces', 'interface_groups', 'origin_interfaces', 'origin_interface_groups', 'icmp_types', 'icmp6_types', 'firewalls', 'firewall_groups']) {
    const select = document.getElementById('id_' + name);
    const editor = select?.parentElement.querySelector('.opn-bulk-editor');
    if (!select || !editor || !$) continue;
    const actions = [];
    for (const [label, all] of [['Clear all', false], ['Select all', true]]) {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = label;
      button.setAttribute('aria-label', `${label}: ${select.labels[0]?.textContent.trim().replace(/:$/, '') || name}`);
      button.addEventListener('click', () => {
        $(select).val(all ? Array.from(select.options).filter(option => !option.disabled && option.value).map(option => option.value) : []).trigger('change');
      });
      actions.push(button);
    }
    editor.prepend(...actions);
    // Keep Django's related-object popup links, alongside the selection actions.
    for (const link of select.parentElement.querySelectorAll(':scope > a.related-widget-wrapper-link')) {
      link.textContent = link.classList.contains('add-related') ? 'Add new' : link.title;
      editor.append(link);
    }
  }
  const protocol = document.getElementById('id_protocol');
  if ($ && protocol) $(protocol).on('change', filterFields);
  // Search and collapse never disable or clear fields; every value is saved.
  form.addEventListener('submit', () => {
    search.value = ''; filterFields();
    for (const row of form.querySelectorAll('.form-row.errors')) row.closest('details').open = true;
  });
  updatePlacement();
});
