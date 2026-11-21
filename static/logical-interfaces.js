/* Fleet: Logical Interfaces — collect mapping edits, flag conflicts, fill matches by name. */
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('li-form');
  const table = document.getElementById('li-matrix');
  if (!form || !table) return;
  const controls = Array.from(form.querySelectorAll('[name^="map_"]'));
  const bar = document.getElementById('li-savebar');
  const countText = document.getElementById('li-change-count');
  const conflictText = document.getElementById('li-conflicts');
  const save = document.getElementById('li-save');
  const cellOf = control => control.closest('.li-cell');
  const fwOf = control => cellOf(control).dataset.fw;
  const changed = control => control.value !== control.dataset.initial;

  function detail(control) {
    const target = cellOf(control).querySelector('.li-detail');
    const option = control.tagName === 'SELECT' ? control.selectedOptions[0] : null;
    const line = (text, className) => Object.assign(document.createElement('div'), {textContent: text, className: className || ''});
    target.replaceChildren();
    if (!option || !option.value) return;
    if (option.dataset.detail) target.append(line(option.dataset.detail));
    for (const address of (option.dataset.addresses || '').split('|').filter(Boolean)) target.append(line(address, 'li-address'));
  }

  function refresh() {
    // One device interface can back only one logical interface per firewall.
    const used = new Map();
    for (const control of controls) {
      if (!control.value) continue;
      const key = fwOf(control) + '\u0000' + control.value;
      used.set(key, (used.get(key) || 0) + 1);
    }
    let conflicts = 0;
    const mapped = new Map();
    for (const control of controls) {
      const cell = cellOf(control);
      const clash = control.value && used.get(fwOf(control) + '\u0000' + control.value) > 1;
      if (clash) conflicts++;
      cell.classList.toggle('is-changed', changed(control));
      cell.classList.toggle('is-conflict', Boolean(clash));
      cell.classList.toggle('is-unmapped', !control.value);
      if (control.value) mapped.set(fwOf(control), (mapped.get(fwOf(control)) || 0) + 1);
      // Show which logical interface already holds each option.
      if (control.tagName === 'SELECT') {
        for (const option of control.options) {
          if (!option.value) continue;
          const holder = controls.find(other => other !== control && fwOf(other) === fwOf(control) && other.value === option.value);
          const base = option.dataset.text || (option.dataset.text = option.textContent);
          option.textContent = holder ? `${base} (used by ${holder.closest('tr').querySelector('.li-name a').textContent})` : base;
        }
      }
    }
    for (const th of table.tHead.rows[0].cells) {
      const count = th.querySelector('[data-mapped-count]');
      if (count) count.textContent = mapped.get(th.dataset.fw) || 0;
    }
    const edits = controls.filter(changed).length;
    if (bar) {
      bar.hidden = edits === 0;
      countText.textContent = `${edits} unsaved change${edits === 1 ? '' : 's'}`;
      conflictText.textContent = conflicts ? 'The highlighted cells pick the same interface twice on one firewall' : '';
      save.disabled = conflicts > 0;
    }
  }

  for (const control of controls) {
    control.addEventListener('change', () => { detail(control); refresh(); });
    control.addEventListener('input', refresh);
  }

  function fill(fw) {
    // Match on the identifier (lan, wan) or the description OPNsense shows (IoT, Guest).
    let filled = 0;
    for (const control of controls) {
      if (control.tagName !== 'SELECT' || control.value || (fw && fwOf(control) !== fw)) continue;
      const name = cellOf(control).dataset.logical;
      const taken = new Set(controls.filter(other => fwOf(other) === fwOf(control) && other.value).map(other => other.value));
      const match = Array.from(control.options).find(option => option.value && !taken.has(option.value)
        && (option.dataset.label === name || option.value.toLowerCase() === name));
      if (match) { control.value = match.value; detail(control); filled++; }
    }
    refresh();
    return filled;
  }
  for (const button of table.querySelectorAll('.li-fill')) {
    button.addEventListener('click', () => { const n = fill(button.dataset.fw); button.textContent = n ? `Filled ${n}` : 'No new matches'; });
  }
  const fillAll = document.getElementById('li-fill-all');
  fillAll?.addEventListener('click', () => { const n = fill(null); fillAll.querySelector('span').textContent = n ? `Filled ${n} — review and save` : 'No new matches'; });

  document.getElementById('li-discard')?.addEventListener('click', () => {
    for (const control of controls) { control.value = control.dataset.initial; detail(control); }
    refresh();
  });
  form.addEventListener('submit', event => {
    const removed = controls.filter(control => changed(control) && !control.value && control.dataset.initial);
    if (removed.length && !confirm(`Remove ${removed.length} mapping${removed.length === 1 ? '' : 's'}? Rules using ${removed.length === 1 ? 'that interface' : 'those interfaces'} will leave it out on that firewall.`)) {
      event.preventDefault();
      return;
    }
    // Send only edited cells.
    for (const control of controls) if (!changed(control)) control.disabled = true;
    form.dataset.submitting = '1';
  });
  window.addEventListener('beforeunload', event => {
    if (bar && !bar.hidden && !form.dataset.submitting) { event.preventDefault(); event.returnValue = ''; }
  });

  const search = document.getElementById('li-search');
  search?.addEventListener('input', () => {
    const query = search.value.trim().toLowerCase();
    for (const row of table.tBodies[0]?.rows || []) row.hidden = Boolean(query) && !row.dataset.search.includes(query);
  });
  refresh();
});
