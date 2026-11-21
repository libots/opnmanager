/*
 * OPNsense-style select pickers for <select class="opn-select">.
 *
 * Mirrors bootstrap-select as OPNsense uses it: a button showing the chosen
 * labels, a dropdown with live search and optgroups, and "Clear All" /
 * "Select All" under multi-selects. data-selector picks the variant:
 *   picker  plain single/multi select
 *   net     networks; "Single host or Network" reveals a text box (OPNsense net_selector)
 *   port    ports; "Single port or range" reveals a text box (OPNsense port_selector)
 *   manual  a list plus one typed value (gateway names)
 *   tags    left to selections.js (free-form chips, like OPNsense's tokenizer)
 * The native <select> stays in the form and is what gets submitted.
 */
(function () {
  'use strict';
  const MANUAL = '__manual__';
  const MANUAL_LABEL = {net: 'Single host or Network', port: 'Single port or range', manual: 'Other (type a name)'};
  let openPicker = null;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function fire(select) {
    select.dataset.opnSyncing = 'true';
    select.dispatchEvent(new Event('change', {bubbles: true}));
    delete select.dataset.opnSyncing;
  }

  function enhance(select) {
    if (select.dataset.opnPicker) return;
    const kind = select.dataset.selector || 'picker';
    if (kind === 'tags') return;
    select.dataset.opnPicker = 'true';
    const multiple = select.multiple;
    const manualKind = kind in MANUAL_LABEL;
    const root = el('div', 'opn-picker' + (multiple ? ' is-multi' : '') + ' opn-picker-' + kind);
    const toggle = el('button', 'opn-picker-toggle');
    toggle.type = 'button';
    toggle.setAttribute('aria-haspopup', 'listbox');
    toggle.setAttribute('aria-expanded', 'false');
    const text = el('span', 'opn-picker-text');
    toggle.append(text, el('span', 'opn-caret'));
    const menu = el('div', 'opn-picker-menu');
    menu.hidden = true;
    const search = el('input', 'opn-picker-search');
    search.type = 'search';
    search.placeholder = 'Search…';
    search.setAttribute('aria-label', 'Search options');
    const list = el('ul', 'opn-picker-list');
    list.setAttribute('role', 'listbox');
    if (multiple) list.setAttribute('aria-multiselectable', 'true');
    const listId = (select.id || 'opn') + '_listbox';
    list.id = listId;
    toggle.setAttribute('aria-controls', listId);
    menu.append(search, list);
    const manualInput = el('input', 'opn-picker-manual');
    manualInput.type = 'text';
    manualInput.hidden = true;
    manualInput.setAttribute('aria-label', (select.labels[0]?.textContent.trim() || 'Value') + ': ' + (MANUAL_LABEL[kind] || ''));
    if (kind === 'net') manualInput.placeholder = 'e.g. 192.168.1.0/24 or 2001:db8::1';
    if (kind === 'port') manualInput.placeholder = 'e.g. 443 or 5060-5070';
    if (kind === 'manual') manualInput.placeholder = 'Gateway name';
    root.append(toggle, menu);
    if (manualKind) root.append(manualInput);
    if (multiple && kind === 'picker') {
      const actions = el('div', 'opn-picker-actions');
      for (const [label, all] of [['Clear All', false], ['Select All', true]]) {
        const button = el('button', all ? 'opn-select-all' : 'opn-clear-all', label);
        button.type = 'button';
        button.setAttribute('aria-label', label + ': ' + (select.labels[0]?.textContent.trim() || select.name));
        button.addEventListener('click', () => {
          for (const option of select.options) if (!option.disabled) option.selected = all;
          render(); fire(select);
        });
        actions.append(button);
      }
      root.append(actions);
    }
    select.classList.add('opn-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');
    select.after(root);
    for (const label of select.labels) label.addEventListener('click', event => { event.preventDefault(); toggle.focus(); });

    let manualActive = false;
    let active = -1;

    // Values typed in earlier arrive as options marked data-manual.
    const manualOptions = () => Array.from(select.options).filter(o => o.dataset.manual === 'true');
    function initialManual() {
      const typed = manualOptions().filter(o => o.selected);
      if (manualKind && typed.length) { manualActive = true; manualInput.value = typed[0].value; }
    }

    function selectedOptions() { return Array.from(select.options).filter(o => o.selected && !(o.dataset.manual === 'true')); }

    function render() {
      const chosen = selectedOptions().map(o => o.textContent.trim());
      // As in OPNsense, the picker names the manual option and the box below holds the value.
      if (manualActive) chosen.push(MANUAL_LABEL[kind]);
      const placeholder = select.dataset.placeholder || (multiple ? 'Nothing selected' : '');
      text.textContent = chosen.length ? chosen.join(', ') : placeholder;
      text.classList.toggle('is-placeholder', !chosen.length);
      toggle.title = text.textContent;
      manualInput.hidden = !manualActive;
      if (!menu.hidden) buildList();
    }

    function items() {
      const result = [];
      if (manualKind) result.push({value: MANUAL, label: MANUAL_LABEL[kind], selected: manualActive, special: true});
      let group = null;
      for (const option of select.options) {
        if (option.dataset.manual === 'true') continue;
        const parent = option.parentElement.tagName === 'OPTGROUP' ? option.parentElement.label : null;
        if (parent !== group) { group = parent; if (group) result.push({group}); }
        result.push({value: option.value, label: option.textContent.trim(), selected: option.selected, option});
      }
      return result;
    }

    function buildList() {
      const query = search.value.trim().toLowerCase();
      list.replaceChildren();
      let pendingGroup = null;
      let index = 0;
      for (const item of items()) {
        if (item.group) { pendingGroup = item.group; continue; }
        if (query && !item.label.toLowerCase().includes(query) && !String(item.value).toLowerCase().includes(query)) continue;
        if (pendingGroup) { const head = el('li', 'opn-picker-group', pendingGroup); head.setAttribute('role', 'presentation'); list.append(head); pendingGroup = null; }
        const li = el('li', 'opn-picker-option' + (item.special ? ' is-special' : ''));
        li.setAttribute('role', 'option');
        li.setAttribute('aria-selected', String(item.selected));
        li.id = listId + '_' + index;
        li.dataset.index = String(index++);
        li.append(el('span', 'opn-picker-label', item.label));
        if (multiple || item.selected) li.append(el('span', 'opn-check'));
        li.addEventListener('mousedown', event => event.preventDefault());
        li.addEventListener('click', () => choose(item));
        list.append(li);
      }
      if (!list.querySelector('[role=option]')) list.append(el('li', 'opn-picker-empty', 'No results matched "' + search.value + '"'));
      setActive(Math.min(Math.max(active, 0), list.querySelectorAll('[role=option]').length - 1));
    }

    function setActive(index) {
      const options = list.querySelectorAll('[role=option]');
      options.forEach(node => node.classList.remove('is-active'));
      active = index;
      if (options[index]) {
        options[index].classList.add('is-active');
        options[index].scrollIntoView({block: 'nearest'});
        search.setAttribute('aria-activedescendant', options[index].id);
      }
    }

    function clearManual() {
      manualActive = false;
      for (const option of manualOptions()) option.remove();
    }

    function choose(item) {
      if (item.special) {
        // Manual entry is exclusive, as in OPNsense: it replaces every other choice.
        for (const option of select.options) option.selected = false;
        manualActive = true;
        syncManual(false);
        close();
        render();
        manualInput.focus();
        return;
      }
      const option = item.option;
      if (multiple) {
        clearManual();
        const exclusive = kind === 'net' && option.value === 'any';
        if (exclusive && !option.selected) for (const other of select.options) other.selected = false;
        else if (kind === 'net') for (const other of select.options) if (other.value === 'any') other.selected = false;
        option.selected = !option.selected;
        render(); fire(select);
      } else {
        clearManual();
        option.selected = true;
        close(); render(); fire(select); toggle.focus();
      }
    }

    function syncManual(notify = true) {
      const value = manualInput.value.trim();
      for (const option of manualOptions()) option.remove();
      if (!value && !multiple) {
        // An empty manual box means "any" rather than whatever option happens to be first.
        const any = Array.from(select.options).find(o => o.value === '');
        if (any) any.selected = true;
      }
      if (value) {
        // A typed value that matches a listed option selects that option instead, like OPNsense.
        const listed = Array.from(select.options).find(o => o.value === value);
        if (listed) { listed.selected = true; manualActive = false; manualInput.value = ''; }
        else {
          const option = new Option(value, value, true, true);
          option.dataset.manual = 'true';
          select.add(option);
        }
      }
      render();
      if (notify) fire(select);
    }

    function open() {
      if (openPicker && openPicker !== close) openPicker();
      menu.hidden = false;
      root.classList.add('is-open');
      toggle.setAttribute('aria-expanded', 'true');
      search.value = '';
      active = Math.max(0, items().filter(i => !i.group).findIndex(i => i.selected));
      buildList();
      search.focus();
      openPicker = close;
    }

    function close() {
      if (menu.hidden) return;
      menu.hidden = true;
      root.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
      if (openPicker === close) openPicker = null;
    }

    toggle.addEventListener('click', () => (menu.hidden ? open() : close()));
    toggle.addEventListener('keydown', event => {
      if (['ArrowDown', 'ArrowUp'].includes(event.key)) { event.preventDefault(); open(); }
    });
    search.addEventListener('input', () => { active = 0; buildList(); });
    search.addEventListener('keydown', event => {
      const count = list.querySelectorAll('[role=option]').length;
      if (event.key === 'ArrowDown') { event.preventDefault(); setActive(Math.min(active + 1, count - 1)); }
      else if (event.key === 'ArrowUp') { event.preventDefault(); setActive(Math.max(active - 1, 0)); }
      else if (event.key === 'Enter') { event.preventDefault(); list.querySelectorAll('[role=option]')[active]?.click(); }
      else if (event.key === 'Escape') { event.preventDefault(); close(); toggle.focus(); }
      else if (event.key === 'Tab') close();
    });
    manualInput.addEventListener('change', () => syncManual());
    manualInput.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); syncManual(); } });
    // Other scripts that change the native select programmatically dispatch "change".
    select.addEventListener('change', () => { if (!select.dataset.opnSyncing) render(); });
    select.addEventListener('opn:refresh', render);
    // Validation-error styling and disabled state follow the native control.
    if (select.disabled) toggle.disabled = true;
    initialManual();
    render();
  }

  document.addEventListener('click', event => {
    if (openPicker && !event.target.closest('.opn-picker.is-open')) openPicker();
  });

  function initialize(root) {
    root.querySelectorAll('select.opn-select').forEach(enhance);
  }
  window.opnSelect = {initialize, enhance};
  document.addEventListener('DOMContentLoaded', () => initialize(document));
  document.addEventListener('formset:added', event => initialize(event.target));
})();
