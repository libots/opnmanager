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
 *   tags    free-form chips, like OPNsense's tokenizer (see enhanceTags)
 * data-exclusive names an option that stands alone (e.g. "all"): choosing it
 * clears the others, choosing another clears it. Multi-select menus stay open
 * while you pick, like bootstrap-select. The native <select> stays in the form
 * and is what gets submitted.
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
    if (kind === 'tags') { enhanceTags(select); return; }
    select.dataset.opnPicker = 'true';
    const exclusiveValue = select.dataset.exclusive ?? (kind === 'net' ? 'any' : null);
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
          for (const option of select.options) {
            if (!option.disabled) option.selected = all && option.value !== exclusiveValue;
          }
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
      if (!menu.hidden) refreshList();
    }

    // Update checkmarks in place: rebuilding would lose the scroll position mid-pick.
    function refreshList() {
      for (const li of list.querySelectorAll('[role=option]')) {
        const item = li.opnItem;
        li.setAttribute('aria-selected', String(item.special ? manualActive : item.option.selected));
      }
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
        li.opnItem = item;
        li.append(el('span', 'opn-picker-label', item.label), el('span', 'opn-check'));
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
        if (exclusiveValue !== null) {
          if (option.value === exclusiveValue && !option.selected) for (const other of select.options) other.selected = false;
          else for (const other of select.options) if (other.value === exclusiveValue) other.selected = false;
        }
        option.selected = !option.selected;
        // The menu stays open for the next pick; only the checkmarks change.
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

  /*
   * Free-form chips, like OPNsense's tokenizer on alias content: chips with a ×,
   * typing with suggestions from the list, Enter/comma/paste to add, Backspace to
   * remove the last chip. Below it, OPNsense's Clear All / Copy / Paste / Text
   * links. Text swaps the chips for a one-item-per-line box in the same place;
   * whatever is in that box is used when the form is saved.
   */
  function enhanceTags(select) {
    if (select.dataset.opnPicker) return;
    select.dataset.opnPicker = 'true';
    const free = select.dataset.tags === 'true';
    const name = select.labels[0]?.textContent.trim().replace(/:$/, '') || 'Items';
    const root = el('div', 'opn-tokens');
    const box = el('div', 'opn-tokens-box');
    const chips = el('ul', 'opn-tokens-chips');
    chips.setAttribute('aria-label', name);
    const input = el('input', 'opn-tokens-input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.setAttribute('aria-label', 'Add to ' + name);
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-expanded', 'false');
    input.placeholder = select.dataset.placeholder || '';
    const menu = el('ul', 'opn-tokens-menu');
    menu.setAttribute('role', 'listbox');
    menu.id = (select.id || 'opn') + '_suggestions';
    input.setAttribute('aria-controls', menu.id);
    menu.hidden = true;
    box.append(chips, input);
    const text = el('textarea', 'opn-tokens-text');
    text.rows = 8;
    text.hidden = true;
    text.setAttribute('aria-label', name + ': one item per line');
    const status = el('p', 'opn-tokens-status');
    status.setAttribute('role', 'status');
    const actions = el('div', 'opn-picker-actions opn-tokens-actions');
    const action = (label, cls, handler) => {
      const button = el('button', cls, label);
      button.type = 'button';
      button.setAttribute('aria-label', label + ': ' + name);
      button.addEventListener('click', handler);
      actions.append(button);
      return button;
    };
    root.append(box, menu, text, actions, status);
    select.classList.add('opn-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');
    select.after(root);
    for (const label of select.labels) label.addEventListener('click', event => { event.preventDefault(); (text.hidden ? input : text).focus(); });

    let active = -1;
    const values = () => Array.from(select.options).filter(o => o.selected).map(o => o.value);
    const labelOf = option => option.textContent.trim();

    function find(value) {
      const options = Array.from(select.options);
      return options.find(o => o.value === value) || options.find(o => o.value.toLowerCase() === value.toLowerCase() || labelOf(o).toLowerCase() === value.toLowerCase());
    }

    // Adds values in order; returns the ones that aren't allowed (only for fixed lists).
    function add(items) {
      const rejected = [];
      for (const raw of items) {
        const value = raw.trim();
        if (!value) continue;
        let option = find(value);
        if (!option) {
          if (!free) { rejected.push(value); continue; }
          option = new Option(value, value);
        }
        option.selected = true;
        select.append(option); // chips follow the order they were added in
      }
      return rejected;
    }

    function render() {
      chips.replaceChildren();
      for (const option of Array.from(select.options).filter(o => o.selected)) {
        const chip = el('li', 'opn-token');
        chip.append(el('span', 'opn-token-label', labelOf(option)));
        const remove = el('button', 'opn-token-remove', '×');
        remove.type = 'button';
        remove.setAttribute('aria-label', 'Remove ' + labelOf(option));
        remove.addEventListener('click', event => {
          event.stopPropagation();
          option.selected = false;
          render(); fire(select); input.focus();
        });
        chip.append(remove);
        chips.append(chip);
      }
      input.placeholder = values().length ? '' : (select.dataset.placeholder || '');
    }

    function suggestions() {
      const query = input.value.trim().toLowerCase();
      if (!query) return [];
      return Array.from(select.options).filter(o => !o.selected && (o.value.toLowerCase().includes(query) || labelOf(o).toLowerCase().includes(query))).slice(0, 50);
    }

    function showMenu() {
      const found = suggestions();
      menu.replaceChildren();
      found.forEach((option, index) => {
        const li = el('li', 'opn-picker-option', labelOf(option));
        li.setAttribute('role', 'option');
        li.id = menu.id + '_' + index;
        li.addEventListener('mousedown', event => event.preventDefault());
        li.addEventListener('click', () => { add([option.value]); input.value = ''; render(); fire(select); showMenu(); input.focus(); });
        menu.append(li);
      });
      active = -1;
      menu.hidden = !found.length;
      input.setAttribute('aria-expanded', String(!menu.hidden));
      input.removeAttribute('aria-activedescendant');
    }

    function setActive(index) {
      const items = menu.querySelectorAll('[role=option]');
      items.forEach(node => node.classList.remove('is-active'));
      active = index;
      if (items[index]) {
        items[index].classList.add('is-active');
        items[index].scrollIntoView({block: 'nearest'});
        input.setAttribute('aria-activedescendant', items[index].id);
      }
    }

    function commitTyped() {
      const items = input.value.split(/[\s,]+/).filter(Boolean);
      if (!items.length) return;
      const rejected = add(items);
      input.value = rejected.join(' ');
      status.textContent = rejected.length ? 'Not in the list: ' + rejected.join(', ') : '';
      render(); fire(select); showMenu();
    }

    input.addEventListener('input', () => {
      if (/[,\n]/.test(input.value)) commitTyped(); else showMenu();
    });
    input.addEventListener('keydown', event => {
      const count = menu.querySelectorAll('[role=option]').length;
      if (event.key === 'ArrowDown' && count) { event.preventDefault(); setActive(Math.min(active + 1, count - 1)); }
      else if (event.key === 'ArrowUp' && count) { event.preventDefault(); setActive(Math.max(active - 1, 0)); }
      else if (event.key === 'Enter') {
        event.preventDefault();
        if (active >= 0) menu.querySelectorAll('[role=option]')[active].click(); else commitTyped();
      } else if (event.key === 'Escape') { menu.hidden = true; input.setAttribute('aria-expanded', 'false'); }
      else if (event.key === 'Backspace' && !input.value) {
        const last = Array.from(select.options).filter(o => o.selected).pop();
        if (last) { last.selected = false; render(); fire(select); }
      }
    });
    input.addEventListener('paste', event => {
      const pasted = event.clipboardData?.getData('text');
      if (!pasted || !/[\s,]/.test(pasted.trim())) return;
      event.preventDefault();
      input.value += pasted;
      commitTyped();
    });
    input.addEventListener('blur', () => { menu.hidden = true; input.setAttribute('aria-expanded', 'false'); if (input.value.trim()) commitTyped(); });
    box.addEventListener('click', () => input.focus());

    // Text mode: the textarea takes the chips' place; switching back (or saving) applies it.
    function applyText() {
      const lines = Array.from(new Set(text.value.split(/\r?\n/).map(line => line.trim()).filter(Boolean)));
      for (const option of select.options) option.selected = false;
      const rejected = add(lines);
      render(); fire(select);
      if (rejected.length) {
        status.textContent = 'Not in the list: ' + rejected.join(', ');
        return false;
      }
      return true;
    }
    function setTextMode(on) {
      if (on) text.value = values().join('\n');
      else if (!applyText()) return;
      text.hidden = !on;
      box.hidden = on;
      textToggle.textContent = on ? 'Done' : 'Text';
      textToggle.setAttribute('aria-pressed', String(on));
      if (!on || !status.textContent.startsWith('Not')) status.textContent = '';
      (on ? text : input).focus();
    }

    action('Clear All', 'opn-clear-all', () => {
      for (const option of select.options) option.selected = false;
      text.value = '';
      render(); fire(select);
    });
    action('Copy', 'opn-copy', async () => {
      try { await navigator.clipboard.writeText(values().join('\n')); status.textContent = 'Copied ' + values().length + ' items.'; }
      catch (error) { setTextMode(true); text.select(); status.textContent = 'Copy from the text box (Ctrl+C).'; }
    });
    action('Paste', 'opn-paste', async () => {
      try {
        const pasted = await navigator.clipboard.readText();
        if (!text.hidden) { text.value += (text.value && !text.value.endsWith('\n') ? '\n' : '') + pasted; return; }
        const rejected = add(pasted.split(/[\s,]+/));
        status.textContent = rejected.length ? 'Not in the list: ' + rejected.join(', ') : '';
        render(); fire(select);
      } catch (error) {
        if (text.hidden) setTextMode(true);
        status.textContent = 'Paste into the text box (Ctrl+V), then choose Done or save.';
      }
    });
    const textToggle = action('Text', 'opn-text-mode', () => setTextMode(text.hidden));
    textToggle.setAttribute('aria-pressed', 'false');
    // Saving while the text box is open uses what's in it; no separate apply step.
    select.form?.addEventListener('submit', event => {
      if (!text.hidden && !applyText()) { event.preventDefault(); text.focus(); }
    });
    select.addEventListener('change', () => { if (!select.dataset.opnSyncing) render(); });
    if (select.disabled) { input.disabled = true; actions.hidden = true; }
    render();
  }

  document.addEventListener('click', event => {
    // composedPath() still lists nodes a click handler removed, so a click inside
    // the open menu never reads as a click outside it.
    if (openPicker && !event.composedPath().some(node => node.classList?.contains('is-open'))) openPicker();
  });

  function initialize(root) {
    root.querySelectorAll('select.opn-select').forEach(enhance);
  }
  window.opnSelect = {initialize, enhance};
  document.addEventListener('DOMContentLoaded', () => initialize(document));
  document.addEventListener('formset:added', event => initialize(event.target));
})();
