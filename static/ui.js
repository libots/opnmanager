document.addEventListener('DOMContentLoaded', function () {
  // Django admin already supplies its own action-toggle. Other checkbox lists
  // get a master toggle scoped to their table or explicit selection container.
  const roots = new Set();
  document.querySelectorAll('input[type=checkbox][name]').forEach(box => {
    if (box.closest('[data-managed-selection]')) return;
    if (box.name === '_selected_action' || !['rule_indices','operations','selected_rules','firewalls','selected_firewalls'].includes(box.name)) return;
    roots.add(box.closest('table') || box.closest('[data-selection-list]') || box.parentElement.parentElement);
  });
  roots.forEach(root => {
    const boxes = () => Array.from(root.querySelectorAll('input[type=checkbox][name]')).filter(box => !box.disabled);
    if (!boxes().length) return;
    const label = document.createElement('label'), toggle = document.createElement('input');
    toggle.type = 'checkbox';toggle.setAttribute('aria-label','Select all or none');
    label.append(toggle, document.createTextNode(' All / none'));label.style.margin='12px';
    root.before(label);
    function update() {const all=boxes();toggle.checked=all.every(box=>box.checked);toggle.indeterminate=all.some(box=>box.checked)&&!toggle.checked;}
    toggle.addEventListener('change',()=>{boxes().forEach(box=>{box.checked=toggle.checked;box.dispatchEvent(new Event('change',{bubbles:true}));});update();});
    root.addEventListener('change',update);update();
  });
});

/* Sidebar: remember which sections are open and whether the menu is collapsed. */
(function () {
  const store = {
    get(key) { try { return localStorage.getItem(key); } catch (error) { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch (error) { /* private mode */ } },
  };
  document.addEventListener('DOMContentLoaded', function () {
    const nav = document.querySelector('.opn-menu');
    const toggle = document.getElementById('opn-sidebar-toggle');
    if (!nav || !toggle) return;
    const root = document.documentElement;
    const narrow = window.matchMedia('(max-width: 760px)');
    const sections = Array.from(nav.querySelectorAll('details[data-menu]'));
    let applying = false;
    const collapsed = () => root.classList.contains('sidebar-collapsed');

    function remember() {
      if (applying || collapsed()) return;
      const state = {};
      for (const details of sections) state[details.dataset.menu] = details.open;
      store.set('opn.sidebar.sections', JSON.stringify(state));
    }
    // In the collapsed icon rail every section is a hover flyout, so all are open
    // there; the stored expanded-mode state comes back when the menu expands.
    function applyCollapsed(on) {
      applying = true;
      root.classList.toggle('sidebar-collapsed', on);
      toggle.setAttribute('aria-pressed', String(on));
      toggle.querySelector('.visually-hidden').textContent = on ? 'Expand menu' : 'Collapse menu';
      if (on) {
        for (const details of sections) details.open = true;
      } else {
        let state = {};
        try { state = JSON.parse(store.get('opn.sidebar.sections') || '{}'); } catch (error) { state = {}; }
        for (const details of sections) {
          if (state[details.dataset.menu] !== undefined) details.open = state[details.dataset.menu];
          if (details.classList.contains('active-menu')) details.open = true;
        }
      }
      // details "toggle" events fire asynchronously; ignore the ones caused here.
      setTimeout(() => { applying = false; }, 0);
    }
    for (const details of sections) details.addEventListener('toggle', remember);
    nav.addEventListener('click', event => {
      // A collapsed flyout's headings shouldn't fold the flyout away.
      if (collapsed() && event.target.closest('summary')) event.preventDefault();
    });
    toggle.addEventListener('click', () => {
      // On phones the menu is an overlay that opens and closes; it isn't remembered.
      if (narrow.matches) { root.classList.toggle('sidebar-open'); return; }
      const on = !collapsed();
      store.set('opn.sidebar.collapsed', on ? '1' : '0');
      applyCollapsed(on);
    });
    // The icon rail is a desktop layout; phones always get the full overlay menu.
    applyCollapsed(!narrow.matches && store.get('opn.sidebar.collapsed') === '1');
  });
})();
