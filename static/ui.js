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
