/* Fleet: Overview — drag rows (or use the arrow keys on a handle) to set the firewall order. */
(function () {
  const table = document.querySelector('table[data-reorder]');
  if (!table) return;
  const body = table.tBodies[0];
  const status = document.getElementById('firewall-order-status');
  const csrf = table.querySelector('input[name=csrfmiddlewaretoken]')?.value || '';
  let dragged = null, before = '';
  const rows = () => Array.from(body.querySelectorAll('tr[data-id]'));
  const order = () => rows().map(row => row.dataset.id).join(',');

  async function save() {
    if (order() === before) return;
    const data = new URLSearchParams();
    for (const row of rows()) data.append('order', row.dataset.id);
    status.textContent = 'Saving order…';
    try {
      const response = await fetch(table.dataset.reorder, {
        method: 'POST', credentials: 'same-origin', body: data,
        headers: {'X-CSRFToken': csrf, Accept: 'application/json'},
      });
      const reply = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(reply.error || 'The order was not saved. Reload the page and try again.');
      status.textContent = reply.message;
      before = order();
    } catch (error) {
      status.textContent = error.message;
    }
  }

  body.addEventListener('dragstart', event => {
    const handle = event.target.closest('.drag-handle');
    if (!handle) return;
    dragged = handle.closest('tr');
    before = order();
    dragged.classList.add('is-dragging');
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', dragged.dataset.id);
    event.dataTransfer.setDragImage(dragged, 20, 20);
  });
  body.addEventListener('dragover', event => {
    if (!dragged) return;
    const row = event.target.closest('tr[data-id]');
    if (!row || row === dragged) return;
    event.preventDefault();
    const box = row.getBoundingClientRect();
    row.parentNode.insertBefore(dragged, event.clientY < box.top + box.height / 2 ? row : row.nextSibling);
  });
  body.addEventListener('drop', event => { if (dragged) event.preventDefault(); });
  body.addEventListener('dragend', () => {
    if (!dragged) return;
    dragged.classList.remove('is-dragging');
    dragged = null;
    save();
  });
  // Keyboard: arrow keys on a handle move its row.
  body.addEventListener('keydown', event => {
    const handle = event.target.closest('.drag-handle');
    if (!handle || (event.key !== 'ArrowUp' && event.key !== 'ArrowDown')) return;
    event.preventDefault();
    const row = handle.closest('tr');
    const sibling = event.key === 'ArrowUp' ? row.previousElementSibling : row.nextElementSibling;
    if (!sibling || !sibling.dataset.id) return;
    before = order();
    if (event.key === 'ArrowUp') body.insertBefore(row, sibling); else body.insertBefore(sibling, row);
    handle.focus();
    save();
  });
})();
