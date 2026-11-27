/* Open editors in a dialog over the page, as OPNsense does, and refresh the page in place.

   Links with data-dialog ("small" for a short form) open their href (an admin editor) framed with ?_modal=1. When the editor
   saves, it posts {type: 'opn-dialog', done: true}; the page then re-fetches itself and swaps every
   element marked data-refresh (matched by id), so filters, scroll position and toggles survive. */
(function () {
  const dialog = document.getElementById('opn-dialog');
  const frame = document.getElementById('opn-dialog-frame');
  if (!dialog || !frame) return;
  const status = document.getElementById('opn-dialog-status');

  function open(url, size) {
    // Each dialog starts at its CSS size; a small one then fits its form once it has loaded.
    dialog.style.height = '';
    dialog.classList.toggle('opn-dialog-small', size === 'small');
    const target = new URL(url, location.origin);
    target.searchParams.set('_modal', '1');
    frame.src = target.pathname + target.search;
    dialog.showModal();
    frame.focus();
  }
  document.addEventListener('click', event => {
    const link = event.target.closest('a[data-dialog]');
    if (!link || event.button || event.ctrlKey || event.metaKey || event.shiftKey) return;
    event.preventDefault();
    open(link.href, link.dataset.dialog);
  });
  dialog.addEventListener('close', () => { watcher?.disconnect(); watcher = null; frame.src = 'about:blank'; dialog.style.height = ''; });
  // A small dialog takes the height of its form (same origin), up to the viewport, and keeps
  // following it: hints under address fields and validation errors arrive after the page loads.
  let watcher = null;
  function fit(form) {
    dialog.style.height = Math.min(Math.ceil(form.getBoundingClientRect().height) + 4, window.innerHeight - 48) + 'px';
  }
  frame.addEventListener('load', () => {
    watcher?.disconnect();
    watcher = null;
    // Closing loads about:blank into the frame, and a save loads a page without a form: neither may
    // resize the dialog, or the next one would open a few pixels high.
    if (!dialog.open || !dialog.classList.contains('opn-dialog-small')) return;
    const form = frame.contentDocument?.querySelector('#content-main > form');
    if (!form) return;
    fit(form);
    if ('ResizeObserver' in window) {
      watcher = new ResizeObserver(() => fit(form));
      watcher.observe(form);
    }
  });
  window.addEventListener('resize', () => {
    const form = frame.contentDocument?.querySelector('#content-main > form');
    if (form && dialog.open && dialog.classList.contains('opn-dialog-small')) fit(form);
  });

  // What a swapped region would otherwise lose: where its scrolling boxes were scrolled to and
  // which of its <details> were open. Elements are matched by their position in the region.
  const SCROLLERS = '.li-scroll, .table-scroll, [data-keep-scroll]';
  function remember(region) {
    const boxes = [region, ...region.querySelectorAll(SCROLLERS)];
    return {
      scroll: boxes.map(box => [box.scrollTop, box.scrollLeft]),
      open: Array.from(region.querySelectorAll('details'), details => details.open),
    };
  }
  function restore(region, state) {
    const boxes = [region, ...region.querySelectorAll(SCROLLERS)];
    boxes.forEach((box, index) => {
      const [top, left] = state.scroll[index] || [0, 0];
      box.scrollTop = top;
      box.scrollLeft = left;
    });
    const details = region.querySelectorAll('details');
    if (details.length === state.open.length) details.forEach((item, index) => { item.open = state.open[index]; });
  }

  async function refresh() {
    const response = await fetch(location.href, {credentials: 'same-origin', headers: {'X-Requested-With': 'fetch'}});
    if (!response.ok) throw new Error(String(response.status));
    const fresh = new DOMParser().parseFromString(await response.text(), 'text/html');
    const pageX = window.scrollX, pageY = window.scrollY;
    for (const region of document.querySelectorAll('[data-refresh][id]')) {
      const replacement = fresh.getElementById(region.id);
      if (!replacement) continue;
      const state = remember(region);
      const node = document.importNode(replacement, true);
      region.replaceWith(node);
      restore(node, state);
    }
    window.scrollTo(pageX, pageY);
    document.dispatchEvent(new CustomEvent('opn-refreshed'));
  }
  function say(text, kind) {
    if (!status) return;
    status.textContent = text;
    status.className = 'notice ' + (kind || 'success');
    status.hidden = !text;
  }
  window.addEventListener('message', async event => {
    if (event.origin !== location.origin || event.source !== frame.contentWindow || event.data?.type !== 'opn-dialog') return;
    dialog.close();
    if (!event.data.done) return;
    try {
      await refresh();
      say(event.data.message, 'success');
    } catch (error) {
      say(event.data.message + ' Reload the page to see it.', 'warning');
    }
  });
})();
