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
  dialog.addEventListener('close', () => { frame.src = 'about:blank'; dialog.style.height = ''; });
  // A small dialog takes the height of its form (same origin), up to the viewport.
  frame.addEventListener('load', () => {
    if (!dialog.classList.contains('opn-dialog-small') || !frame.contentDocument?.body) return;
    const form = frame.contentDocument.querySelector('#content-main > form') || frame.contentDocument.body;
    dialog.style.height = Math.min(form.getBoundingClientRect().height + 4, window.innerHeight - 48) + 'px';
  });

  async function refresh() {
    const response = await fetch(location.href, {credentials: 'same-origin', headers: {'X-Requested-With': 'fetch'}});
    if (!response.ok) throw new Error(String(response.status));
    const fresh = new DOMParser().parseFromString(await response.text(), 'text/html');
    for (const region of document.querySelectorAll('[data-refresh][id]')) {
      const replacement = fresh.getElementById(region.id);
      if (replacement) region.replaceWith(document.importNode(replacement, true));
    }
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
