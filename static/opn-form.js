/* Editors laid out like OPNsense dialogs (templates/admin/opn_change_form.html). */
document.addEventListener('DOMContentLoaded', function () {
  // In a page's dialog frame: Close/Cancel/Escape ask that page to close the dialog.
  if (window.parent !== window && document.body.classList.contains('opn-modal')) {
    const close = () => window.parent.postMessage({type: 'opn-dialog', close: true}, window.location.origin);
    for (const button of document.querySelectorAll('[data-dialog-close]')) button.addEventListener('click', close);
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !event.defaultPrevented && !document.querySelector('.opn-picker.open, .select2-container--open')) close();
    });
  }
  const page = document.querySelector('.opn-form-page #content-main > form');
  if (!page) return;
  const fullHelp = document.getElementById('opn-full-help');
  const store = {
    get(key) { try { return localStorage.getItem(key); } catch (error) { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch (error) { /* private mode */ } },
  };
  function apply() { page.classList.toggle('opn-full-help-visible', fullHelp.getAttribute('aria-checked') === 'true'); }
  if (fullHelp) {
    fullHelp.setAttribute('aria-checked', String(store.get('opn.form.fullhelp') === 'true'));
    fullHelp.addEventListener('click', () => {
      const on = fullHelp.getAttribute('aria-checked') !== 'true';
      fullHelp.setAttribute('aria-checked', String(on));
      store.set('opn.form.fullhelp', String(on));
      apply();
    });
    apply();
  }
  for (const button of page.querySelectorAll('button.opn-help-toggle:not(.no-help)')) {
    button.addEventListener('click', () => {
      const row = button.closest('.form-row');
      row.classList.toggle('opn-help-open');
      button.setAttribute('aria-expanded', String(row.classList.contains('opn-help-open')));
    });
  }
  // Open the first field with an error, and focus the first field of a new object.
  const error = page.querySelector('.opn-form-row.errors input, .opn-form-row.errors select, .opn-form-row.errors textarea');
  const first = page.querySelector('.opn-form-row input:not([type=hidden]):not([type=checkbox]), .opn-form-row select');
  (error || (document.body.classList.contains('opn-modal') ? first : null))?.focus();
});
