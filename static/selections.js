(function () {
  function addTextEditor(select, $) {
    const wrapper = document.createElement('div');
    wrapper.className = 'opn-bulk-editor'; wrapper.style.margin = '6px 0';
    const toggle = document.createElement('button');
    toggle.type = 'button'; toggle.textContent = 'Edit as text';
    toggle.setAttribute('aria-expanded', 'false');
    const panel = document.createElement('div'); panel.hidden = true;
    const textarea = document.createElement('textarea');
    textarea.rows = 7; textarea.style.width = '100%';
    textarea.setAttribute('aria-label', (select.labels[0]?.textContent || 'Selections') + ' — one item per line');
    const hint = document.createElement('p');
    hint.textContent = select.dataset.tags === 'true' ? 'One item per line. New entries are allowed.' : 'One existing option name or value per line. Unknown or ambiguous entries must be corrected.';
    const apply = document.createElement('button'); apply.type = 'button'; apply.textContent = 'Apply list';
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel';
    const status = document.createElement('p'); status.setAttribute('role', 'alert');
    panel.append(hint, textarea, apply, cancel, status);
    wrapper.append(toggle, panel);
    const anchor = select.nextElementSibling?.classList.contains('select2') ? select.nextElementSibling : select;
    anchor.after(wrapper);
    toggle.addEventListener('click', function () {
      textarea.value = Array.from(select.selectedOptions, option => select.dataset.tags === 'true' ? option.value : option.textContent.trim()).join('\n');
      panel.hidden = false; toggle.hidden = true; toggle.setAttribute('aria-expanded', 'true'); status.textContent = ''; textarea.focus();
    });
    function close() { panel.hidden = true; toggle.hidden = false; toggle.setAttribute('aria-expanded', 'false'); status.textContent = ''; }
    cancel.addEventListener('click', close);
    apply.addEventListener('click', function () {
      const lines = Array.from(new Set(textarea.value.split(/\r?\n/).map(line => line.trim()).filter(Boolean)));
      const values = [], additions = [], invalid = [];
      for (const line of lines) {
        const options = Array.from(select.options);
        let matches = options.filter(option => option.value === line || option.textContent.trim() === line);
        if (!matches.length) matches = options.filter(option => option.value.toLowerCase() === line.toLowerCase() || option.textContent.trim().toLowerCase() === line.toLowerCase());
        if (matches.length === 1) values.push(matches[0].value);
        else if (!matches.length && select.dataset.tags === 'true') { additions.push(line); values.push(line); }
        else invalid.push(line);
      }
      if (invalid.length) { status.textContent = 'Unknown or ambiguous items: ' + invalid.join(', '); return; }
      for (const value of additions) select.add(new Option(value, value));
      $(select).val(Array.from(new Set(values))).trigger('change');
      close();
    });
    select.form?.addEventListener('submit', function (event) {
      if (!panel.hidden) { event.preventDefault(); status.textContent = 'Apply or cancel this text list before saving.'; textarea.focus(); }
    });
  }
  function initialize(root) {
    const $ = window.django && window.django.jQuery;
    if (!$ || !$.fn.select2) return;
    $(root).find('select.opn-select').each(function () {
      if (this.dataset.opnInitialized) return;
      this.dataset.opnInitialized = 'true';
      if (!$(this).hasClass('select2-hidden-accessible')) $(this).select2({tags: this.dataset.tags === 'true', width: 'resolve', placeholder: 'Type to search…', tokenSeparators: [','], allowClear: true});
      if (this.multiple) addTextEditor(this, $);
    });
  }
  document.addEventListener('DOMContentLoaded', function () {
    initialize(document);
    const protocol=document.getElementById('id_protocol');
    if (protocol) {
      function updateICMP() {
        const values=Array.from(protocol.selectedOptions, option=>option.value.toLowerCase());
        for (const [id,needle] of [['id_icmp_types','icmp'],['id_icmp6_types','ipv6-icmp']]) {
          const field=document.getElementById(id),row=field?.closest('.form-row');
          if (row) row.hidden=!values.includes(needle);
        }
      }
      window.django.jQuery(protocol).on('change',updateICMP);updateICMP();
    }
  });
  document.addEventListener('formset:added', function (event) { initialize(event.target); });
})();
