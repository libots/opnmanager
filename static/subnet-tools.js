/* Address fields: a live hint under the field and a subnet calculator.

   Inputs marked data-subnet-hint="<kind>" (set by admin.OpnDialogAdmin.address_fields) get a line
   below them, fetched from data-hint-url: the usable range and size of a prefix, or what a template
   or range means at each site. data-hint-context names other fields the hint depends on (the
   logical interface, the firewall). data-calculator adds a button that opens a subnet calculator;
   "use" lets it write the chosen network back into the field. */
(function () {
  'use strict';

  // --- address arithmetic (BigInt, IPv4 and IPv6) ---
  function parse(text) {
    text = text.trim().toLowerCase();
    const [address, length] = text.split('/');
    let value = 0n, bits;
    if (address.includes(':')) {
      bits = 128;
      const halves = address.split('::');
      if (halves.length > 2) return null;
      const head = halves[0] ? halves[0].split(':') : [];
      const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
      const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
      const parts = [...head, ...Array(Math.max(fill, 0)).fill('0'), ...tail];
      if (parts.length !== 8 || fill < 0 || (halves.length === 2 && fill < 1)) return null;
      for (const part of parts) {
        if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
        value = (value << 16n) | BigInt(parseInt(part, 16));
      }
    } else {
      bits = 32;
      const parts = address.split('.');
      if (parts.length !== 4) return null;
      for (const part of parts) {
        if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null;
        value = (value << 8n) | BigInt(Number(part));
      }
    }
    const prefix = length === undefined ? bits : Number(length);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits || (length !== undefined && !/^\d+$/.test(length))) return null;
    return {value, bits, prefix};
  }
  function format(value, bits) {
    if (bits === 32) return [24n, 16n, 8n, 0n].map(shift => String((value >> shift) & 255n)).join('.');
    const parts = [];
    for (let shift = 112n; shift >= 0n; shift -= 16n) parts.push(((value >> shift) & 0xffffn).toString(16));
    let start = -1, length = 0;
    for (let i = 0; i < 8;) {
      if (parts[i] !== '0') { i++; continue; }
      let j = i;
      while (j < 8 && parts[j] === '0') j++;
      if (j - i > length && j - i > 1) { start = i; length = j - i; }
      i = j;
    }
    if (start < 0) return parts.join(':');
    return parts.slice(0, start).join(':') + '::' + parts.slice(start + length).join(':');
  }
  const all = bits => (1n << BigInt(bits)) - 1n;
  function network({value, bits, prefix}) {
    const host = all(bits - prefix);
    const mask = all(bits) ^ host;
    return {bits, prefix, mask, host, first: value & mask, last: (value & mask) | host, address: value};
  }
  const count = n => n.toLocaleString('en-US');
  function details(net) {
    const rows = [['Network', format(net.first, net.bits) + '/' + net.prefix]];
    if (net.bits === 32) {
      const usable = net.prefix >= 31 ? [net.first, net.last] : [net.first + 1n, net.last - 1n];
      const hosts = net.prefix === 32 ? 1n : net.prefix === 31 ? 2n : net.host - 1n;
      rows.push(['Netmask', format(net.mask, 32)], ['Wildcard', format(net.host, 32)],
        ['Usable range', format(usable[0], 32) + ' – ' + format(usable[1], 32)],
        ['Usable hosts', count(hosts)]);
      if (net.prefix < 31) rows.push(['Broadcast', format(net.last, 32)]);
    } else {
      rows.push(['Range', format(net.first, 128) + ' – ' + format(net.last, 128)],
        ['Addresses', net.prefix >= 96 ? count(net.host + 1n) : '2^' + (128 - net.prefix)]);
      if (net.prefix < 64) rows.push(['/64 networks', count(1n << BigInt(64 - net.prefix))]);
    }
    if (net.address !== net.first) rows.push(['Address', format(net.address, net.bits) + ' (host ' + count(net.address - net.first) + ')']);
    return rows;
  }

  // --- the calculator dialog (one per page) ---
  let calc = null;
  function calculator() {
    if (calc) return calc;
    const dialog = document.createElement('dialog');
    dialog.className = 'subnet-calc';
    dialog.setAttribute('aria-label', 'Subnet calculator');
    dialog.innerHTML = `
      <form method="dialog" class="subnet-calc-body">
        <div class="subnet-calc-head"><h2>Subnet calculator</h2><button type="button" class="subnet-calc-close" aria-label="Close" data-close>×</button></div>
        <div class="subnet-calc-inputs">
          <label>Address <input type="text" name="address" spellcheck="false" autocomplete="off" placeholder="10.20.40.0"></label>
          <label>Prefix length <span class="subnet-calc-prefix"><span>/</span><input type="number" name="prefix" min="0" max="32"></span></label>
          <input type="range" name="slider" min="0" max="32" aria-label="Prefix length">
        </div>
        <p class="subnet-calc-error" role="alert" hidden></p>
        <table class="subnet-calc-result"><tbody></tbody></table>
        <details class="subnet-calc-split"><summary>Split into smaller subnets</summary>
          <label>Into /<input type="number" name="split" min="1" max="32"></label>
          <table><thead><tr><th>Subnet</th><th>Usable</th></tr></thead><tbody></tbody></table>
          <p class="help subnet-calc-more" hidden></p>
        </details>
        <p class="help subnet-calc-note"></p>
        <div class="subnet-calc-actions"><button type="button" class="button" data-close>Close</button><button type="button" class="button primary" data-use>Use this network</button></div>
      </form>`;
    document.body.append(dialog);
    const form = dialog.querySelector('form');
    const field = name => form.elements[name];
    const error = dialog.querySelector('.subnet-calc-error');
    calc = {dialog, target: null, mode: 'view', current: null};

    function update(source) {
      const text = field('address').value.trim();
      const probe = parse(text.split('/')[0] || '');
      const bits = probe ? probe.bits : (text.includes(':') ? 128 : 32);
      for (const name of ['prefix', 'slider']) field(name).max = bits;
      if (source === 'address' && text.includes('/')) field('prefix').value = text.split('/')[1];
      if (source === 'slider') field('prefix').value = field('slider').value;
      field('slider').value = field('prefix').value;
      const parsed = parse((text.split('/')[0] || '') + '/' + field('prefix').value);
      const body = dialog.querySelector('.subnet-calc-result tbody');
      const split = dialog.querySelector('.subnet-calc-split tbody');
      body.replaceChildren(); split.replaceChildren();
      calc.current = null;
      dialog.querySelector('[data-use]').disabled = true;
      if (!parsed) { error.hidden = !text; error.textContent = 'Enter an IPv4 or IPv6 address and a prefix length.'; return; }
      error.hidden = true;
      const net = network(parsed);
      calc.current = net;
      dialog.querySelector('[data-use]').disabled = calc.mode !== 'use';
      for (const [label, value] of details(net)) {
        const row = body.insertRow();
        row.insertCell().textContent = label;
        row.insertCell().textContent = value;
      }
      // Subnets of the chosen size, at most 64 listed.
      field('split').min = net.prefix + 1;
      field('split').max = bits;
      let into = Number(field('split').value);
      if (!(into > net.prefix && into <= bits)) { into = Math.min(bits, net.prefix + (bits === 128 && net.prefix < 64 ? 64 - net.prefix : 2)); field('split').value = into; }
      const total = 1n << BigInt(into - net.prefix);
      const size = 1n << BigInt(bits - into);
      const shown = total > 64n ? 64n : total;
      for (let i = 0n; i < shown; i++) {
        const sub = network({value: net.first + i * size, bits, prefix: into});
        const row = split.insertRow();
        row.insertCell().textContent = format(sub.first, bits) + '/' + into;
        const usable = bits === 32 && into < 31 ? [sub.first + 1n, sub.last - 1n] : [sub.first, sub.last];
        row.insertCell().textContent = format(usable[0], bits) + ' – ' + format(usable[1], bits);
      }
      const more = dialog.querySelector('.subnet-calc-more');
      more.hidden = total <= 64n;
      more.textContent = 'Showing the first 64 of ' + count(total) + ' subnets.';
    }
    form.addEventListener('input', event => update(event.target.name));
    dialog.addEventListener('click', event => {
      if (event.target.closest('[data-close]')) dialog.close();
      if (event.target.closest('[data-use]') && calc.current && calc.target) {
        const net = calc.current;
        const kind = calc.target.dataset.subnetHint;
        const address = kind === 'interface' ? net.address : net.first;
        calc.target.value = format(address, net.bits) + '/' + net.prefix;
        calc.target.dispatchEvent(new Event('input', {bubbles: true}));
        dialog.close();
        calc.target.focus();
      }
    });
    calc.open = function (target) {
      calc.target = target;
      calc.mode = target.dataset.calculator;
      const value = target.value.trim().replace(/\bx\b/gi, '0');
      field('address').value = value.split('/')[0] || '';
      field('prefix').value = value.includes('/') ? value.split('/')[1] : (value.includes(':') ? 64 : 24);
      field('split').value = '';
      dialog.querySelector('.subnet-calc-note').textContent = calc.mode === 'use' ? '' :
        'Templates write the site part as x, so this calculator is for reference here: x is shown as 0.';
      dialog.querySelector('[data-use]').hidden = calc.mode !== 'use';
      update('address');
      dialog.showModal();
      field('address').focus();
    };
    return calc;
  }

  // --- live hints under the fields ---
  function hintFor(input) {
    const form = input.form;
    const hint = document.createElement('div');
    hint.className = 'subnet-hint';
    hint.setAttribute('aria-live', 'polite');
    hint.id = input.id + '_subnet_hint';
    input.setAttribute('aria-describedby', ((input.getAttribute('aria-describedby') || '') + ' ' + hint.id).trim());
    const holder = document.createElement('div');
    holder.className = 'subnet-field';
    input.parentNode.insertBefore(holder, input);
    holder.append(input);
    if (input.dataset.calculator) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'subnet-calc-button';
      button.title = 'Subnet calculator';
      button.setAttribute('aria-label', 'Open the subnet calculator');
      const icon = document.getElementById('subnet-calc-icon');
      if (icon) button.append(icon.content.cloneNode(true)); else button.textContent = 'Calc';
      button.addEventListener('click', () => calculator().open(input));
      holder.append(button);
    }
    holder.after(hint);
    const context = (input.dataset.hintContext || '').split(' ').filter(Boolean);
    const param = {logical_interface: 'interface', firewall: 'firewall'};
    let timer = null, serial = 0;
    async function refresh() {
      const query = new URLSearchParams({kind: input.dataset.subnetHint, value: input.value});
      for (const name of context) if (form.elements[name]) query.set(param[name] || name, form.elements[name].value);
      const mine = ++serial;
      if (!input.value.trim()) { hint.replaceChildren(); return; }
      try {
        const response = await fetch(input.dataset.hintUrl + '?' + query, {credentials: 'same-origin', headers: {Accept: 'application/json'}});
        const data = await response.json();
        if (mine !== serial) return;
        hint.replaceChildren();
        if (data.error) hint.append(Object.assign(document.createElement('div'), {className: 'subnet-hint-error', textContent: data.error}));
        for (const line of data.lines || []) {
          const row = document.createElement('div');
          if (line.error) row.className = 'subnet-hint-error';
          if (line.label) row.append(Object.assign(document.createElement('strong'), {textContent: line.label + ': '}));
          row.append(document.createTextNode(line.text));
          hint.append(row);
        }
      } catch (error) {
        if (mine === serial) hint.replaceChildren();
      }
    }
    const later = () => { clearTimeout(timer); timer = setTimeout(refresh, 250); };
    input.addEventListener('input', later);
    for (const name of context) form.elements[name]?.addEventListener('change', later);
    refresh();
  }

  function init() { document.querySelectorAll('input[data-subnet-hint]').forEach(hintFor); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
