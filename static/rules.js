/* Firewall: Rules grid, laid out like OPNsense's rule list. */
document.addEventListener('DOMContentLoaded', function () {
  const dataNode=document.getElementById('rule-data'),form=document.getElementById('rule-filters');
  if (!dataNode || !form) return;
  const data=JSON.parse(dataNode.textContent),rows=data.rows,groups=new Map(Object.entries(data.groups));
  const body=document.getElementById('rule-table-body'),table=document.getElementById('rules-table');
  const manager=data.manager,canSelect=manager?(data.can_edit||data.can_delete):data.can_import;
  // Manager rules are selected by id for bulk commands; snapshot rows by index for import.
  const key=rule=>manager?rule.id:rule.index;
  const selected=new Set(),collapsed=new Set();let matching=[];
  const split=value=>new Set(String(value || '').split(',').map(v=>v.trim()).filter(Boolean));
  const element=(tag,text,className)=>{const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(className)el.className=className;return el;};
  const value=name=>form.elements.namedItem(name).value;
  const icons=document.getElementById('rule-icons').content;
  function icon(name,className,title) {
    const svg=icons.querySelector(`[data-icon="${name}"] svg`).cloneNode(true);
    const wrap=element('span',undefined,'rule-icon'+(className?' '+className:''));wrap.append(svg);
    if(title){wrap.dataset.tip=title;wrap.setAttribute('role','img');wrap.setAttribute('aria-label',title);}
    return wrap;
  }
  const here=()=>location.pathname+location.search;
  const editURL=id=>'/admin/fleet/rule/'+encodeURIComponent(id)+'/change/?_next='+encodeURIComponent(here());

  function matches(row) {
    if (value('placement') && value('placement')!==row.placement) return false;
    const bindings=split(row.interface),iface=value('interface');
    if (iface && bindings.size) {
      let affected=bindings.has(iface) || Array.from(bindings).some(binding=>(groups.get(binding)||[]).includes(iface));
      if (row.interfacenot==='1') affected=!affected;
      if (!affected) return false;
    }
    if (value('category') && !split(row.categories).has(value('category'))) return false;
    if (value('enabled') && value('enabled')!==String(row.enabled??'1')) return false;
    const query=value('q').trim().toLocaleLowerCase();
    return !query || data.search_fields.map(key=>String(row[key] || '')).join(' ').toLocaleLowerCase().includes(query);
  }

  // --- commands (manager policy): one hidden form posts every toggle/delete ---
  function command(action,ids) {
    if (!ids.length) return;
    if (action==='edit') {
      if (ids.length===1) { location.href=editURL(ids[0]); return; }
      const url=new URL('/admin/fleet/rule/bulk-edit/',location.origin);
      for (const id of ids) url.searchParams.append('ids',id);
      url.searchParams.set('_next',here());location.href=url;return;
    }
    if (action==='delete' && !confirm(ids.length===1?'Delete this rule from manager policy?':`Delete ${ids.length} rules from manager policy?`)) return;
    const bulk=document.getElementById('rule-bulk-form');
    bulk.elements.action.value=action;bulk.elements._next.value=here();
    document.getElementById('rule-bulk-ids').replaceChildren(...ids.map(id=>Object.assign(element('input'),{type:'hidden',name:'ids',value:id})));
    bulk.submit();
  }
  function commandButton(name,title,action,ids,className) {
    const button=element('button',undefined,'rule-command'+(className?' '+className:''));button.type='button';button.title=title;button.setAttribute('aria-label',title);
    button.append(icon(name));button.addEventListener('click',()=>command(action,ids));return button;
  }

  function selectionStatus() {
    const count=selected.size,shown=matching.filter(row=>selected.has(key(row))).length;
    document.getElementById('rule-selection-status').textContent=!canSelect||!count?'':manager?`${count} selected${shown!==count?` (${count-shown} hidden by filters)`:''}`:`${count} selected for import (${shown} matching filters)`;
    const toggle=document.getElementById('rule-select-all');
    if (toggle) {
      toggle.checked=matching.length>0 && matching.every(row=>selected.has(key(row)));
      toggle.indeterminate=matching.some(row=>selected.has(key(row))) && !toggle.checked;
      toggle.disabled=!matching.length;
    }
    for (const button of document.querySelectorAll('#rule-bulk-bar [data-bulk]')) button.disabled=!count;
  }
  function cell(row,text,cls){const td=element('td',text,cls);row.append(td);return td;}
  function bindingCell(row,count,display,inverted) {
    const td=cell(row);
    if (!count) { td.textContent=inverted?'! *':'*'; return; }
    if (count===1) { td.textContent=(inverted?'! ':'')+display; return; }
    // Several interfaces: a count and the network icon, as OPNsense does; names in the tooltip, one per line.
    const span=element('span',(inverted?'! ':'')+count+' ','rule-binding-count');span.dataset.tip=display.split(', ').join('\n');
    span.tabIndex=0;span.setAttribute('aria-label',(inverted?'not ':'')+display);span.append(icon('network-wired'));td.append(span);
  }
  function renderRow(rule) {
    const row=element('tr',undefined,'rule-row'+(rule.enabled==='0'?' rule-disabled':'')),id=key(rule);
    const check=cell(row,undefined,'rule-check');
    if (canSelect) {
      const box=element('input');box.type='checkbox';box.checked=selected.has(id);
      if (!manager) { box.name='rule_indices';box.value=rule.index; }
      box.setAttribute('aria-label',(manager?'Select ':'Import ')+rule.description);
      box.addEventListener('change',()=>{if(box.checked)selected.add(id);else selected.delete(id);row.classList.toggle('rule-selected',box.checked);selectionStatus();});
      row.classList.toggle('rule-selected',box.checked);check.append(box);
    }
    const tags=cell(row,undefined,'rule-tags');
    for (const badge of rule.category_badges) { const tag=icon('tag','rule-category-tag',badge.name);tag.style.color='#'+badge.color;tags.append(tag); }
    const enabled=rule.enabled!=='0',state=cell(row,undefined,'rule-state');
    if (manager && data.can_edit) state.append(commandButton(enabled?'square-check-regular':'square-regular',enabled?'Disable rule':'Enable rule',enabled?'disable':'enable',[rule.id],'rule-toggle'));
    else state.append(icon(enabled?'square-check-regular':'square-regular','',enabled?'Enabled':'Disabled'));
    const flags=cell(row,undefined,'rule-flags'),action=rule.action || 'pass',direction=rule.direction||'in';
    flags.append(
      icon({block:'xmark',reject:'circle-xmark',match:'sliders'}[action]||'play','action-'+action,action[0].toUpperCase()+action.slice(1)),
      icon({out:'arrow-left-long',any:'right-left'}[direction]||'arrow-right-long','direction','Direction: '+({out:'out',any:'both'}[direction]||'in')),
      icon('bolt',rule.quick!=='0'?'quick':'off',rule.quick!=='0'?'Quick':'Not quick (last match wins)'),
      icon('circle-info',rule.log==='1'?'log':'off',rule.log==='1'?'Logging enabled':'Logging disabled'),
    );
    const sequence=element('span',rule.sequence||'','rule-sequence');sequence.title='Sequence';flags.append(sequence);
    bindingCell(row,rule.binding_count,rule.interface_display,rule.interfacenot==='1');
    bindingCell(row,rule.origin_count,rule.origin_display,rule['received-on-not']==='1');
    cell(row,rule.ipprotocol==='inet6'?'IPv6':rule.ipprotocol==='inet46'?'IPv4+IPv6':'IPv4');
    const protocol=cell(row,!rule.protocol||rule.protocol==='any'?'*':rule.protocol);if(rule.icmptype || rule.icmp6type)protocol.append(element('small',rule.icmptype || rule.icmp6type));
    const addresses=lines=>{const td=cell(row,undefined,'rule-addresses');for(const line of lines||['*'])td.append(element('div',line));};
    addresses(rule.source_lines);cell(row,rule.source_port || '*');
    addresses(rule.destination_lines);cell(row,rule.destination_port || '*');
    cell(row,rule.gateway || '*');
    cell(row,rule.description,'rule-description');
    const commands=cell(row,undefined,'rule-commands');
    if (manager) {
      if (data.can_edit) commands.append(commandButton(rule.log==='1'?'bell':'bell-slash',rule.log==='1'?'Logging on: click to turn off':'Logging off: click to turn on',rule.log==='1'?'nolog':'log',[rule.id]));
      if (data.can_edit) { const edit=element('a',undefined,'rule-command');edit.href=editURL(rule.id);edit.title='Edit';edit.setAttribute('aria-label','Edit '+rule.description);edit.append(icon('pencil'));commands.append(edit); }
      if (data.can_add) { const clone=element('a',undefined,'rule-command');clone.href='/admin/fleet/rule/add/?clone='+encodeURIComponent(rule.id)+'&_next='+encodeURIComponent(here());clone.title='Clone';clone.setAttribute('aria-label','Clone '+rule.description);clone.append(icon('copy-regular'));commands.append(clone); }
      if (data.can_delete) commands.append(commandButton('trash-can','Delete','delete',[rule.id],'danger'));
    } else if (rule.manager_id && data.can_edit) {
      const edit=element('a',undefined,'rule-command');edit.href=editURL(rule.manager_id);edit.title='Edit manager rule';edit.setAttribute('aria-label','Edit manager rule '+rule.description);edit.append(icon('pencil'));commands.append(edit);
    } else if (data.can_import) {
      const button=element('button',undefined,'rule-command');button.type='button';button.title='Select to import';button.setAttribute('aria-label','Select '+rule.description+' to import');button.append(icon('plus'));
      button.addEventListener('click',()=>{selected.add(rule.index);render();document.getElementById('rule-import-options').scrollIntoView({behavior:'smooth'});});commands.append(button);
    }
    return row;
  }
  function updateURL() {
    const url=new URL(location.href);
    for(const name of ['firewall','placement','interface','category','enabled','q']) {
      const current=value(name);if(current)url.searchParams.set(name,current);else url.searchParams.delete(name);
    }
    history.replaceState(null,'',url);
  }
  let sectionNames=[];
  const expandAll=document.getElementById('rule-expand-all');
  function render() {
    matching=rows.filter(matches);body.replaceChildren();
    const sections=new Map();
    for(const rule of matching){if(!sections.has(rule.section_label))sections.set(rule.section_label,[]);sections.get(rule.section_label).push(rule);}
    const rank=section=>section[1][0].placement==='floating'?0:section[1][0].placement==='group'?1:2;
    const ordered=Array.from(sections).sort((a,b)=>rank(a)-rank(b)||a[0].localeCompare(b[0]));
    sectionNames=ordered.map(([name])=>name);
    for(const [name,sectionRows] of ordered) {
      const open=!collapsed.has(name),placement=sectionRows[0].placement;
      const section=element('tr',undefined,'rule-section'),td=cell(section);td.colSpan=table.tHead.rows[0].cells.length;
      const button=element('button');button.type='button';button.setAttribute('aria-expanded',String(open));
      button.append(icon(open?'square-minus-regular':'square-plus-regular','fold'),icon({floating:'layer-group',group:'sitemap'}[placement]||'ethernet','kind'),document.createTextNode(` ${name} (${sectionRows.length})`));
      button.addEventListener('click',()=>{if(collapsed.has(name))collapsed.delete(name);else collapsed.add(name);render();});td.append(button);body.append(section);
      if(open)for(const rule of sectionRows)body.append(renderRow(rule));
    }
    if(!matching.length){const row=element('tr'),td=cell(row,'No matching rules. Clear filters or pull a firewall snapshot.','empty');td.colSpan=table.tHead.rows[0].cells.length;body.append(row);}
    document.getElementById('rule-count').textContent=`${matching.length} of ${rows.length} rules`;
    const allCollapsed=sectionNames.length>0&&sectionNames.every(name=>collapsed.has(name));
    expandAll.hidden=!sectionNames.length;expandAll.replaceChildren(icon(allCollapsed?'angles-down':'angles-up'));
    expandAll.title=expandAll.ariaLabel=allCollapsed?'Expand all sections':'Collapse all sections';
    selectionStatus();
  }
  expandAll.addEventListener('click',()=>{
    const allCollapsed=sectionNames.every(name=>collapsed.has(name));
    for(const name of sectionNames){if(allCollapsed)collapsed.delete(name);else collapsed.add(name);}
    render();
  });
  form.addEventListener('input',event=>{if(event.target.name==='q'){render();updateURL();}});
  form.addEventListener('change',event=>{
    if(event.target.name==='firewall'){
      form.elements.interface.value='';form.elements.category.value='';form.submit();return;
    }
    render();updateURL();
  });
  form.addEventListener('submit',event=>{event.preventDefault();render();updateURL();});
  form.addEventListener('reset',event=>{
    event.preventDefault();for(const name of ['placement','interface','category','enabled','q'])form.elements.namedItem(name).value='';
    collapsed.clear();render();updateURL();
  });
  document.getElementById('rule-filter-submit').hidden=true;
  document.getElementById('rule-reload').addEventListener('click',()=>location.reload());
  document.getElementById('rule-select-all')?.addEventListener('change',event=>{
    for(const row of matching){if(event.target.checked)selected.add(key(row));else selected.delete(key(row));}render();
  });
  for (const button of document.querySelectorAll('#rule-bulk-bar [data-bulk]')) {
    button.addEventListener('click',()=>command(button.dataset.bulk,Array.from(selected)));
  }
  document.getElementById('rule-add')?.addEventListener('click',event=>{event.currentTarget.href='/admin/fleet/rule/add/?_next='+encodeURIComponent(here());});
  document.getElementById('clear-rule-selection')?.addEventListener('click',()=>{selected.clear();render();});
  document.getElementById('rule-import-form')?.addEventListener('submit',()=>{
    // Include selections hidden by filters/collapsed sections exactly once.
    const hidden=document.getElementById('rule-hidden-selections');hidden.replaceChildren();
    const rendered=new Set(Array.from(body.querySelectorAll('input[name=rule_indices]:checked'),box=>box.value));
    for(const index of selected)if(!rendered.has(index)){const input=element('input');input.type='hidden';input.name='rule_indices';input.value=index;hidden.append(input);}
  });
  render();
});
