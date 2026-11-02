document.addEventListener('DOMContentLoaded', function () {
  const dataNode=document.getElementById('rule-data'),form=document.getElementById('rule-filters');
  if (!dataNode || !form) return;
  const data=JSON.parse(dataNode.textContent),rows=data.rows,groups=new Map(Object.entries(data.groups));
  const body=document.getElementById('rule-table-body'),table=document.getElementById('rules-table');
  const selected=new Set(),collapsed=new Set();let matching=[];
  const split=value=>new Set(String(value || '').split(',').map(v=>v.trim()).filter(Boolean));
  const element=(tag,text,className)=>{const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(className)el.className=className;return el;};
  const value=name=>form.elements.namedItem(name).value;
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
  function selectionStatus() {
    document.getElementById('rule-selection-status').textContent=data.can_import?`${selected.size} selected for import (${matching.filter(row=>selected.has(row.index)).length} matching filters)`:'';
    const toggle=document.getElementById('rule-select-all');
    if (toggle) {
      toggle.checked=matching.length>0 && matching.every(row=>selected.has(row.index));
      toggle.indeterminate=matching.some(row=>selected.has(row.index)) && !toggle.checked;
      toggle.disabled=!matching.length;
      toggle.title='Select all / none of the matching rules, including collapsed sections';
    }
  }
  function cell(row,text,cls){const td=element('td',text,cls);row.append(td);return td;}
  function renderRow(rule) {
    const row=element('tr',undefined,'rule-row'+(rule.enabled==='0'?' rule-disabled':''));
    if (form.elements.firewall.value) {
      const td=cell(row);
      if (data.can_import) {
        const box=element('input');box.type='checkbox';box.name='rule_indices';box.value=rule.index;box.checked=selected.has(rule.index);
        box.setAttribute('aria-label','Import '+rule.description);
        box.addEventListener('change',()=>{if(box.checked)selected.add(rule.index);else selected.delete(rule.index);selectionStatus();});td.append(box);
      }
    }
    const categories=cell(row,undefined,'rule-tags');
    for (const badge of rule.category_badges) {
      const tag=element('span',badge.name,'rule-category');tag.style.setProperty('--category-color','#'+badge.color);categories.append(tag);
    }
    const state=cell(row,rule.enabled==='0'?'—':'✓');state.title=rule.enabled==='0'?'Disabled':'Enabled';
    const flags=cell(row,undefined,'rule-flags');
    const action=rule.action || 'pass',direction=rule.direction||'in';
    const icon=element('span',action==='block'?'⊘':action==='reject'?'↩':'▶︎',action);icon.title=action;flags.append(icon,document.createTextNode(' '));
    const arrow=element('span',direction==='out'?'←':direction==='any'?'↔':'→');arrow.title='Direction: '+direction;flags.append(arrow);
    if(rule.quick!=='0'){const quick=element('span',' ⚡︎');quick.title='Quick';flags.append(quick);}
    if(rule.log==='1'){const log=element('span',' ●');log.title='Logging enabled';flags.append(log);}
    flags.append(element('small',rule.sequence || ''));
    cell(row,(rule.interface_display || '*')+(rule.interfacenot==='1'?' (inverted)':''));
    cell(row,rule.origin_display || '*');cell(row,rule.ipprotocol==='inet6'?'IPv6':rule.ipprotocol==='inet46'?'Any':'IPv4');
    const protocol=cell(row,rule.protocol || 'any');if(rule.icmptype || rule.icmp6type)protocol.append(element('small',rule.icmptype || rule.icmp6type));
    for (const key of ['source_display','source_port','destination_display','destination_port','gateway']) {
      const raw=rule[key] || '*',display=raw==='(self)'?'This Firewall':raw==='any'?'*':raw;
      cell(row,display);
    }
    cell(row,rule.description,'rule-description');
    const commands=cell(row,undefined,'rule-commands');
    if (rule.manager_id && data.can_edit) {
      const link=element('a','✎ Edit','button');link.href='/admin/fleet/rule/'+encodeURIComponent(rule.manager_id)+'/change/';link.title='Edit manager rule';commands.append(link);
    } else if (data.can_import) {
      const button=element('button','Select to import','button');button.type='button';
      button.addEventListener('click',()=>{selected.add(rule.index);render();document.getElementById('rule-import-options').scrollIntoView({behavior:'smooth'});});commands.append(button);
    } else commands.textContent='Read-only';
    return row;
  }
  function updateURL() {
    const url=new URL(location.href);
    for(const name of ['firewall','placement','interface','category','enabled','q']) {
      const current=value(name);if(current)url.searchParams.set(name,current);else url.searchParams.delete(name);
    }
    history.replaceState(null,'',url);
  }
  function render() {
    matching=rows.filter(matches);body.replaceChildren();
    const sections=new Map();
    for(const rule of matching){if(!sections.has(rule.section_label))sections.set(rule.section_label,[]);sections.get(rule.section_label).push(rule);}
    const ordered=Array.from(sections).sort((a,b)=>{
      const rank=section=>section[1][0].placement==='floating'?0:section[1][0].placement==='group'?1:2;
      return rank(a)-rank(b)||a[0].localeCompare(b[0]);
    });
    for(const [name,sectionRows] of ordered) {
      const section=element('tr',undefined,'rule-section'),td=cell(section);td.colSpan=table.tHead.rows[0].cells.length;
      const button=element('button',(collapsed.has(name)?'▸ ':'▾ ')+name+' ('+sectionRows.length+')');button.type='button';button.setAttribute('aria-expanded',String(!collapsed.has(name)));
      button.addEventListener('click',()=>{if(collapsed.has(name))collapsed.delete(name);else collapsed.add(name);render();});td.append(button);body.append(section);
      if(!collapsed.has(name))for(const rule of sectionRows)body.append(renderRow(rule));
    }
    if(!matching.length){const row=element('tr'),td=cell(row,'No matching rules. Clear filters or pull a firewall snapshot.','empty');td.colSpan=table.tHead.rows[0].cells.length;body.append(row);}
    document.getElementById('rule-count').textContent=`${matching.length} of ${rows.length} rules`;
    selectionStatus();
  }
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
    for(const row of matching){if(event.target.checked)selected.add(row.index);else selected.delete(row.index);}render();
  });
  document.getElementById('clear-rule-selection')?.addEventListener('click',()=>{selected.clear();render();});
  document.getElementById('rule-import-form')?.addEventListener('submit',()=>{
    // Include selections hidden by filters/collapsed sections exactly once.
    const hidden=document.getElementById('rule-hidden-selections');hidden.replaceChildren();
    const rendered=new Set(Array.from(body.querySelectorAll('input[name=rule_indices]:checked'),box=>box.value));
    for(const index of selected)if(!rendered.has(index)){const input=element('input');input.type='hidden';input.name='rule_indices';input.value=index;hidden.append(input);}
  });
  render();
});
