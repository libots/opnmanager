/* Firewall: Rules grid, laid out like OPNsense's rule list. */
document.addEventListener('DOMContentLoaded', function () {
  const dataNode=document.getElementById('rule-data'),form=document.getElementById('rule-filters');
  if (!dataNode || !form) return;
  let data=JSON.parse(dataNode.textContent),groups=new Map(Object.entries(data.groups));
  const panel=document.getElementById('rules-panel'),body=document.getElementById('rule-table-body'),table=document.getElementById('rules-table');
  const manager=data.manager,canSelect=manager?(data.can_edit||data.can_delete):data.can_import;
  // Manager rules are selected by id for bulk commands; snapshot rows by index for import.
  const key=rule=>manager?rule.id:rule.index;
  const selected=new Set(),collapsed=new Set();let matching=[],page=1;
  const store={
    get(name,fallback){try{const stored=localStorage.getItem(name);return stored===null?fallback:JSON.parse(stored);}catch(e){return fallback;}},
    set(name,value){try{localStorage.setItem(name,JSON.stringify(value));}catch(e){/* not kept */}},
  };
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
  const editURL=id=>'/admin/fleet/rule/'+encodeURIComponent(id)+'/change/';
  const cloneURL=id=>'/admin/fleet/rule/add/?clone='+encodeURIComponent(id);

  // --- messages after commands and saves ---
  const toast=document.getElementById('rule-toast');let toastTimer;
  function notify(message,level) {
    if (!message) return;
    toast.textContent=message;toast.className='rule-toast notice '+(level==='error'?'error':'success');toast.hidden=false;
    clearTimeout(toastTimer);toastTimer=setTimeout(()=>{toast.hidden=true;},level==='error'?12000:5000);
  }

  // --- columns: every rule setting can be shown; Select and Commands stay first and last ---
  const yesNo=flag=>flag?'Yes':'No';
  const STATE_TYPES={keep:'keep state',sloppy:'sloppy state',modulate:'modulate state',synproxy:'synproxy state',none:'no state'};
  const actionName=rule=>{const action=rule.action||'pass';return action[0].toUpperCase()+action.slice(1);};
  const versionName=rule=>rule.ipprotocol==='inet6'?'IPv6':rule.ipprotocol==='inet46'?'IPv4+IPv6':'IPv4';
  const protocolName=rule=>!rule.protocol||rule.protocol==='any'?'*':rule.protocol;
  const bindingText=(display,inverted)=>(inverted?'! ':'')+(display||'*');
  function bindingCell(td,count,display,inverted) {
    if (count<2) { td.textContent=bindingText(display,inverted); return; }
    // Several interfaces: a count and the network icon, as OPNsense does; names in the tooltip, one per line.
    const span=element('span',(inverted?'! ':'')+count+' ','rule-binding-count');span.dataset.tip=display.split(', ').join('\n');
    span.tabIndex=0;span.setAttribute('aria-label',(inverted?'not ':'')+display);span.append(icon('network-wired'));td.append(span);
  }
  function addressCell(td,lines){td.classList.add('rule-addresses');for(const line of lines||['*'])td.append(element('div',line));}
  const COLUMNS=[
    {key:'check',fixed:true,cls:'rule-check'},
    {key:'tags',label:'Categories',cls:'rule-tags',iconHead:'tag',text:r=>r.category_display,cell(td,r){
      for (const badge of r.category_badges) { const tag=icon('tag','rule-category-tag',badge.name);tag.style.color='#'+badge.color;td.append(tag); }
    }},
    {key:'state',label:'Enabled',cls:'rule-state',iconHead:'square-check-regular',text:r=>yesNo(r.enabled!=='0'),cell(td,r){
      const enabled=r.enabled!=='0';
      if (manager && data.can_edit) td.append(commandButton(enabled?'square-check-regular':'square-regular',enabled?'Disable rule':'Enable rule',enabled?'disable':'enable',[r.id],'rule-toggle'));
      else td.append(icon(enabled?'square-check-regular':'square-regular','',enabled?'Enabled':'Disabled'));
    }},
    {key:'icons',label:'Icons',cls:'rule-flags',text:()=>'',cell(td,r){
      const action=r.action||'pass',direction=r.direction||'in';
      td.append(
        icon({block:'xmark',reject:'circle-xmark',match:'sliders'}[action]||'play','action-'+action,actionName(r)),
        icon({out:'arrow-left-long',any:'right-left'}[direction]||'arrow-right-long','direction','Direction: '+({out:'out',any:'both'}[direction]||'in')),
        icon('bolt',r.quick!=='0'?'quick':'off',r.quick!=='0'?'Quick':'Not quick (last match wins)'),
        icon('circle-info',r.log==='1'?'log':'off',r.log==='1'?'Logging enabled':'Logging disabled'),
      );
      const sequence=element('span',r.sequence||'','rule-sequence');sequence.title='Sequence';td.append(sequence);
    }},
    {key:'sequence',label:'Sequence',hidden:true,text:r=>r.sequence||''},
    {key:'action',label:'Action',hidden:true,text:actionName},
    {key:'quick',label:'Quick',hidden:true,text:r=>yesNo(r.quick!=='0')},
    {key:'direction',label:'Direction',hidden:true,text:r=>({out:'out',any:'both'}[r.direction]||'in')},
    {key:'rule',label:'Rule (interfaces)',head:'Rule',headIcon:'network-wired',text:r=>bindingText(r.interface_display,r.interfacenot==='1'),
      cell:(td,r)=>bindingCell(td,r.binding_count,r.interface_display,r.interfacenot==='1')},
    {key:'origin',label:'Origin',headIcon:'network-wired',text:r=>bindingText(r.origin_display,r['received-on-not']==='1'),
      cell:(td,r)=>bindingCell(td,r.origin_count,r.origin_display,r['received-on-not']==='1')},
    {key:'version',label:'Version',text:versionName},
    {key:'protocol',label:'Protocol',text:protocolName,cell(td,r){td.textContent=protocolName(r);if(r.icmptype||r.icmp6type)td.append(element('small',r.icmptype||r.icmp6type));}},
    {key:'icmp',label:'ICMP type',hidden:true,text:r=>[r.icmptype,r.icmp6type].filter(Boolean).join(', ')},
    {key:'source',label:'Source',text:r=>r.source_display,cell:(td,r)=>addressCell(td,r.source_lines)},
    {key:'source_port',label:'Source port',head:'Port',text:r=>r.source_port||'*'},
    {key:'destination',label:'Destination',text:r=>r.destination_display,cell:(td,r)=>addressCell(td,r.destination_lines)},
    {key:'destination_port',label:'Destination port',head:'Port',text:r=>r.destination_port||'*'},
    {key:'log',label:'Log',hidden:true,text:r=>yesNo(r.log==='1')},
    {key:'statetype',label:'State type',hidden:true,text:r=>STATE_TYPES[r.statetype]||r.statetype||''},
    {key:'gateway',label:'Gateway',text:r=>r.gateway||'*'},
    {key:'description',label:'Description',cls:'rule-description',text:r=>r.description||''},
    {key:'categories',label:'Category names',hidden:true,text:r=>r.category_display||''},
    {key:'placement',label:'Placement',hidden:true,text:r=>({floating:'Floating',group:'Group',interface:'Interface'}[r.placement]||'')},
    {key:'targets',label:'Deploy to',hidden:true,managerOnly:true,text:r=>r.targets_display||''},
    {key:'commands',fixed:true,cls:'rule-commands',head:'Commands'},
  ].filter(col=>!col.managerOnly||manager);
  const byKey=new Map(COLUMNS.map(col=>[col.key,col])),movable=COLUMNS.filter(col=>!col.fixed).map(col=>col.key);
  const COLUMN_STORE='opn.rules.columns';
  function loadLayout() {
    const defaults={order:[...movable],hidden:new Set(movable.filter(k=>byKey.get(k).hidden))};
    const stored=store.get(COLUMN_STORE,null);
    if (!stored || !Array.isArray(stored.order)) return defaults;
    // Columns added since the layout was saved take their default place and visibility.
    const known=new Set(Array.isArray(stored.known)?stored.known:stored.order);
    const order=stored.order.filter(k=>movable.includes(k));
    for (const k of movable) if (!order.includes(k)) order.splice(Math.min(movable.indexOf(k),order.length),0,k);
    const hidden=new Set((stored.hidden||[]).filter(k=>movable.includes(k)));
    for (const k of movable) if (!known.has(k) && byKey.get(k).hidden) hidden.add(k);
    return {order,hidden};
  }
  let layout=loadLayout();
  const visibleColumns=()=>[COLUMNS[0],...layout.order.filter(k=>!layout.hidden.has(k)).map(k=>byKey.get(k)),COLUMNS[COLUMNS.length-1]];
  const label=k=>byKey.get(k).label;
  function setLayout(next) {
    layout=next;store.set(COLUMN_STORE,{order:layout.order,hidden:[...layout.hidden],known:movable});
    buildHeader();render();
  }
  function moveColumn(k,target,after) {
    if (k===target) return;
    const order=layout.order.filter(c=>c!==k);order.splice(order.indexOf(target)+(after?1:0),0,k);
    setLayout({order,hidden:layout.hidden});
  }
  const headerRow=table.tHead.rows[0],selectAll=document.getElementById('rule-select-all');
  let dragging=null;
  function clearDrop(){for(const th of headerRow.cells)th.classList.remove('col-drop-before','col-drop-after','col-dragging');}
  function buildHeader() {
    headerRow.replaceChildren(...visibleColumns().map(col=>{
      const th=element('th',undefined,col.cls);th.dataset.col=col.key;
      if (col.key==='check') { if(selectAll)th.append(selectAll); return th; }
      if (col.iconHead) { th.title=col.label;th.append(element('span',col.label,'visually-hidden'),icon(col.iconHead)); }
      else { if(col.headIcon)th.append(icon(col.headIcon),document.createTextNode(' '));th.append(document.createTextNode(col.head||col.label));if(col.head&&col.head!==col.label)th.title=col.label; }
      if (col.fixed) return th;
      th.draggable=true;th.classList.add('col-draggable');th.title=(th.title||col.label)+' · drag to reorder';
      th.addEventListener('dragstart',event=>{dragging=col.key;event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('text/plain',col.key);th.classList.add('col-dragging');});
      th.addEventListener('dragover',event=>{
        if (!dragging || dragging===col.key) return;
        event.preventDefault();event.dataTransfer.dropEffect='move';
        const rect=th.getBoundingClientRect(),after=event.clientX>rect.left+rect.width/2;
        th.classList.toggle('col-drop-after',after);th.classList.toggle('col-drop-before',!after);
      });
      th.addEventListener('dragleave',()=>th.classList.remove('col-drop-before','col-drop-after'));
      th.addEventListener('drop',event=>{
        event.preventDefault();if(!dragging)return;
        const after=th.classList.contains('col-drop-after'),moved=dragging;dragging=null;clearDrop();moveColumn(moved,col.key,after);
        if(!columnMenu.hidden)buildColumnMenu();
      });
      th.addEventListener('dragend',()=>{dragging=null;clearDrop();});
      return th;
    }));
  }
  const columnList=document.getElementById('rule-columns-list');
  function buildColumnMenu(focus) {
    columnList.replaceChildren(...layout.order.map((k,index)=>{
      const item=element('li'),box=element('input'),name=element('label');
      box.type='checkbox';box.checked=!layout.hidden.has(k);box.id='rule-column-'+k;
      box.addEventListener('change',()=>{const hidden=new Set(layout.hidden);if(box.checked)hidden.delete(k);else hidden.add(k);setLayout({order:layout.order,hidden});buildColumnMenu({col:k});});
      name.htmlFor=box.id;name.append(box,document.createTextNode(' '+label(k)));item.append(name);
      for (const [text,step] of [['↑',-1],['↓',1]]) {
        const button=element('button',text,'rule-column-move');button.type='button';button.id=`rule-column-${k}-${step}`;
        button.setAttribute('aria-label',`Move ${label(k)} ${step<0?'left':'right'}`);
        const target=layout.order[index+step];button.disabled=!target;item.append(button);
        button.addEventListener('click',()=>{moveColumn(k,target,step>0);buildColumnMenu({col:k,step});});
      }
      return item;
    }));
    // Keep keyboard focus on the control just used, or on its checkbox once an arrow is disabled.
    if (focus) { const target=focus.step&&document.getElementById(`rule-column-${focus.col}-${focus.step}`);(target&&!target.disabled?target:document.getElementById('rule-column-'+focus.col)).focus(); }
  }
  const columnToggle=document.getElementById('rule-columns-toggle'),columnMenu=document.getElementById('rule-columns-menu');
  function showColumnMenu(open){columnMenu.hidden=!open;columnToggle.setAttribute('aria-expanded',String(open));if(open){buildColumnMenu();columnList.querySelector('input')?.focus();}}
  columnToggle.addEventListener('click',()=>showColumnMenu(columnMenu.hidden));
  // composedPath, not contains: a menu click rebuilds the list and detaches its target.
  document.addEventListener('click',event=>{if(!columnMenu.hidden&&!event.composedPath().includes(document.getElementById('rule-columns')))showColumnMenu(false);});
  columnMenu.addEventListener('keydown',event=>{if(event.key==='Escape'){showColumnMenu(false);columnToggle.focus();}});
  document.getElementById('rule-columns-reset').addEventListener('click',()=>{setLayout({order:[...movable],hidden:new Set(movable.filter(k=>byKey.get(k).hidden))});buildColumnMenu();});

  // --- filtering, Inspect (evaluation order) and Tree (by category) ---
  function matches(row) {
    if (value('placement') && value('placement')!==row.placement) return false;
    const bindings=split(row.interface),iface=value('interface');
    if (iface && bindings.size) {
      let affected=bindings.has(iface) || Array.from(bindings).some(binding=>(groups.get(binding)||[]).includes(iface));
      if (row.interfacenot==='1') affected=!affected;
      if (!affected) return false;
    }
    if (value('category') && !split(row.categories).has(value('category'))) return false;
    const query=value('q').trim().toLocaleLowerCase();
    return !query || data.search_fields.map(name=>String(row[name] || '')).join(' ').toLocaleLowerCase().includes(query);
  }
  const RANK={floating:0,group:1,interface:2},sequenceOf=rule=>parseInt(rule.sequence,10)||0;
  const evaluationOrder=(a,b)=>RANK[a.placement]-RANK[b.placement]||sequenceOf(a)-sequenceOf(b);
  const toggles={inspect:store.get('opn.rules.inspect',false),tree:store.get('opn.rules.tree',false)};
  function sections(rules) {
    if (toggles.tree) {
      const byCategory=new Map();
      for (const rule of rules) {
        const name=(rule.category_display||'').split(', ')[0]||'Uncategorized';
        if(!byCategory.has(name))byCategory.set(name,[]);byCategory.get(name).push(rule);
      }
      return Array.from(byCategory).sort((a,b)=>(a[0]==='Uncategorized')-(b[0]==='Uncategorized')||a[0].localeCompare(b[0]))
        .map(([name,list])=>({name,kind:'category',rules:list.sort(evaluationOrder)}));
    }
    // Inspect: one list in the order the firewall evaluates it (floating, group, then interface rules).
    if (toggles.inspect) return [{name:null,rules:[...rules].sort(evaluationOrder)}];
    const byLabel=new Map();
    for (const rule of rules) { if(!byLabel.has(rule.section_label))byLabel.set(rule.section_label,[]);byLabel.get(rule.section_label).push(rule); }
    return Array.from(byLabel).sort((a,b)=>RANK[a[1][0].placement]-RANK[b[1][0].placement]||a[0].localeCompare(b[0]))
      .map(([name,list])=>({name,kind:list[0].placement,rules:list}));
  }

  // --- commands (manager policy): posted with fetch, then the table is refreshed ---
  const bulkForm=document.getElementById('rule-bulk-form');
  async function runCommand(action,ids) {
    if (!ids.length) return;
    if (action==='edit') { openDialog(ids.length===1?editURL(ids[0]):'/admin/fleet/rule/bulk-edit/?'+ids.map(id=>'ids='+encodeURIComponent(id)).join('&')); return; }
    if (action==='delete' && !confirm(ids.length===1?'Delete this rule from manager policy?':`Delete ${ids.length} rules from manager policy?`)) return;
    const payload=new FormData();
    payload.append('csrfmiddlewaretoken',bulkForm.elements.csrfmiddlewaretoken.value);payload.append('action',action);
    for (const id of ids) payload.append('ids',id);
    try {
      // getAttribute: the form's hidden "action" input shadows form.action.
      const response=await fetch(bulkForm.getAttribute('action'),{method:'POST',body:payload,headers:{Accept:'application/json'},credentials:'same-origin'});
      const result=await response.json().catch(()=>({ok:false,message:response.status===403?'You don\'t have permission for that.':'The command failed. Reload the page and try again.'}));
      notify(result.message,result.ok?'success':'error');
      if (result.ok && action==='delete') for (const id of ids) selected.delete(id);
    } catch (e) { notify('Could not reach OPNmanager. Check the connection and try again.','error'); }
    await refresh();
  }
  function commandButton(name,title,action,ids,className) {
    const button=element('button',undefined,'rule-command'+(className?' '+className:''));button.type='button';button.title=title;button.setAttribute('aria-label',title);
    button.append(icon(name));button.addEventListener('click',()=>runCommand(action,ids));return button;
  }
  function dialogLink(name,title,url) {
    const link=element('a',undefined,'rule-command');link.href=url;link.title=title;link.setAttribute('aria-label',title);link.append(icon(name));
    link.addEventListener('click',event=>{if(event.button||event.ctrlKey||event.metaKey||event.shiftKey)return;event.preventDefault();openDialog(url);});
    return link;
  }

  // --- the rule dialog: the editor in a frame, like OPNsense's modal ---
  const dialog=document.getElementById('rule-dialog'),frame=document.getElementById('rule-dialog-frame');
  function openDialog(url) {
    const target=new URL(url,location.origin);target.searchParams.set('_modal','1');target.searchParams.set('_next',here());
    frame.src=target.pathname+target.search;dialog.showModal();frame.focus();
  }
  dialog.addEventListener('close',()=>{frame.src='about:blank';});
  window.addEventListener('message',event=>{
    if (event.origin!==location.origin || event.source!==frame.contentWindow || event.data?.type!=='opn-rule-dialog') return;
    dialog.close();
    if (event.data.done) { notify(event.data.message,'success');refresh(); }
  });

  // --- refresh: reload the rule data in place ---
  const reload=document.getElementById('rule-reload');
  async function refresh() {
    reload.disabled=true;reload.classList.add('is-loading');
    try {
      const response=await fetch(here(),{headers:{Accept:'application/json'},credentials:'same-origin'});
      if (!response.ok || !(response.headers.get('content-type')||'').includes('application/json')) throw new Error();
      data=await response.json();groups=new Map(Object.entries(data.groups));
      const present=new Set(data.rows.map(key));
      for (const id of [...selected]) if (!present.has(id)) selected.delete(id);
      render();
    } catch (e) { notify('Could not refresh the rules. Your session may have ended; reload the page.','error'); }
    finally { reload.disabled=false;reload.classList.remove('is-loading'); }
  }

  // --- rendering ---
  function selectionStatus() {
    const count=selected.size,shown=matching.filter(row=>selected.has(key(row))).length;
    document.getElementById('rule-selection-status').textContent=!canSelect||!count?'':manager?`${count} selected${shown!==count?` (${count-shown} hidden by filters)`:''}`:`${count} selected for import (${shown} matching filters)`;
    if (selectAll) {
      selectAll.checked=matching.length>0 && matching.every(row=>selected.has(key(row)));
      selectAll.indeterminate=matching.some(row=>selected.has(key(row))) && !selectAll.checked;
      selectAll.disabled=!matching.length;
    }
    for (const button of document.querySelectorAll('#rule-bulk-bar [data-bulk]')) button.disabled=!count;
  }
  function renderRow(rule) {
    const row=element('tr',undefined,'rule-row'+(rule.enabled==='0'?' rule-disabled':'')),id=key(rule);
    for (const col of visibleColumns()) {
      const td=element('td',undefined,col.cls);row.append(td);
      if (col.key==='check') {
        if (!canSelect) continue;
        const box=element('input');box.type='checkbox';box.checked=selected.has(id);
        if (!manager) { box.name='rule_indices';box.value=rule.index; }
        box.setAttribute('aria-label',(manager?'Select ':'Import ')+rule.description);
        box.addEventListener('change',()=>{if(box.checked)selected.add(id);else selected.delete(id);row.classList.toggle('rule-selected',box.checked);selectionStatus();});
        row.classList.toggle('rule-selected',box.checked);td.append(box);
      } else if (col.key==='commands') renderCommands(td,rule);
      else if (col.cell) col.cell(td,rule);
      else td.textContent=col.text(rule);
    }
    return row;
  }
  function renderCommands(td,rule) {
    if (manager) {
      if (data.can_edit) td.append(commandButton(rule.log==='1'?'bell':'bell-slash',rule.log==='1'?'Logging on: click to turn off':'Logging off: click to turn on',rule.log==='1'?'nolog':'log',[rule.id]));
      if (data.can_edit) td.append(dialogLink('pencil','Edit '+rule.description,editURL(rule.id)));
      if (data.can_add) td.append(dialogLink('copy-regular','Clone '+rule.description,cloneURL(rule.id)));
      if (data.can_delete) td.append(commandButton('trash-can','Delete','delete',[rule.id],'danger'));
    } else if (rule.manager_id && data.can_edit) {
      td.append(dialogLink('pencil','Edit manager rule '+rule.description,editURL(rule.manager_id)));
    } else if (data.can_import) {
      const button=element('button',undefined,'rule-command');button.type='button';button.title='Select to import';button.setAttribute('aria-label','Select '+rule.description+' to import');button.append(icon('plus'));
      button.addEventListener('click',()=>{selected.add(rule.index);render();document.getElementById('rule-import-options').scrollIntoView({behavior:'smooth'});});td.append(button);
    }
  }
  const pageSize=document.getElementById('rule-page-size');
  pageSize.value=String(store.get('opn.rules.page_size',500));if(!pageSize.value)pageSize.value='500';
  const pager=document.getElementById('rule-pagination');
  function renderPager(pages) {
    const button=(text,target,labelText,current)=>{
      const b=element('button',text,'page-link'+(current?' active':''));b.type='button';b.setAttribute('aria-label',labelText);
      if(current)b.setAttribute('aria-current','page');b.disabled=current||target<1||target>pages;
      b.addEventListener('click',()=>{page=target;render();table.closest('.rules-scroll').scrollTop=0;});return b;
    };
    const first=Math.max(1,Math.min(page-2,pages-4)),numbers=[];
    for (let n=first;n<=Math.min(pages,first+4);n++) numbers.push(button(String(n),n,'Page '+n,n===page));
    pager.replaceChildren(button('«',1,'First page'),button('‹',page-1,'Previous page'),...numbers,button('›',page+1,'Next page'),button('»',pages,'Last page'));
  }
  let sectionNames=[];
  const expandAll=document.getElementById('rule-expand-all');
  function render() {
    matching=data.rows.filter(matches);body.replaceChildren();
    const ordered=sections(matching),entries=ordered.flatMap(section=>section.rules.map(rule=>[section,rule]));
    const size=Number(pageSize.value)||entries.length||1,pages=Math.max(1,Math.ceil(entries.length/size));
    page=Math.min(Math.max(page,1),pages);
    const from=(page-1)*size,shown=entries.slice(from,from+size),width=visibleColumns().length;
    sectionNames=ordered.filter(section=>section.name).map(section=>section.name);
    let current=null;
    for (const [section,rule] of shown) {
      if (section!==current && section.name) {
        const open=!collapsed.has(section.name),header=element('tr',undefined,'rule-section'),td=element('td');td.colSpan=width;header.append(td);
        const button=element('button');button.type='button';button.setAttribute('aria-expanded',String(open));
        button.append(icon(open?'square-minus-regular':'square-plus-regular','fold'),icon({floating:'layer-group',group:'sitemap',category:'tag'}[section.kind]||'ethernet','kind'),document.createTextNode(` ${section.name} (${section.rules.length})`));
        button.addEventListener('click',()=>{if(collapsed.has(section.name))collapsed.delete(section.name);else collapsed.add(section.name);render();});td.append(button);body.append(header);
      }
      current=section;
      if (!section.name || !collapsed.has(section.name)) body.append(renderRow(rule));
    }
    if (!matching.length) { const row=element('tr'),td=element('td','No matching rules. Clear filters or pull a firewall snapshot.','empty');td.colSpan=width;row.append(td);body.append(row); }
    const filtered=matching.length!==data.rows.length?` (filtered from ${data.rows.length})`:'';
    document.getElementById('rule-count').textContent=matching.length?`Showing ${from+1} to ${from+shown.length} of ${matching.length} entries${filtered}`:`No entries${filtered}`;
    renderPager(pages);
    const allCollapsed=sectionNames.length>0&&sectionNames.every(name=>collapsed.has(name));
    expandAll.hidden=!sectionNames.length;expandAll.replaceChildren(icon(allCollapsed?'angles-down':'angles-up'));
    expandAll.title=allCollapsed?'Expand all sections':'Collapse all sections';expandAll.setAttribute('aria-label',expandAll.title);
    selectionStatus();
  }

  // --- toolbar ---
  function updateURL() {
    const url=new URL(location.href);
    for(const name of ['firewall','placement','interface','category','q']) {
      const current=value(name);if(current)url.searchParams.set(name,current);else url.searchParams.delete(name);
    }
    url.searchParams.delete('enabled');history.replaceState(null,'',url);
  }
  const filtersChanged=()=>{page=1;render();updateURL();};
  expandAll.addEventListener('click',()=>{
    const allCollapsed=sectionNames.every(name=>collapsed.has(name));
    for(const name of sectionNames){if(allCollapsed)collapsed.delete(name);else collapsed.add(name);}
    render();
  });
  for (const [name,id] of [['inspect','rule-inspect'],['tree','rule-tree']]) {
    const button=document.getElementById(id);button.hidden=false;button.setAttribute('aria-pressed',String(toggles[name]));
    button.addEventListener('click',()=>{toggles[name]=!toggles[name];store.set('opn.rules.'+name,toggles[name]);button.setAttribute('aria-pressed',String(toggles[name]));collapsed.clear();filtersChanged();});
  }
  const interfaceSelect=document.getElementById('rule-interface');
  form.addEventListener('input',event=>{if(event.target.name==='q')filtersChanged();});
  form.addEventListener('change',event=>{
    if (event.target.name==='firewall') { form.elements.interface.value='';form.elements.placement.value='';form.elements.category.value='';form.submit();return; }
    if (event.target===interfaceSelect) {
      const [kind,choice]=[interfaceSelect.value.split(':')[0],interfaceSelect.value.slice(interfaceSelect.value.indexOf(':')+1)];
      form.elements.placement.value=kind==='placement'?choice:'';form.elements.interface.value=kind==='interface'?choice:'';
    }
    if (event.target===pageSize) { store.set('opn.rules.page_size',Number(pageSize.value));page=1;render();return; }
    // Search filters as you type; its change on blur would re-render under the click that caused it.
    if (event.target.name==='q' || event.target.closest('#rule-columns')) return;
    filtersChanged();
  });
  form.addEventListener('submit',event=>{event.preventDefault();filtersChanged();});
  document.getElementById('rule-filter-submit').hidden=true;
  reload.addEventListener('click',refresh);
  selectAll?.addEventListener('change',event=>{
    for(const row of matching){if(event.target.checked)selected.add(key(row));else selected.delete(key(row));}render();
  });
  document.getElementById('rule-export').addEventListener('click',()=>{
    const columns=visibleColumns().filter(col=>col.text&&col.key!=='icons');
    const quote=text=>/[",\n]/.test(text)?'"'+text.replaceAll('"','""')+'"':text;
    const lines=[columns.map(col=>col.label),...sections(matching).flatMap(section=>section.rules).map(rule=>columns.map(col=>String(col.text(rule)??'')))];
    const link=element('a');link.href=URL.createObjectURL(new Blob([lines.map(line=>line.map(quote).join(',')).join('\r\n')+'\r\n'],{type:'text/csv'}));
    link.download=(manager?'manager':form.elements.firewall.selectedOptions[0].textContent.replace(/ snapshot$/,''))+'-rules.csv';
    link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);
  });
  const fullscreen=document.getElementById('rule-fullscreen');
  function setFullscreen(on) {
    panel.classList.toggle('rules-fullscreen',on);document.body.classList.toggle('rules-fullscreen-open',on);
    fullscreen.setAttribute('aria-pressed',String(on));fullscreen.title=on?'Exit full screen':'Full screen';fullscreen.setAttribute('aria-label',fullscreen.title);
    fullscreen.replaceChildren(icon(on?'compress':'expand'));
  }
  fullscreen.addEventListener('click',()=>setFullscreen(!panel.classList.contains('rules-fullscreen')));
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&panel.classList.contains('rules-fullscreen')&&!dialog.open&&columnMenu.hidden)setFullscreen(false);});
  for (const button of document.querySelectorAll('#rule-bulk-bar [data-bulk]')) {
    button.addEventListener('click',()=>runCommand(button.dataset.bulk,Array.from(selected)));
  }
  document.getElementById('rule-add')?.addEventListener('click',event=>{if(event.button||event.ctrlKey||event.metaKey||event.shiftKey)return;event.preventDefault();openDialog('/admin/fleet/rule/add/');});
  document.getElementById('clear-rule-selection')?.addEventListener('click',()=>{selected.clear();render();});
  document.getElementById('rule-import-form')?.addEventListener('submit',()=>{
    // Include selections hidden by filters, pages or collapsed sections exactly once.
    const hidden=document.getElementById('rule-hidden-selections');hidden.replaceChildren();
    const rendered=new Set(Array.from(body.querySelectorAll('input[name=rule_indices]:checked'),box=>box.value));
    for(const index of selected)if(!rendered.has(index)){const input=element('input');input.type='hidden';input.name='rule_indices';input.value=index;hidden.append(input);}
  });
  for (const id of ['rule-columns','rule-export','rule-fullscreen']) document.getElementById(id).hidden=false;
  pageSize.closest('label').hidden=false;
  buildHeader();render();
});
