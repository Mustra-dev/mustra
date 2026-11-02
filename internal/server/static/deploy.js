/* Deploy authoring uses the same serialized model the server validates. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const node = (tag, text, cls) => { const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls; return e; };
  const row = (...children) => {const e=node('div',undefined,'deploy-row');e.append(...children);return e;};
  const button = (text, fn, primary=false) => {const e=node('button',text,primary?'primary':'secondary');e.type='button';e.onclick=fn;return e;};
  // Every section folds. The editor redraws on each change, so the choice is
  // kept by title; a section can also start folded (fold()) until someone
  // opens it.
  const collapsed=new Set(),touched=new Set();
  const card = (title,...children) => {const e=node('section',undefined,'deploy-card');e.dataset.card=title;
    const head=node('button',undefined,'deploy-card-head');head.type='button';head.innerHTML='<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M3 2l4 3-4 3z" fill="currentColor"/></svg>';head.append(node('h3',title));
    const sync=()=>{const c=collapsed.has(title);e.classList.toggle('is-collapsed',c);head.setAttribute('aria-expanded',String(!c));};
    head.onclick=()=>{touched.add(title);collapsed.has(title)?collapsed.delete(title):collapsed.add(title);sync();};
    e.append(head,...children);sync();return e;};
  const fold=(el,byDefault)=>{const t=el.dataset.card;if(!touched.has(t)){byDefault?collapsed.add(t):collapsed.delete(t);el.classList.toggle('is-collapsed',byDefault);el.firstChild.setAttribute('aria-expanded',String(!byDefault));}return el;};
  const cols=(...children)=>{children=children.filter(Boolean);const e=node('div',undefined,'deploy-cols'+(children.length<2?' is-single':''));for(const c of children){const col=node('div',undefined,'deploy-col');col.append(...[].concat(c).filter(Boolean));e.append(col);}return e;};
  const mark=(el,section)=>{el.dataset.section=section;return el;};
  const note = text => node('p',text,'deploy-note');
  const uid=()=> 's_'+crypto.randomUUID().replaceAll('-','').slice(0,16);
  const clone = v => JSON.parse(JSON.stringify(v));
  const state={catalogKind:location.hash==='#actions'?'action':'software',logSearch:'',logBefore:'',packages:[],sensors:[],agents:[],revisions:[],files:[],draft:null,packageID:'new',name:'',label:'',revision:null,variant:0,operation:'install',job:null,allRevisions:[],metadata:{},plans:[],templates:[],canOverride:false};
  async function api(path,method='GET',body) {const res=await fetch(path,{method,headers:body instanceof FormData?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:body instanceof FormData?body:JSON.stringify(body)});if(!res.ok){const text=await res.text();let body=null;if((res.headers.get('Content-Type')||'').includes('application/json'))try{body=JSON.parse(text);}catch(e){}const err=Error(body?.error||text);if(body?.location)err.location=body.location;throw err;}return res.status===204?null:res.json();}
  function message(text,error=false){let e=$('deploy-editor-message');if(location.hash==='#deployments'&&state.logRoot?.isConnected){e=state.logRoot.querySelector('.deploy-console-msg');if(!e){e=node('p',undefined,'deploy-console-msg');e.setAttribute('role','status');state.logRoot.prepend(e);}}if(e){e.textContent=text;e.style.color=error?'var(--off)':'var(--text-muted)';}
    // And in the corner, where it can't be missed: green for a save or
    // publish, red for an error.
    if(typeof showToast==='function')showToast(text,error?'error':/^Nothing/.test(text)?'info':/saved|updated|published|retired|deleted/i.test(text)?'ok':'info');}
  // One editor action at a time. Without this a double-click on Save sent
  // two "new application" saves 58ms apart and the catalog ended up with two
  // packages of the same name.
  let busy=false;
  async function act(fn){if(busy)return;busy=true;try{state.problem=null;await fn();}catch(e){if(e.location&&state.draft){showProblem(e.location,e.message);}else message(e.message,true);}finally{busy=false;}}
  // A validation error that names a place (platform, operation, section):
  // switch to that platform and operation, redraw, then outline the section,
  // say what is wrong inside it, and bring it into view. The bar at the
  // foot keeps the message and a link back to it.
  function showProblem(loc,text){
    const i=state.draft.variants.findIndex(v=>v.id===loc.variant_id);if(i>=0)state.variant=i;
    if(loc.operation)state.operation=loc.operation;
    state.problem={...loc,text};render();message(text,true);
  }
  function revealProblem(){
    const p=state.problem;const root=$('deploy-editor');if(!p||!root)return;
    const el=root.querySelector(`[data-section="${CSS.escape(p.section)}"]`);if(!el)return;
    el.classList.add('deploy-problem');
    for(let c=el.closest('.deploy-card');c;c=c.parentElement?.closest('.deploy-card')){collapsed.delete(c.dataset.card);c.classList.remove('is-collapsed');c.firstChild.setAttribute('aria-expanded','true');}
    if(el.querySelector(':scope > .deploy-problem-text'))return;
    const say=node('p',p.message||p.text,'deploy-problem-text');say.setAttribute('role','alert');if(el.classList.contains('deploy-card'))el.firstChild.after(say);else el.prepend(say);
    requestAnimationFrame(()=>el.scrollIntoView({behavior:'smooth',block:'center'}));
  }

  function field(obj,key,label,type='text',options){
    const wrap=node('label',undefined,'deploy-field');wrap.append(node('span',label));
    const e=node(type==='textarea'?'textarea':options?'select':'input');
    if(options)for(const value of options){const [id,title]=Array.isArray(value)?value:[value,value];const opt=node('option',title);opt.value=id;e.append(opt);}
    else if(type!=='textarea')e.type=type;
    if(type==='checkbox')e.checked=obj[key]===true||obj[key]==='true';else e.value=obj[key]??'';
    e.oninput=()=>{obj[key]=type==='checkbox'?e.checked:type==='number'?(e.value===''?undefined:Number(e.value)):e.value;};
    e.addEventListener("change",event=>e.oninput?.(event));
    wrap.append(e);return wrap;
  }
  // Which computer groups a package is for: Self Service offers it only to
  // their members, and deployments can only target them. Picked by name;
  // none ticked means every endpoint.
  function groupPicker(meta){
    const box=node('div',undefined,'gp');
    box.append(node('span',isAction()?'Allowed computer groups':'Offered to computer groups','gp-label'));
    if(!state.groupList){box.append(note('Loading groups…'));if(!state.groupListLoading){state.groupListLoading=true;api('/api/groups').then(r=>{state.groupList=(r.groups||[]).filter(g=>g&&g.id).sort((a,b)=>a.name.localeCompare(b.name));}).catch(()=>{state.groupList=[];}).finally(()=>{state.groupListLoading=false;render();});}return box;}
    meta.group_ids??=[];
    const chosen=new Set(meta.group_ids);
    const summary=node('p',undefined,'gp-summary');
    const sum=()=>{const names=state.groupList.filter(g=>chosen.has(g.id)).map(g=>g.name);const gone=[...chosen].filter(id=>!state.groupList.some(g=>g.id===id)).length;
      summary.textContent=chosen.size===0?(isAction()?'Every endpoint: no group is ticked.':'Every endpoint sees it in Self Service: no group is ticked.'):`Only members of: ${names.join(', ')}${gone?` (+${gone} deleted group${gone===1?'':'s'})`:''}`;};
    const q=node('input');q.type='search';q.placeholder='Find a group';q.setAttribute('aria-label','Find a computer group');q.className='gp-search';
    const list=node('div',undefined,'gp-list');
    const draw=()=>{list.replaceChildren();const needle=q.value.trim().toLowerCase();
      // Groups ticked but since deleted stay listed, so they can be removed.
      const rows=[...state.groupList,...[...chosen].filter(id=>!state.groupList.some(g=>g.id===id)).map(id=>({id,name:'Deleted group',deleted:true}))];
      for(const g of rows){if(needle&&!g.name.toLowerCase().includes(needle))continue;
        const lab=node('label',undefined,'gp-item'+(g.deleted?' is-gone':''));const cb=node('input');cb.type='checkbox';cb.checked=chosen.has(g.id);
        cb.onchange=()=>{cb.checked?chosen.add(g.id):chosen.delete(g.id);meta.group_ids=[...chosen];sum();};
        const count=g.deleted?'applies to nobody':`${g.member_count??(g.member_ids||[]).length} computer${(g.member_count??(g.member_ids||[]).length)===1?'':'s'} · ${g.kind||'static'}`;
        lab.append(cb,node('span',g.name,'gp-name'),node('span',count,'gp-meta'));list.append(lab);}
      if(!list.children.length)list.append(note(state.groupList.length?'No group matches.':'No computer groups yet. Create them under Groups.'));};
    q.oninput=draw;
    const clear=button('Clear (every endpoint)',()=>{chosen.clear();meta.group_ids=[];sum();draw();});clear.className='cl-link';
    box.append(summary,row(q,clear),list);sum();draw();
    return box;
  }
  function csv(obj,key,label){const holder={value:(obj[key]||[]).join(', ')};const f=field(holder,'value',label);f.lastChild.oninput=e=>obj[key]=e.target.value.split(',').map(x=>x.trim()).filter(Boolean);return f;}
  function jsonField(obj,key,label,fallback){const holder={value:JSON.stringify(obj[key]??fallback,null,2)};const f=field(holder,'value',label,'textarea');f.lastChild.onchange=e=>{try{obj[key]=JSON.parse(e.target.value);e.target.setCustomValidity('');}catch(err){e.target.setCustomValidity(err.message);e.target.reportValidity();}};return f;}
  function isAction(){return state.draft?.kind==='action';}
  function newRun(os){return {identity:'administrator',success_mode:'exit_code',download_seconds:1800,validation_seconds:0,files:[],steps:[{id:uid(),name:'Run',script:{language:os==='windows'?'powershell':'shell',source:'',timeout_seconds:900}}]};}
  function actionVariant(os){return {id:uid(),os,arch:[],parameters:[],actions:{run:newRun(os)}};}
  function newAction(os){return {require_files:false,files:[],dependencies:[],parameters:[],steps:[{id:uid(),name:'Run installer',script:{language:os==='windows'?'powershell':'shell',source:'',timeout_seconds:900},files:[]}],identity:'administrator',validation:{kind:'app',name:'',field:'',operator:'eq',value:''}};}
  function newVariant(os){return {id:uid(),os,arch:[],version:'',parameters:[],actions:{install:newAction(os)},detection:{kind:'app',name:''}};}
  function create(){state.packageID='new';state.metadata={enabled:true,group_ids:[]};state.name='';state.label='';state.revision=null;state.files=[];state.revisions=[];state.variant=0;state.draft=state.catalogKind==='action'?{version:2,kind:'action',files:[],parameters:[],variants:[]}:{version:1,parameters:[],variants:[]};state.operation=state.catalogKind==='action'?'run':'install';render();}
  async function refresh(){const [data,revs,conf]=await Promise.all([api('/api/software'),api('/api/deploy/packages/all/revisions'),api('/api/confidence').catch(()=>({}))]);state.packages=data.packages||[];state.applicability=data.applicability||{};state.allRevisions=revs.revisions||[];list.confidence=Object.fromEntries((conf.packages||[]).map(c=>[c.package_id,c]));library();}
  async function openPackage(pkg){{const u=new URL(location.href);u.searchParams.set('package',pkg.id);history.replaceState(null,'',u);}state.packageID=pkg.id;state.name=pkg.name;state.metadata=clone(pkg);state.savedMeta=metaKey();const [revs,files]=await Promise.all([api(`/api/deploy/packages/${pkg.id}/revisions`),api(`/api/software/${pkg.id}/files`)]);state.revisions=revs.revisions;state.files=files.files;state.variant=0;
    const latest=state.revisions[0];if(latest){chooseRevision(latest);}else{state.revision=null;state.label=pkg.version||'';state.draft={version:1,parameters:[],variants:Object.entries(pkg.commands||{}).map(([os,ops])=>{const v=newVariant(os);v.version=pkg.version||'';v.detection={kind:'app',name:pkg.detect?.app_name||pkg.name};v.actions={};for(const op of ['install','update','remove'])if(ops[op]){const a=newAction(os);a.steps[0].script.source=ops[op];a.validation=null;v.actions[op]=a;}return v;})};render();message('Converted draft: add validation for each action before publishing. Existing package behavior is unchanged.');}}
  function chooseRevision(rev){state.operation=rev.definition.kind==='action'?'run':'install';state.revision=rev;state.label=rev.label;state.draft=clone(rev.definition);state.variant=0;render();state.savedDraft=draftKey();}
  // Package details (name, description, vendor, category, groups, Self
  // Service…) belong to the package, not a version: they save on their own,
  // and Save or Publish saves them too, so no edit is lost.
  const META_FIELDS=['enabled','vendor','category','description','group_ids','self_service','self_service_follow_latest','self_service_revision','expire_seconds','allow_requests'];
  function metaKey(){const m=state.metadata||{};return JSON.stringify([state.name,...META_FIELDS.map(k=>m[k]??null)]);}
  // Taken after the editor's first render, which fills in defaults, and
  // normalized as a save would be, so opening a version is not an edit.
  function draftKey(){const d=clone(state.draft);if(d)normalizeCodes(d);return JSON.stringify([state.label,d]);}
  const metaDirty=()=>state.packageID!=='new'&&metaKey()!==state.savedMeta;
  const draftDirty=()=>!state.revision||draftKey()!==state.savedDraft;
  async function saveMeta(){
    if(!metaDirty())return false;
    const meta=state.metadata;meta.name=state.name;
    // A pin on a version retired since this page loaded would be refused.
    const pin=state.revisions.find(r=>r.id===meta.self_service_revision);if(pin&&pin.retired)meta.self_service_revision='';
    await api(`/api/deploy/packages/${state.packageID}`,'PUT',meta);state.savedMeta=metaKey();await refresh();return true;
  }
  // Save: details only when only details changed (no new version), else the
  // version as a draft and the details with it.
  async function saveAll(){
    if(!draftDirty()){const changed=await saveMeta();render();message(changed?'Package details saved. The version is unchanged.':'Nothing to save.');return state.revision;}
    const detailsFirst=state.packageID!=='new'&&await saveMeta();
    const rev=await save();
    if(!detailsFirst&&await saveMeta())message('Draft and package details saved.');
    state.savedDraft=draftKey();return rev;
  }
  // --- Catalog lists -------------------------------------------------------
  // Actions and Software open on a full-width list: count, filters, a
  // search box, selectable rows, and the package opens in the editor below
  // a breadcrumb back to the list. The old 260px sidebar of buttons could
  // not show what a package *is* (platforms, command, who needs it) without
  // opening each one.
  const OS_GLYPHS={
    windows:'<path fill="currentColor" d="M3 5.6 10.4 4.6v6.9H3zM11.4 4.4 21 3v8.5h-9.6zM3 12.5h7.4v6.9L3 18.4zM11.4 12.5H21V21l-9.6-1.4z"/>',
    darwin:'<path fill="currentColor" d="M16.5 12.7c0-2.5 2-3.6 2.1-3.7-1.1-1.7-2.9-1.9-3.5-1.9-1.5-.2-2.9.9-3.7.9-.8 0-1.9-.9-3.2-.8-1.6 0-3.2 1-4 2.5-1.7 3-.4 7.4 1.2 9.8.8 1.2 1.8 2.5 3 2.4 1.2 0 1.7-.8 3.1-.8 1.5 0 1.9.8 3.2.8 1.3 0 2.2-1.2 3-2.4.9-1.4 1.3-2.7 1.3-2.8 0 0-2.5-1-2.5-4zM14.1 5.5c.7-.8 1.1-1.9 1-3-1 0-2.1.7-2.8 1.5-.6.7-1.2 1.8-1 2.9 1.1.1 2.1-.6 2.8-1.4z"/>',
    linux:'<path fill="currentColor" fill-rule="evenodd" d="M12 2c-2.2 0-3.6 1.9-3.6 4.4 0 1.4.3 2.3-.6 3.6-1.2 1.8-2.6 3.8-2.6 6.4 0 .9.2 1.6.5 2.2-.9.4-1.7.9-1.7 1.6 0 1 1.6 1.3 3.4 1.6 1 .2 1.7.6 2.4.6.8 0 1.2-.4 1.6-.6h1.2c.4.2.8.6 1.6.6.7 0 1.4-.4 2.4-.6 1.8-.3 3.4-.6 3.4-1.6 0-.7-.8-1.2-1.7-1.6.3-.6.5-1.3.5-2.2 0-2.6-1.4-4.6-2.6-6.4-.9-1.3-.6-2.2-.6-3.6C15.6 3.9 14.2 2 12 2zm-1.3 3.4c.4 0 .7.5.7 1.1s-.3 1.1-.7 1.1-.7-.5-.7-1.1.3-1.1.7-1.1zm2.6 0c.4 0 .7.5.7 1.1s-.3 1.1-.7 1.1-.7-.5-.7-1.1.3-1.1.7-1.1zM12 8.5l1.9 1.1L12 10.9l-1.9-1.3z"/>'};
  const OS_NAMES={windows:'Windows',darwin:'macOS',linux:'Linux'};
  function osIcons(list){const span=node('span',undefined,'cl-os');for(const os of ['windows','darwin','linux'].filter(o=>list.includes(o))){const i=node('span',undefined,'cl-os-ic');i.title=OS_NAMES[os];i.setAttribute('aria-label',OS_NAMES[os]);i.innerHTML=/* safe-html: fixed SVG paths from OS_GLYPHS, keyed by a filtered OS list */ '<svg viewBox="0 0 24 24" aria-hidden="true">'+OS_GLYPHS[os]+'</svg>';span.append(i);}if(!span.childNodes.length)span.append(node('span','—','cl-muted'));return span;}
  const list={sel:new Set(),open:new Set(),q:'',filters:{},sort:{key:'name',dir:1},filtersOpen:null,confidence:{}};
  // List preferences that survive a reload: hiding retired packages and
  // which columns each list shows.
  const pref={get(k,d){try{const v=JSON.parse(localStorage.getItem('mustra-deploy-'+k));return v===null?d:v;}catch(e){return d;}},set(k,v){try{localStorage.setItem('mustra-deploy-'+k,JSON.stringify(v));}catch(e){}}};
  // Disabled with every published version retired: kept for the record of
  // what ran (it cannot be deleted once it has), hidden on request.
  const isShelved=p=>p.enabled===false&&statusOf(p).key==='retired';
  // Created On/By start hidden (Columns turns them on): with them the lists
  // are wider than most screens.
  const hiddenCols=kind=>new Set(pref.get('hidden-cols-'+kind,['created','createdby']));
  // One listener for the page: a click outside the Columns menu closes it.
  document.addEventListener('click',e=>{if(!e.target.closest('.cl-cols'))document.querySelectorAll('.cl-cols-pop').forEach(p=>{p.hidden=true;});});
  // The Maintenance Windows list (software.html) shows the same glyphs.
  window.mustraOsIcon=os=>OS_GLYPHS[os]?osIcons([os]).outerHTML:'';
  const isBuiltin=p=>!!p.detect?.fact;
  function revisionsOf(p){return state.allRevisions.filter(r=>r.package_id===p.id).sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)));}
  function currentRevision(p){const revs=revisionsOf(p);return revs.find(r=>r.id===p.deploy_revision)||revs.find(r=>r.published&&!r.retired)||revs[0]||null;}
  function statusOf(p){
    if(isBuiltin(p))return{key:'builtin',label:'Built-in',hint:'Managed by mustra. Its version targeting follows the agent build the server serves.'};
    const revs=revisionsOf(p);
    if(revs.length&&revs.filter(r=>r.published).length&&revs.filter(r=>r.published).every(r=>r.retired))return{key:'retired',label:'Retired',hint:'Every published version is retired.'};
    if(p.enabled===false)return{key:'disabled',label:'Disabled',hint:'Disabled in catalog settings.'};
    if(revs.some(r=>r.published&&!r.retired))return{key:'published',label:'Published',hint:'A published version is available to deploy.'};
    if(!revs.length)return{key:'unreviewed',label:'Not reviewed',hint:'Deploys with its original commands. Open it to review and publish a versioned release.'};
    return{key:'draft',label:'Draft',hint:'Not published yet.'};
  }
  function platformsOf(p){const rev=currentRevision(p);const fromRev=(rev?.definition?.variants||[]).map(v=>v.os);return [...new Set(fromRev.length?fromRev:Object.keys(p.commands||{}))];}
  // The version a deployment of this action package would use: its pinned
  // revision, else the newest published one that is not retired.
  function actionVersionOf(p){const revs=revisionsOf(p);const r=revs.find(r=>r.id===p.deploy_revision&&r.published)||revs.find(r=>r.published&&!r.retired);return r?.label||'';}
  function newerDraftOf(p){const live=revisionsOf(p).find(r=>r.published&&!r.retired);const d=revisionsOf(p).find(r=>!r.published);return d&&(!live||String(d.created_at)>String(live.created_at))?d:null;}
  function versionOf(p){const rev=currentRevision(p);const v=(rev?.definition?.variants||[]).map(v=>v.version).find(Boolean);return v||p.version||rev?.label||'';}
  function commandOf(p){
    const rev=currentRevision(p);
    for(const v of rev?.definition?.variants||[]){const s=v.actions?.run?.steps?.[0]?.script;if(s?.source)return{text:s.source,timeout:s.timeout_seconds,os:v.os};}
    for(const [os,ops] of Object.entries(p.commands||{})){const t=ops.install||ops.run||ops.update||ops.remove;if(t)return{text:t,timeout:p.command_timeout_seconds,os};}
    return{text:'',timeout:0};
  }
  function humanSeconds(s){if(!s)return'—';if(s%3600===0)return`${s/3600} hour${s===3600?'':'s'}`;if(s%60===0)return`${s/60} minute${s===60?'':'s'}`;return`${s} second${s===1?'':'s'}`;}
  // The package's newest change, whatever it was: its details saved, a
  // version saved or published, or a version retired.
  function lastChangeOf(p){
    const ev=[{at:p.updated_at,by:p.updated_by},{at:p.created_at,by:p.created_by}];
    for(const r of revisionsOf(p)){ev.push({at:r.created_at,by:r.created_by});if(r.retired_at)ev.push({at:r.retired_at,by:r.retired_by});}
    // Newest first; among changes at the same moment, one that says who.
    return ev.filter(e=>e.at).sort((a,b)=>String(b.at).localeCompare(String(a.at))||(!!b.by-!!a.by))[0]||{at:'',by:''};
  }
  function modifiedOf(p){return lastChangeOf(p).at;}
  function modifiedByOf(p){const c=lastChangeOf(p);return c.by||(revisionsOf(p).find(r=>r.created_by)?.created_by)||p.created_by||'';}
  function authorOf(p){return revisionsOf(p)[0]?.created_by||p.created_by||'';}
  function countsOf(p){return state.applicability?.[p.id]||{};}
  function pctOf(n){const total=state.agents.length||0;return total?` (${Math.round(n*100/total)}%)`:'';}

  function columnsFor(kind){
    if(kind==='action')return [
      {key:'name',label:'Display Name',value:p=>p.name,cell:p=>nameLink(p)},
      {key:'version',label:'Version',value:p=>actionVersionOf(p),cell:p=>{const e=node('span',actionVersionOf(p)||'—','cl-nowrap'+(actionVersionOf(p)?'':' cl-muted'));const d=newerDraftOf(p);if(d){e.append(node('span',' · newer draft','cl-muted'));e.title=`Draft ${d.label||d.id} is not published yet`;}return e;}},
      {key:'os',label:'Platforms',value:p=>platformsOf(p).join(','),cell:p=>osIcons(platformsOf(p))},
      {key:'description',label:'Description',value:p=>p.description||'',cell:p=>node('span',p.description||'','cl-desc')},
      {key:'command',label:'Command',value:p=>commandOf(p).text,cell:p=>{const c=commandOf(p);const lines=c.text.split('\n').map(l=>l.trim()).filter(Boolean);const e=node('code',lines.find(l=>!l.startsWith('#'))||lines[0]||'—','cl-cmd');e.title=c.text;return e;}},
      {key:'timeout',label:'Command Timeout',value:p=>commandOf(p).timeout||0,cell:p=>node('span',humanSeconds(commandOf(p).timeout),'cl-nowrap')},
      {key:'status',label:'Status',value:p=>statusOf(p).label,cell:p=>statusPill(p)},
      {key:'modified',label:'Modified On',value:p=>modifiedOf(p),cell:p=>node('span',fmtDate(modifiedOf(p)),'cl-nowrap')},
      {key:'modifiedby',label:'Modified By',value:p=>modifiedByOf(p),cell:p=>node('span',modifiedByOf(p)||'—',modifiedByOf(p)?'':'cl-muted')},
      {key:'created',label:'Created On',value:p=>p.created_at||'',cell:p=>node('span',fmtDate(p.created_at),'cl-nowrap')},
      {key:'createdby',label:'Created By',value:p=>p.created_by||'',cell:p=>node('span',p.created_by||'—',p.created_by?'':'cl-muted')},
    ];
    return [
      {key:'status',label:'Status',value:p=>statusOf(p).label,cell:p=>statusIcon(p),narrow:true},
      {key:'os',label:'OS',value:p=>platformsOf(p).join(','),cell:p=>osIcons(platformsOf(p)),narrow:true},
      {key:'vendor',label:'Vendor',value:p=>p.vendor||'',cell:p=>node('span',p.vendor||'—',p.vendor?'':'cl-muted')},
      {key:'name',label:'Title',value:p=>p.name,cell:p=>nameLink(p)},
      {key:'version',label:'Version',value:p=>versionOf(p),cell:p=>node('span',versionOf(p)||'—','cl-nowrap cl-num')},
      {key:'confidence',label:'Confidence',value:p=>list.confidence[p.id]?.score??-1,cell:p=>confidencePill(p)},
      {key:'selfservice',label:'Self Service',value:p=>p.self_service?'Yes':'No',cell:p=>node('span',p.self_service?'Yes':'No',p.self_service?'':'cl-muted')},
      {key:'eligible',label:'Install Eligible',value:p=>countsOf(p).install_eligible||0,cell:p=>countCell(countsOf(p).install_eligible)},
      {key:'updates',label:'Updates Needed',value:p=>countsOf(p).update_eligible||0,cell:p=>countCell(countsOf(p).update_eligible)},
      {key:'installed',label:'Installed',value:p=>countsOf(p).installed||0,cell:p=>countCell(countsOf(p).installed)},
      {key:'modified',label:'Modified On',value:p=>modifiedOf(p),cell:p=>node('span',fmtDate(modifiedOf(p)),'cl-nowrap')},
      {key:'modifiedby',label:'Modified By',value:p=>modifiedByOf(p),cell:p=>node('span',modifiedByOf(p)||'—',modifiedByOf(p)?'':'cl-muted')},
      {key:'created',label:'Created On',value:p=>p.created_at||'',cell:p=>node('span',fmtDate(p.created_at),'cl-nowrap')},
      {key:'createdby',label:'Created By',value:p=>p.created_by||'',cell:p=>node('span',p.created_by||'—',p.created_by?'':'cl-muted')},
    ];
  }
  function filtersFor(kind){
    const common=[
      {key:'os',label:kind==='action'?'Platform':'OS',options:p=>platformsOf(p).map(o=>[o,OS_NAMES[o]||o])},
      {key:'status',label:'Status',options:p=>[[statusOf(p).key,statusOf(p).label]]},
    ];
    if(kind==='action')return [...common,{key:'author',label:'Created/Modified By',options:p=>authorOf(p)?[[authorOf(p),authorOf(p)]]:[]}];
    return [...common,
      {key:'vendor',label:'Vendor',options:p=>p.vendor?[[p.vendor,p.vendor]]:[]},
      {key:'confidence',label:'Confidence',options:p=>{const b=list.confidence[p.id]?.band||'unknown';return [[b,b[0].toUpperCase()+b.slice(1)]];}},
      {key:'selfservice',label:'Self Service',options:p=>[[p.self_service?'yes':'no',p.self_service?'Offered':'Not offered']]},
      {key:'author',label:'Created/Modified By',options:p=>authorOf(p)?[[authorOf(p),authorOf(p)]]:[]},
    ];
  }
  function nameLink(p){
    // Built-in actions deploy from the applicability drawer (software.html):
    // their version targeting is the server's, so there is nothing to edit.
    if(isBuiltin(p)){const a=node('a',p.name,'cl-name');a.href='#';a.title='Built-in: choose endpoints and deploy';a.onclick=e=>{e.preventDefault();if(typeof window.openPackage==='function')window.openPackage(p.id);};return a;}
    const a=node('a',p.name,'cl-name');a.href=`?package=${encodeURIComponent(p.id)}${location.hash}`;
    a.onclick=e=>{if(e.metaKey||e.ctrlKey||e.shiftKey||e.button)return;e.preventDefault();act(()=>openFromList(p));};return a;
  }
  function statusPill(p){const s=statusOf(p);const e=node('span',s.label,'cl-pill cl-st-'+s.key);e.title=s.hint;return e;}
  function statusIcon(p){
    const s=statusOf(p);const e=node('span',undefined,'cl-st-ic cl-st-'+s.key);e.title=s.label+' — '+s.hint;e.setAttribute('aria-label',s.label);
    e.innerHTML=s.key==='published'?'<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="9" fill="currentColor"/><path d="m6 10.2 2.6 2.6L14.2 7" fill="none" stroke="var(--surface)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      :s.key==='draft'||s.key==='unreviewed'?'<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="3 2.6"/></svg>'
      :s.key==='builtin'?'<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="9" fill="currentColor"/><path d="M10 5.5v9M5.5 10h9" stroke="var(--surface)" stroke-width="2.2" stroke-linecap="round"/></svg>'
      :'<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/><path d="m5 15 10-10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
    return e;
  }
  function confidencePill(p){
    const c=list.confidence[p.id];const band=c?.band||'unknown';
    const e=node('span',undefined,'cl-conf cl-conf-'+band);
    const bars=band==='high'?3:band==='moderate'?2:band==='low'?1:0;
    e.innerHTML='<svg viewBox="0 0 14 12" aria-hidden="true">'+[0,1,2].map(i=>`<rect x="${i*5}" y="${8-i*4}" width="3.4" height="${4+i*4}" rx="1" fill="currentColor" opacity="${i<bars?1:.28}"/>`).join('')+'</svg>';
    e.append(document.createTextNode(band==='unknown'?'Not rated':band[0].toUpperCase()+band.slice(1)));
    e.title=c?(c.reason||'')+(c.score!==undefined?` · score ${c.score}`:''):'No deployment history yet';
    return e;
  }
  function countCell(n){if(!n)return node('span','','cl-muted');const e=node('span',`${n}${pctOf(n)}`,'cl-count');return e;}

  function matchesRow(p,kind){
    if(pref.get('hide-retired',false)&&isShelved(p))return false;
    if(list.q){const hay=[p.name,p.vendor,p.description,commandOf(p).text,versionOf(p),authorOf(p)].join(' ').toLowerCase();if(!hay.includes(list.q))return false;}
    for(const f of filtersFor(kind)){const want=list.filters[kind+':'+f.key];if(want&&!f.options(p).some(([v])=>v===want))return false;}
    if(kind==='software'&&list.filters['software:needed']&&!((countsOf(p).install_eligible||0)+(countsOf(p).update_eligible||0)))return false;
    return true;
  }
  function rowsFor(kind){
    const cols=columnsFor(kind);const col=cols.find(c=>c.key===list.sort.key)||cols.find(c=>c.key==='name');
    const all=state.packages.filter(p=>(p.kind==='action')===(kind==='action'));
    const shown=all.filter(p=>matchesRow(p,kind));
    shown.sort((a,b)=>{const x=col.value(a),y=col.value(b);const r=typeof x==='number'&&typeof y==='number'?x-y:String(x).localeCompare(String(y),undefined,{numeric:true,sensitivity:'base'});return r*list.sort.dir||a.name.localeCompare(b.name);});
    return{all,shown,cols};
  }

  function library(){
    const root=$('deploy-library');if(!root)return;
    const kind=state.catalogKind;const {all,shown,cols:baseCols}=rowsFor(kind);
    // Saved column order first, any column it doesn't know after, in place.
    const order=pref.get('col-order-'+kind,[]);const rank=c=>{const i=order.indexOf(c.key);return i<0?order.length+baseCols.indexOf(c):i;};
    const allCols=[...baseCols].sort((a,b)=>rank(a)-rank(b));
    const hidden=hiddenCols(kind);const cols=allCols.filter(c=>c.key==='name'||!hidden.has(c.key));
    for(const id of [...list.sel])if(!all.some(p=>p.id===id))list.sel.delete(id);
    if(list.filtersOpen===null)list.filtersOpen=kind==='software';
    root.replaceChildren();
    // Page head: title on the left, the page's primary actions on the right.
    const head=node('div',undefined,'cl-head');
    head.append(node('h1',kind==='action'?'Action Packages':'Software Packages'));
    const headActions=node('div',undefined,'cl-head-actions');
    if(kind==='software'){const lib=button('Add from library',()=>openLibrary());lib.className='cl-btn';headActions.append(lib);}
    headActions.append(button(kind==='action'?'New Action Package':'Create Software Package',()=>{create();},true));
    head.append(headActions);root.append(head);
    if(kind==='software'){
      const tabs=node('nav',undefined,'cl-tabs');tabs.setAttribute('aria-label','Software views');
      for(const [hash,label] of [['#catalog','Software Packages'],['#discover','Installed Software'],['#confidence','Package Confidence']]){const a=node('a',label);a.href=hash;if(location.hash===hash)a.setAttribute('aria-current','page');tabs.append(a);}
      root.append(tabs);
    }
    const panel=node('section',undefined,'cl-panel');root.append(panel);
    // Toolbar: count, then export and the free-text filter.
    const bar=node('div',undefined,'cl-bar');
    const count=node('div',undefined,'cl-count-line');count.innerHTML=`<strong>${escapeHtml(shown.length.toLocaleString())}</strong> of <strong>${escapeHtml(all.length.toLocaleString())}</strong> Items`;
    const tools=node('div',undefined,'cl-tools');
    const exp=button('Export CSV',()=>exportCSV(kind,list.sel.size?shown.filter(p=>list.sel.has(p.id)):shown));exp.className='cl-btn';exp.title=list.sel.size?'Export the selected rows':'Export the rows shown';
    const search=node('label',undefined,'cl-search');search.innerHTML=icon('search');const input=node('input');input.type='search';input.placeholder='Filter items';input.setAttribute('aria-label','Filter items');input.value=list.q;
    input.oninput=()=>{list.q=input.value.trim().toLowerCase();const pos=input.selectionStart;library();const again=$('deploy-library').querySelector('.cl-search input');again.focus();again.setSelectionRange(pos,pos);};
    search.append(input);
    const retired=all.filter(isShelved).length;
    const hr0=node('label',undefined,'cl-filter-check');hr0.title='Hide disabled packages whose versions are all retired. They stay for the record of what ran.';
    const hcb=node('input');hcb.type='checkbox';hcb.checked=pref.get('hide-retired',false);hcb.onchange=()=>{pref.set('hide-retired',hcb.checked);library();};
    hr0.append(hcb,document.createTextNode(` Hide retired${retired?` (${retired})`:''}`));
    const colWrap=node('div',undefined,'cl-cols');const colBtn=button('Columns',()=>{pop.hidden=!pop.hidden;colBtn.setAttribute('aria-expanded',String(!pop.hidden));});colBtn.className='cl-btn';colBtn.setAttribute('aria-haspopup','true');colBtn.setAttribute('aria-expanded','false');
    const pop=node('div',undefined,'cl-cols-pop');pop.hidden=true;pop.onclick=e=>e.stopPropagation();
    for(const c of allCols){const lab=node('label');const cb=node('input');cb.type='checkbox';cb.checked=c.key==='name'||!hidden.has(c.key);cb.disabled=c.key==='name';
      cb.onchange=()=>{const h=hiddenCols(kind);cb.checked?h.delete(c.key):h.add(c.key);pref.set('hidden-cols-'+kind,[...h]);library();const again=$('deploy-library').querySelector('.cl-cols-pop');if(again){again.hidden=false;}};
      lab.append(cb,document.createTextNode(' '+c.label));pop.append(lab);}
    pop.append(node('p','Drag a column header to move it; drag its right edge to resize, double-click the edge to fit.','cl-muted'));
    const resetW=button('Reset columns',()=>{pref.set('hidden-cols-'+kind,['created','createdby']);pref.set('col-order-'+kind,[]);const t=$('deploy-library').querySelector('table.cl-table');if(t&&t._colResize)t._colResize.reset();library();});resetW.className='cl-link';pop.append(resetW);
    colWrap.append(colBtn,pop);
    tools.append(hr0,colWrap,exp,search);bar.append(count,tools);panel.append(bar);
    // Filters: a disclosure, with each control a select over the values
    // actually present (no empty choices to pick and get nothing back).
    const fwrap=node('div',undefined,'cl-filters');
    const toggle=node('button',undefined,'cl-filter-toggle');toggle.type='button';toggle.setAttribute('aria-expanded',list.filtersOpen);
    const active=Object.entries(list.filters).filter(([k,v])=>k.startsWith(kind+':')&&v).length;
    toggle.innerHTML=`<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M3 2l4 3-4 3z" fill="currentColor"/></svg> Filters${active?` <span class="cl-filter-n">${escapeHtml(String(active))}</span>`:''}`;
    toggle.onclick=()=>{list.filtersOpen=!list.filtersOpen;library();};fwrap.append(toggle);
    if(list.filtersOpen){
      const grid=node('div',undefined,'cl-filter-grid');
      for(const f of filtersFor(kind)){
        const opts=new Map();for(const p of all)for(const [v,l] of f.options(p))opts.set(v,l);
        const lab=node('label',undefined,'cl-filter');lab.append(node('span',f.label));
        const sel=node('select');sel.append(new Option('Select…',''));for(const [v,l] of [...opts].sort((a,b)=>String(a[1]).localeCompare(String(b[1]))))sel.append(new Option(l,v));
        sel.value=list.filters[kind+':'+f.key]||'';sel.onchange=()=>{list.filters[kind+':'+f.key]=sel.value;library();};lab.append(sel);grid.append(lab);
      }
      if(kind==='software'){const lab=node('label',undefined,'cl-filter-check');const cb=node('input');cb.type='checkbox';cb.checked=!!list.filters['software:needed'];cb.onchange=()=>{list.filters['software:needed']=cb.checked;library();};lab.append(cb,document.createTextNode(' Only packages endpoints need'));grid.append(lab);}
      if(active||list.filters['software:needed']){const clear=button('Clear filters',()=>{for(const k of Object.keys(list.filters))if(k.startsWith(kind+':'))delete list.filters[k];library();});clear.className='cl-link';grid.append(clear);}
      fwrap.append(grid);
    }
    panel.append(fwrap);
    // Bulk bar appears only with a selection, so it never sits there disabled.
    if(list.sel.size){
      const bulk=node('div',undefined,'cl-bulk');bulk.append(node('span',`${list.sel.size} selected`,'cl-bulk-n'));
      const chosen=state.packages.filter(p=>list.sel.has(p.id));const ready=chosen.filter(canDeploy);
      const dep=button(`Deploy${ready.length<chosen.length?` ${ready.length}`:''}`,()=>act(()=>openDeployWindow(ready)));dep.className='cl-btn cl-primary';dep.disabled=!ready.length;if(ready.length<chosen.length)dep.title=`${chosen.length-ready.length} selected package(s) have no published version`;
      const del=button('Delete',()=>act(()=>deleteSelected(kind)));del.className='cl-btn cl-danger';
      const clr=button('Clear selection',()=>{list.sel.clear();library();});clr.className='cl-link';
      bulk.append(dep,del,clr);panel.append(bulk);
    }
    // The table.
    const wrap=node('div',undefined,'cl-table-wrap');const table=node('table',undefined,'cl-table cl-'+kind);
    const thead=node('thead');const hr=node('tr');
    const selectable=shown.filter(p=>!isBuiltin(p));
    const allTh=node('th',undefined,'cl-chk');allTh.dataset.noResize='';const allCb=node('input');allCb.type='checkbox';allCb.setAttribute('aria-label','Select all rows shown');
    const on=selectable.filter(p=>list.sel.has(p.id)).length;allCb.checked=on>0&&on===selectable.length;allCb.indeterminate=on>0&&on<selectable.length;allCb.disabled=!selectable.length;
    allCb.onchange=()=>{for(const p of selectable)allCb.checked?list.sel.add(p.id):list.sel.delete(p.id);library();};allTh.append(allCb);hr.append(allTh);
    if(kind==='software'){const et=node('th',undefined,'cl-exp');et.dataset.noResize='';hr.append(et);}
    for(const c of cols){
      const th=node('th',undefined,c.narrow?'cl-narrow':'');th.dataset.colKey=c.key;
      // Modified On is a fixed width, like the Action column; Description
      // (actions) or the title (software) takes any leftover width.
      if(c.key==='modified'||c.key==='created')th.dataset.noResize='';
      if(c.key===(kind==='action'?'description':'name'))th.dataset.flex='';const b=node('button',c.label,'cl-sort');b.type='button';
      if(list.sort.key===c.key){th.setAttribute('aria-sort',list.sort.dir>0?'ascending':'descending');b.dataset.dir=list.sort.dir>0?'asc':'desc';}
      b.onclick=()=>{list.sort=list.sort.key===c.key?{key:c.key,dir:-list.sort.dir}:{key:c.key,dir:1};library();};th.append(b);hr.append(th);
    }
    {const at=node('th','Action','cl-actions');at.dataset.noResize='';hr.append(at);}
    thead.append(hr);table.append(thead);
    const tbody=node('tbody');
    if(!shown.length){const tr=node('tr');const td=node('td',all.length?'No packages match these filters.':(kind==='action'?'No action packages yet. Create one to run a command across endpoints.':'No software packages yet. Create one to publish an application.'),'cl-empty');td.colSpan=cols.length+(kind==='software'?3:2);tr.append(td);tbody.append(tr);}
    for(const p of shown){
      const tr=node('tr');if(list.sel.has(p.id))tr.className='is-selected';
      const ctd=node('td',undefined,'cl-chk');const cb=node('input');cb.type='checkbox';cb.checked=list.sel.has(p.id);cb.setAttribute('aria-label','Select '+p.name);
      if(isBuiltin(p)){cb.disabled=true;cb.title='Built-in packages cannot be deleted';}
      cb.onchange=()=>{cb.checked?list.sel.add(p.id):list.sel.delete(p.id);library();};ctd.append(cb);tr.append(ctd);
      if(kind==='software'){
        const etd=node('td',undefined,'cl-exp');const revs=revisionsOf(p);
        if(revs.length){const eb=node('button',undefined,'cl-expander');eb.type='button';eb.setAttribute('aria-expanded',list.open.has(p.id));eb.setAttribute('aria-label',(list.open.has(p.id)?'Hide':'Show')+' versions of '+p.name);eb.innerHTML='<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M3 2l4 3-4 3z" fill="currentColor"/></svg>';eb.onclick=()=>{list.open.has(p.id)?list.open.delete(p.id):list.open.add(p.id);library();};etd.append(eb);}
        tr.append(etd);
      }
      for(const c of cols){const td=node('td',undefined,c.narrow?'cl-narrow':'');td.append(c.cell(p));tr.append(td);}
      const atd=node('td',undefined,'cl-actions');if(canDeploy(p)){const b=button('Deploy',()=>act(()=>openDeployWindow([p])));b.className='cl-btn';b.setAttribute('aria-label','Deploy '+p.name);atd.append(b);}else atd.append(Object.assign(node('span','Not published','cl-muted'),{title:'Publish a version before deploying'}));tr.append(atd);
      tbody.append(tr);
      if(kind==='software'&&list.open.has(p.id))tbody.append(versionsRow(p,cols.length+3));
    }
    table.append(tbody);wrap.append(table);panel.append(wrap);
    if(typeof makeColumnsResizable==='function')makeColumnsResizable(table,'deploy-'+kind);
    if(typeof makeHeadersReorderable==='function')makeHeadersReorderable(table,th=>th.dataset.colKey||null,(from,to,after)=>{
      const keys=allCols.map(c=>c.key).filter(k=>k!==from);let at=keys.indexOf(to);if(after)at++;keys.splice(at,0,from);
      pref.set('col-order-'+kind,keys);library();});
  }
  function versionsRow(p,span){
    const tr=node('tr',undefined,'cl-versions');const td=node('td');td.colSpan=span;
    const t=node('table',undefined,'cl-subtable');t.innerHTML='<thead><tr><th>Version</th><th>Status</th><th>Platforms</th><th>Created by</th><th>Created</th><th></th></tr></thead>';
    const b=node('tbody');
    for(const r of revisionsOf(p)){
      const row=node('tr');const st=r.retired?'Retired':r.published?'Published':'Draft';
      const plats=[...new Set((r.definition?.variants||[]).map(v=>v.os))];
      const open=button('Open',()=>act(async()=>{await openFromList(p);const rev=state.revisions.find(x=>x.id===r.id);if(rev)chooseRevision(rev);}));open.className='cl-btn';
      const stCell=node('span');const pill=node('span',st,'cl-pill cl-st-'+st.toLowerCase());stCell.append(pill);
      if(r.retired&&r.retired_note){stCell.append(node('span',' '+r.retired_note,'cl-muted'));pill.title=`${r.retired_note}${r.retired_by?' · '+r.retired_by:''}${r.retired_at?' · '+fmtDate(r.retired_at):''}`;}
      for(const cell of [node('span',r.label||r.id,'cl-num'),stCell,osIcons(plats),node('span',r.created_by||'—'),node('span',fmtDate(r.created_at),'cl-nowrap'),open]){const c=node('td');c.append(cell);row.append(c);}
      b.append(row);
    }
    t.append(b);td.append(t);tr.append(td);return tr;
  }
  async function openFromList(p){
    // An action that predates reviewed versions is converted on first
    // open: the editor only edits reviewed definitions.
    if(p.kind==='action'&&!revisionsOf(p).length&&!isBuiltin(p)){
      if(!confirm(`“${p.name}” has no reviewed version yet. Convert it now? A reviewed draft is created; nothing runs until you publish it.`))return;
      const result=await api(`/api/deploy/packages/${p.id}/convert-action`,'POST',{});await refresh();
      const first=result.revisions[0];if(first){const np=state.packages.find(x=>x.id===first.package_id);if(np){await openPackage(np);message(result.message);}}return;
    }
    await openPackage(p);
  }
  async function deleteSelected(kind){
    const targets=state.packages.filter(p=>list.sel.has(p.id)&&!isBuiltin(p));if(!targets.length)return;
    if(!confirm(`Delete ${targets.length} package${targets.length===1?'':'s'}?\n\n${targets.map(p=>'• '+p.name).join('\n')}\n\nPackages with published versions are kept: retire those instead, so the record of what endpoints were sent stays intact.`))return;
    const failed=[];
    for(const p of targets){try{await api(`/api/software/${p.id}`,'DELETE');list.sel.delete(p.id);}catch(e){failed.push(`${p.name}: ${e.message.trim()}`);}}
    await refresh();
    if(failed.length)alert(`Not deleted:\n\n${failed.join('\n')}`);
  }
  function exportCSV(kind,rows){
    // csvRow (app.js) quotes and neutralises cells that a spreadsheet would
    // read as a formula: package names and commands are operator-written.
    const cols=columnsFor(kind);
    const lines=[csvRow(cols.map(c=>c.label))];
    for(const p of rows)lines.push(csvRow(cols.map(c=>c.key==='confidence'?(list.confidence[p.id]?.band||''):c.key==='os'?platformsOf(p).map(o=>OS_NAMES[o]||o).join(' '):String(c.value(p)??''))));
    const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/csv'}));a.download=`${kind==='action'?'action-packages':'software-packages'}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
  }
  // Switching between the list and the editor. The editor keeps its own
  // markup; the list is simply hidden while a package is open.
  function showEditor(on){
    const lib=$('deploy-library'),ed=$('deploy-editor');if(!lib||!ed)return;
    lib.hidden=on;ed.hidden=!on;
    if(!on){state.draft=null;state.revision=null;library();}
  }
  // The version number: digits and dots only (1.0.2), as the server requires.
  function versionField(){
    const f=field(state,'label','Version number');const inp=f.lastChild;
    inp.placeholder='1.0.0';inp.inputMode='decimal';inp.pattern='[0-9]+(\\.[0-9]+)*';inp.title='Digits and dots only, such as 1.0.2';
    inp.addEventListener('input',()=>{const clean=inp.value.replace(/[^0-9.]/g,'');if(clean!==inp.value){inp.value=clean;state.label=clean;}});
    return f;
  }
  function crumb(){
    const nav=node('nav',undefined,'cl-crumb');nav.setAttribute('aria-label','Breadcrumb');
    const back=node('a',state.catalogKind==='action'?'Action Packages':'Software Packages');back.href=location.hash||'#catalog';
    back.onclick=e=>{e.preventDefault();const u=new URL(location.href);u.searchParams.delete('package');history.replaceState(null,'',u);showEditor(false);};
    nav.append(back,node('span','›','cl-crumb-sep'),node('span',state.name||(isAction()?'New action package':'New application'),'cl-crumb-here'));
    return nav;
  }
  function parameters(owner,title){owner.parameters??=[];const root=card(title,note('Scripts read inputs from MUSTRA_PARAM_name environment variables. Values are passed as data.'));
    owner.parameters.forEach((p,i)=>{root.append(row(field(p,'name','Name'),field(p,'label','Label'),field(p,'type','Type','text',['text','numeric','select','checkbox']),field(p,'default','Default'),field(p,'required','Required','checkbox'),field(p,'secret','Secret','checkbox'),button('Remove',()=>{owner.parameters.splice(i,1);render();})));const more=node('details');more.append(node('summary','Constraints'),row(field(p,'min','Minimum','number'),field(p,'max','Maximum','number'),csv(p,'options','Choices')));root.append(more);});root.append(button('Add parameter',()=>{owner.parameters.push({name:'parameter'+(owner.parameters.length+1),type:'text'});render();}));return root;
  }
  const checkKinds=[['app','Installed application'],['sensor','Existing sensor'],['file_exists','File exists'],['directory_exists','Directory exists'],['file_hash','File SHA-256'],['file_version','File version'],['registry','Windows registry'],['service','Service'],['process','Process'],['os','Operating system'],['arch','Architecture'],['ram','RAM (MB)'],['disk_free','Free disk (GB)'],['script','Custom script'],['and','All conditions (AND)'],['or','Any condition (OR)'],['not','NOT']];
  const ops=[['eq','Equals'],['ne','Does not equal'],['contains','Contains'],['matches','Regular expression'],['version','Version constraint'],['gt','Greater than'],['gte','At least'],['lt','Less than'],['lte','At most']];
  function checkEditor(owner,key,title,os,depth=0){const box=node('div',undefined,'deploy-condition');box.append(node('strong',title));if(!owner[key]){box.append(button('Add check',()=>{owner[key]=isAction()?{kind:'sensor',sensor_id:''}:{kind:'app',name:''};render();}));return box;}
    const c=owner[key];const kind=field(c,'kind','Check type','text',isAction()?checkKinds.filter(([k])=>['sensor','and','or','not'].includes(k)):checkKinds);kind.lastChild.onchange=()=>{owner[key]={kind:kind.lastChild.value};if(['and','or','not'].includes(owner[key].kind))owner[key].children=[isAction()?{kind:'sensor',sensor_id:''}:{kind:'file_exists',path:''}];render();};box.append(row(kind,button('Remove check',()=>{if(Array.isArray(owner))owner.splice(key,1);else owner[key]=null;render();})));
    if(['and','or','not'].includes(c.kind)){c.children??=[];c.children.forEach((child,i)=>{box.append(checkEditor(c.children,i,`Condition ${i+1}`,os,depth+1));});if(c.kind!=='not'&&depth<7)box.append(button('Add condition',()=>{c.children.push(isAction()?{kind:'sensor',sensor_id:''}:{kind:'file_exists',path:''});render();}));return box;}
    if(['file_exists','directory_exists','file_hash','file_version','registry','disk_free'].includes(c.kind))box.append(field(c,'path','Path'));
    if(['app','service','process','registry'].includes(c.kind))box.append(field(c,'name',c.kind==='registry'?'Value name':'Name'));
    if(['app','service','process'].includes(c.kind))box.append(field(c,'field','Additional field (optional)','text',[['','Existence only'],['version','Version'],['status','Status'],['start_type','Start type'],['username','Username']]));
    if(c.kind==='sensor'){
      const selector=field(c,'sensor_id','Sensor','text',[['','Select sensor'],...state.sensors.filter(s=>s.id!=='action_logs').map(s=>[s.id,s.name])]);selector.lastChild.onchange=()=>{c.sensor_id=selector.lastChild.value;delete c.sensor;render();};box.append(selector);
      const sensor=state.sensors.find(s=>s.id===c.sensor_id);if(sensor)box.append(note('Fields: '+(sensor.fields||[]).map(f=>f.name||f).join(', ')));
      c.rows??=[];c.rows.forEach((p,i)=>box.append(row(field(p,'field','Field'),field(p,'operator','Comparison','text',ops),field(p,'value','Value'),field(p,'parameter','Or package parameter'),button('Remove',()=>{c.rows.splice(i,1);render();}))));
      box.append(button('Add row filter',()=>{c.rows.push({field:'name',operator:'eq',value:''});render();}));box.append(row(field(c,'quantifier','Result','text',[['any','Any matching row'],['none','No matching rows'],['all','All rows match'],['count','Matching row count']]),field(c,'allow_empty','Allow empty ALL result','checkbox'),field(c,'lookback_seconds','Historical lookback (seconds)','number')));
      box.append(jsonField(c,'inputs','Sensor input bindings — { "input": { "parameter": "package_input" } }',{}));
    }
    if(c.kind==='script'){c.script??={language:os==='windows'?'powershell':'shell',source:'',timeout_seconds:30};box.append(scriptEditor(c.script,os));box.append(note('Exit 0 = true; exit 1 = false. Other failures are errors and never select an else branch.'));}
    if(!['file_exists','directory_exists','script'].includes(c.kind))box.append(row(field(c,'operator','Comparison','text',ops),field(c,'value','Expected value / version constraint'),field(c,'parameter','Or package parameter')));
    return box;
  }
  function scriptEditor(script,os){return nodeAppend('div',row(field(script,'language','Language','text',os==='windows'?['powershell','batch','python','go']:['shell','python','go']),field(script,'timeout_seconds',isAction()?'Execution timeout (seconds; 0 = 900)':'Timeout (seconds)','number')),field(script,'source','Script','textarea'));}
  function nodeAppend(tag,...children){const e=node(tag);e.append(...children);return e;}
  function stepsEditor(steps,action,os,depth=0){const root=node('div');steps.forEach((step,i)=>{const box=node('div',undefined,'deploy-step');box.append(row(field(step,'name',`Step ${i+1}`),button('Move up',()=>{if(i){[steps[i-1],steps[i]]=[steps[i],steps[i-1]];render();}}),button('Remove',()=>{steps.splice(i,1);render();})));
      if(step.if){box.append(checkEditor(step,'if','If',os),node('strong','Then'),stepsEditor(step.then??=[],action,os,depth+1),node('strong','Else'),stepsEditor(step.else??=[],action,os,depth+1));}
      else{step.script??={language:os==='windows'?'powershell':'shell',source:'',timeout_seconds:900};box.append(scriptEditor(step.script,os));const files=node('div');files.append(node('strong','Files needed by this step'));step.files??=[];for(const f of action.files||[]){const label=node('label');const input=node('input');input.type='checkbox';input.checked=step.files.includes(f.id);input.onchange=()=>{step.files=input.checked?[...step.files,f.id]:step.files.filter(id=>id!==f.id);};label.append(input,document.createTextNode(f.name+' '));files.append(label);}box.append(files);
        const more=node('details');more.append(node('summary','Outcome, retry, and installer logs'),row(field(step,'continue_on_error','Continue on error','checkbox'),field(step,'retry_safe','Safe to retry','checkbox'),field(step,'retries','Retries (0–5)','number')),csv(step,'success_codes','Success exit codes (default 0)'),csv(step,'reboot_codes','Reboot-required exit codes'),csv(step,'log_paths','Installer log paths'));box.append(more);}
      root.append(box);
    });root.append(row(button('Add command',()=>{steps.push({id:uid(),name:'Command',script:{language:os==='windows'?'powershell':'shell',source:'',timeout_seconds:900},files:[]});render();}),button('Add if / else',()=>{if(depth>=8)return;steps.push({id:uid(),name:'Condition',if:{kind:'file_exists',path:''},then:[],else:[]});render();})));return root;
  }
  async function save(){if(!state.draft)throw Error('Create or select an application');normalizeCodes(state.draft);const editing=state.revision&&!state.revision.published?state.revision.id:'';const rev=await api(`/api/deploy/packages/${state.packageID}/revisions`,'POST',{name:state.name,label:state.label,revision_id:editing,definition:state.draft});state.packageID=rev.package_id;state.revision=rev;const at=state.revisions.findIndex(r=>r.id===rev.id);if(at>=0)state.revisions[at]=rev;else state.revisions.unshift(rev);await refresh();render();message(at>=0?'Draft updated. Published revisions remain unchanged.':'Draft saved. Published revisions remain unchanged.');return rev;}
  function normalizeCodes(d){for(const v of d.variants)for(const a of Object.values(v.actions)){const walk=ss=>ss.forEach(s=>{for(const key of ['success_codes','reboot_codes'])if(s[key])s[key]=s[key].map(Number);walk(s.then||[]);walk(s.else||[]);});walk(a.steps);}}
  function filesEditor(a,v){a.files??=[];const root=isAction()?card(v.os?'Platform files':'Shared files',note(v.os?'Only endpoints matching this variant and each file’s architecture receive these files.':'Every selected platform receives these explicitly shared files.')):card('Package files',field(a,'require_files','Require software files for this action','checkbox'),note('Only files selected by an executed step are downloaded. Sensor and script runtime artifacts are managed separately.'));
    a.files.forEach((f,i)=>root.append(row(node('span',f.name),csv(f,'os','OS scope (blank = shared or current variant)'),csv(f,'arch','Architectures (blank = all)'),button('Remove',()=>{a.files.splice(i,1);render();}))));
    const choice={id:''};root.append(row(field(choice,'id','Add from uploaded library','text',[['','Select file'],...state.files.map(f=>[f.id,f.name])]),button('Add file',()=>{const f=state.files.find(f=>f.id===choice.id);if(f&&!a.files.some(x=>x.id===f.id)){a.files.push({id:f.id,name:f.name,sha256:f.sha256,size:f.size_bytes,os:v.os?[v.os]:[],arch:[]});a.require_files=true;render();}})));
    const upload=node('input');upload.type='file';upload.setAttribute('aria-label','Upload package file');root.append(row(upload,button('Upload',()=>act(async()=>{if(!upload.files[0])throw Error('Choose a file');if(state.packageID==='new')await save();const data=new FormData();data.append('file',upload.files[0]);const f=await api(`/api/software/${state.packageID}/files`,'POST',data);state.files.push(f);a.files.push({id:f.id,name:f.name,sha256:f.sha256,size:f.size_bytes,os:v.os?[v.os]:[]});a.require_files=true;render();}))));
    const source={url:'',name:'',sha256:'',credential_id:'',mode:'import'};root.append(row(field(source,'mode','URL delivery','text',[['import','Import into server library'],['direct','Endpoint downloads directly']]),field(source,'url','HTTPS URL')),row(field(source,'name','Filename'),field(source,'sha256','SHA-256 (required for direct)'),field(source,'credential_id','Vault credential ID (import)')),button('Add URL',()=>act(async()=>{if(source.mode==='direct'){if(!source.sha256||!source.name)throw Error('Direct files need a name and SHA-256');a.files.push({id:uid(),name:source.name,sha256:source.sha256,url:source.url,os:v.os?[v.os]:[]});}else{if(state.packageID==='new')await save();const f=await api(`/api/deploy/packages/${state.packageID}/import`,'POST',source);state.files.push(f);a.files.push({id:f.id,name:f.name,sha256:f.sha256,size:f.size_bytes,os:v.os?[v.os]:[]});}a.require_files=true;render();})));
    return root;
  }
  function dependencies(a){a.dependencies??=[];const root=card('Dependencies',note('Missing dependencies are installed and validated first. Removing this application keeps shared dependencies.'));
    a.dependencies.forEach((d,i)=>{root.append(row(field(d,'package_id','Package','text',[['','Select package'],...state.packages.filter(p=>p.id!==state.packageID).map(p=>[p.id,p.name])]),field(d,'revision_id','Published revision','text',[['','Select revision'],...state.allRevisions.filter(r=>r.published&&r.package_id===d.package_id).map(r=>[r.id,r.label||r.id])]),field(d,'version','Acceptable version (e.g. >=8, <9)'),button('Remove',()=>{a.dependencies.splice(i,1);render();})),jsonField(d,'parameters','Dependency input bindings',{}));});root.querySelectorAll('select').forEach(select=>{if(select.closest('label')?.firstChild?.textContent==='Package')select.addEventListener('change',()=>render());});root.append(button('Add dependency',()=>{a.dependencies.push({package_id:'',revision_id:'',version:'',parameters:{}});render();}));return root;
  }
  // The editor: details beside catalog settings, then one Platforms section
  // whose tab strip picks the platform being edited (one package, a command
  // per OS; each endpoint gets its own platform's), with that platform's
  // configuration and checks on the left and its operations on the right.
  // Save, Publish and the latest message sit in a bar pinned to the foot.
  function opLabel(op){return op==='remove'?'Uninstall':op==='run'?'Run':op[0].toUpperCase()+op.slice(1);}
  function osName(os){return OS_NAMES[os]||os;}
  // The platforms a package covers are chosen, not implied: a new package
  // starts with none, and each OS is a toggle. Turning one on adds its
  // variant; turning it off drops every variant of that OS. The tab strip
  // below appears only when there is more than one variant to switch
  // between (two OSes, or two Linux variants for different distributions).
  // The OS glyph beside a visible OS name: hidden from assistive tech so the
  // name is not read twice.
  function quietIcon(os){const ic=osIcons([os]);ic.setAttribute('aria-hidden','true');ic.querySelectorAll('[aria-label]').forEach(e=>{e.removeAttribute('aria-label');e.removeAttribute('title');});return ic;}
  function variantHasWork(v){return !!v.version||/"source":"[^"]/.test(JSON.stringify(v.actions||{}));}
  function platformTabs(d,addVariant,label){
    const bar=node('div',undefined,'deploy-platform-bar');
    const pick=node('div',undefined,'deploy-platform-pick');pick.setAttribute('role','group');pick.setAttribute('aria-label','Platforms this package runs on');
    for(const os of ['windows','darwin','linux']){
      const mine=d.variants.filter(v=>v.os===os),on=mine.length>0;
      const b=node('button',undefined,'deploy-platform-toggle');b.type='button';b.dataset.osToggle=os;b.setAttribute('aria-pressed',String(on));
      const ic=quietIcon(os);
      const check=node('span',undefined,'deploy-platform-check');check.setAttribute('aria-hidden','true');
      b.append(check,ic,node('span',osName(os)));
      b.title=on?`Remove ${osName(os)} from this package`:`Add ${osName(os)} to this package`;
      b.onclick=()=>{
        if(!on){addVariant(os);state.variant=d.variants.length-1;}
        else{
          if(mine.some(variantHasWork)&&!confirm(`Remove ${osName(os)} from this package?\n\nIts ${mine.length>1?mine.length+' variants':'commands'} will be discarded when you save.`))return;
          const current=d.variants[state.variant];d.variants=d.variants.filter(v=>v.os!==os);
          state.variant=Math.max(0,d.variants.indexOf(current));
        }
        render();$('deploy-editor')?.querySelector(`[data-os-toggle="${os}"]`)?.focus();
      };
      pick.append(b);
    }
    bar.append(pick);
    if(d.variants.length>1){
      const tabs=node('div',undefined,'deploy-platforms');tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label','Variant being edited');
      d.variants.forEach((v,i)=>{const b=node('button',undefined,'deploy-platform');b.type='button';b.setAttribute('role','tab');b.setAttribute('aria-selected',String(i===state.variant));
        b.append(quietIcon(v.os),node('span',label(v)));if(state.problem&&state.problem.variant_id===v.id)b.classList.add('has-problem');b.onclick=()=>{state.variant=i;render();};tabs.append(b);});
      bar.append(tabs);
    }else if(!d.variants.length){
      bar.append(note('Choose one or more platforms. Each endpoint runs the commands for its own operating system.'));
    }
    return bar;
  }
  // A second variant of the selected OS, e.g. Linux arm64 beside amd64.
  function addAnotherVariant(d,v,make){return Object.assign(button(`Add another ${osName(v.os)} variant`,()=>{d.variants.push(make(v.os));state.variant=d.variants.length-1;render();}),{className:'cl-btn'});}
  // The package library: ready-made definitions added to the catalog as
  // drafts to review, test and publish (software_library.go). Each row says
  // exactly what it would adopt: the vendor, the platforms and the package
  // each one installs from.
  async function openLibrary(){
    let data;try{data=await api('/api/software-library');}catch(e){message(e.message);return;}
    openModal('Package library','<p class="modal-note">Widely used applications, installed through each platform\'s own package manager, so endpoints always get the vendor\'s current release. Adding one creates an unpublished draft in your catalog: test it on one endpoint, then publish it.</p><label class="lib-search"><input type="search" placeholder="Filter by name, vendor or category" aria-label="Filter the library"></label><ul class="lib-list" role="list"></ul>',wrap=>{
      const list=wrap.querySelector('.lib-list'),q=wrap.querySelector('.lib-search input');
      const draw=()=>{const t=q.value.trim().toLowerCase();list.replaceChildren();
        const shown=data.items.filter(i=>!t||[i.name,i.vendor,i.category].join(' ').toLowerCase().includes(t));
        if(!shown.length){list.append(node('li','Nothing in the library matches.','lib-empty'));return;}
        for(const it of shown){const li=node('li',undefined,'lib-item');
          const main=node('div',undefined,'lib-main');
          main.append(node('div',it.name,'lib-name'),node('div',[it.vendor,it.category].filter(Boolean).join(' · '),'lib-meta'));
          const src=node('div',undefined,'lib-src');
          for(const os of ['windows','darwin','linux'])if(it.sources[os]){const s=node('span',undefined,'lib-src-item');const ic=osIcons([os]);ic.setAttribute('aria-hidden','true');s.append(ic,node('span',it.sources[os]));src.append(s);}
          main.append(src);
          let act;
          if(it.package_id){act=button('Open in catalog',async()=>{document.getElementById('mustra-modal')?.remove();const pkg=state.packages.find(p=>p.id===it.package_id);if(pkg)await openPackage(pkg);});act.className='cl-btn';}
          else{act=button('Add',async()=>{act.disabled=true;act.textContent='Adding…';
            try{const r=await api('/api/software-library/'+encodeURIComponent(it.id),'POST');it.package_id=r.package_id;await refresh();
              document.getElementById('mustra-modal')?.remove();const pkg=state.packages.find(p=>p.id===r.package_id);if(pkg)await openPackage(pkg);
              message(it.name+' added as a draft. Test it on one endpoint, then publish.');}
            catch(e){act.disabled=false;act.textContent='Add';li.append(node('div',e.message,'lib-err'));}});act.className='cl-btn';}
          act.classList.add('lib-act');li.append(main,act);list.append(li);}};
      q.addEventListener('input',draw);draw();q.focus();
    });
  }
  function footer(extra){
    const bar=node('div',undefined,'deploy-footer');
    const actions=node('div',undefined,'deploy-footer-actions');
    const saved=state.packages.find(p=>p.id===state.packageID);
    if(saved&&canDeploy(saved))extra=[button('Deploy…',()=>act(()=>openDeployWindow([saved]))),...extra];
    // Saving re-renders the editor, so the check goes on the Save button
    // that is there afterwards.
    // A check only when something was saved: with nothing changed, the
    // editor's own "Nothing to save." says so instead.
    const saveBtn=button('Save',()=>act(async()=>{if(!draftDirty()&&metaKey()===state.savedMeta){await saveAll();return;}await withButtonState(saveBtn,saveAll);flashDone($('deploy-editor')?.querySelector('.deploy-footer-actions button[data-save]'));}));saveBtn.dataset.save='1';
    actions.append(saveBtn,button('Publish',()=>act(async()=>{
      // Only the package's details changed on a published version: save
      // them, and there is no new version to publish.
      if(!draftDirty()&&state.revision?.published){const changed=await saveMeta();render();message(changed?'Package details saved. Nothing new to publish: the version is unchanged.':'Nothing new to publish.');return;}
      const rev=await saveAll();
      const live=state.revisions.filter(r=>r.published&&!r.retired&&r.id!==rev.id);
      const retire=live.length>0&&confirm(`Publish ${rev.label||rev.id} and retire the previous version${live.length===1?'':'s'} (${live.map(r=>r.label||r.id).join(', ')})?\n\nRetired versions are kept for the record and marked "Superseded by ${rev.label||rev.id}"; they can no longer be deployed. Cancel publishes without retiring anything.`);
      const out=await api(`/api/deploy/revisions/${rev.id}/publish`,'POST',{retire_previous:retire});state.revision.published=true;await refresh();render();
      const gone=out?.retired_previous||[];message('Published '+(rev.label||rev.id)+(gone.length?` · retired ${gone.join(', ')}`:''));}),true),...extra);
    const msg=node('div',undefined,'deploy-message');msg.id='deploy-editor-message';msg.setAttribute('role','status');
    if(state.problem){msg.textContent=state.problem.text;msg.style.color='var(--off)';msg.classList.add('is-link');msg.title='Show where';msg.onclick=()=>{const el=$('deploy-editor').querySelector('.deploy-problem');el?.scrollIntoView({behavior:'smooth',block:'center'});};}
    bar.append(actions,msg);return bar;
  }
  function draftExtras(){
    const extra=[];
    if(state.revision?.published)extra.push(button('Used by / retire version',()=>act(()=>references(state.revision))));
    // Drafts only. A published version is retired instead, so the record of
    // what endpoints were actually sent stays intact.
    if(state.revision&&!state.revision.published)extra.push(button('Delete this draft',()=>act(async()=>{
      const rev=state.revision;
      if(!confirm(`Delete draft ${rev.label||rev.id}?\n\nIt has not been published, so nothing is running it. Any test-run results for this draft go with it; the audit log keeps the record that those dispatches happened. This cannot be undone.`))return;
      const out=await api(`/api/deploy/revisions/${rev.id}`,'DELETE');
      state.revisions=state.revisions.filter(r=>r.id!==rev.id);
      const next=state.revisions[0];
      if(next)chooseRevision(next); else {state.revision=null;state.draft=null;}
      await refresh();render();message(out&&out.test_runs_removed
        ?`Draft deleted, along with ${out.test_runs_removed} test-run record(s).`
        :'Draft deleted.');
    })));
    return extra;
  }
  function detailsCard(){
    const revisionSelect=field({value:state.revision?.id||''},'value','Revision','text',[['','Unsaved draft'],...state.revisions.map(r=>[r.id,`${r.label||r.id} · ${r.retired?'Retired'+(r.retired_note?': '+r.retired_note:''):r.published?'Published':'Draft'}`])]);revisionSelect.lastChild.onchange=e=>{const rev=state.revisions.find(r=>r.id===e.target.value);if(rev)chooseRevision(rev);};
    return mark(card('Package details',row(field(state,'name',isAction()?'Package name':'Application name'),versionField(),revisionSelect),note(state.revision?.retired?`Retired${state.revision.retired_note?': '+state.revision.retired_note:''}${state.revision.retired_by?' · by '+state.revision.retired_by:''}${state.revision.retired_at?' · '+fmtDate(state.revision.retired_at):''}. It can no longer be deployed; editing creates a new draft.`:state.revision?.published?'Editing creates a new draft; this published revision is immutable.':isAction()?'Configure one command per platform; each endpoint runs its own platform\'s. Success defaults to exit code 0.':'One package can cover Windows, macOS and Linux: add a platform below and each endpoint gets the commands for its own OS. Drafts must define detection and validation before publishing.')),'details');
  }
  function catalogCard(){
    if(state.packageID==='new')return null;const meta=state.metadata;meta.name=state.name;
    const c=card('Catalog settings',row(field(meta,'enabled','Enabled','checkbox'),...(isAction()?[]:[field(meta,'self_service','Offer in Self Service','checkbox'),field(meta,'self_service_follow_latest','Self Service follows latest published','checkbox'),field(meta,'allow_requests','Endpoints outside its groups may request it','checkbox')])),row(field(meta,'vendor','Vendor'),field(meta,'category','Category')),field(meta,'description','Description','textarea'),groupPicker(meta),...(isAction()?[]:[field(meta,'self_service_revision','Self Service pinned revision','text',[['','First published revision'],...state.revisions.filter(r=>r.published&&!r.retired).map(r=>[r.id,r.label||r.id])])]),field(meta,'expire_seconds','Default deployment expiry (seconds)','number'),button('Save details',()=>act(async()=>{if(state.packageID==='new')throw Error('Save the package first');const c=await saveMeta();render();message(c?'Package details saved. The version is unchanged.':'Nothing to save.');})));
    c.querySelector('textarea')?.classList.add('deploy-short');return c;
  }
  function render(){const root=$('deploy-editor');if(!root)return;root.replaceChildren();if(!state.draft){showEditor(false);return;}showEditor(true);root.append(crumb());
    root.append(node('h1',state.packageID==='new'?(isAction()?'Create Action Package':'Create Software Package'):state.name||'Package','deploy-title'));
    root.append(cols(detailsCard(),catalogCard()));
    root.append(fold(parameters(state.draft,'Shared parameters'),!(state.draft.parameters||[]).length));
    if(isAction()){renderAction(root);return;}
    const d=state.draft;
    const plat=card('Platforms');root.append(plat);
    plat.append(platformTabs(d,os=>d.variants.push(newVariant(os)),v=>`${osName(v.os)}${v.version?' · '+v.version:''}`));
    const v=d.variants[state.variant];
    if(!v){root.append(footer(draftExtras()));revealProblem();return;}
    // Left: what this platform is and how an endpoint knows it has it.
    const config=node('div');config.append(node('h4',`${osName(v.os)} configuration`),row(field(v,'version','Application version'),csv(v,'arch','Architectures: amd64, arm64')),...(v.os==='linux'?[row(csv(v,'distribution','Linux distributions'),field(v,'os_version','OS version constraint'))]:[row(field(v,'os_version','OS version constraint'))]),mark(checkEditor(v,'requirements','Platform requirements',v.os),'requirements'),mark(checkEditor(v,'detection','Installed software detection',v.os),'detection'),fold(parameters(v,'Platform parameters'),!(v.parameters||[]).length),row(addAnotherVariant(d,v,newVariant),button(`Remove this ${osName(v.os)} variant`,()=>{if(variantHasWork(v)&&!confirm(`Remove this ${osName(v.os)} variant from this package?`))return;d.variants.splice(state.variant,1);state.variant=0;render();})));
    // Right: the operations this platform supports.
    const opsBox=node('div');const actionTabs=node('div',undefined,'deploy-ops');actionTabs.setAttribute('role','tablist');
    for(const op of ['install','update','remove']){const b=node('button',opLabel(op)+(v.actions[op]?'':' +'),'deploy-op');b.type='button';b.setAttribute('role','tab');b.setAttribute('aria-selected',String(state.operation===op));if(!v.actions[op])b.classList.add('is-empty');if(state.problem&&state.problem.variant_id===v.id&&state.problem.operation===op)b.classList.add('has-problem');b.onclick=()=>{state.operation=op;render();};actionTabs.append(b);}
    opsBox.append(actionTabs);
    let a=v.actions[state.operation];
    if(!a){opsBox.append(mark(node('div',undefined,'deploy-empty-op'),'actions'));opsBox.lastChild.append(note(`${opLabel(state.operation)} is not configured for ${osName(v.os)}.`),button('Configure '+opLabel(state.operation).toLowerCase(),()=>{v.actions[state.operation]=newAction(v.os);render();},true));}
    else{
      opsBox.append(row(field(a,'identity','Run as','text',[['administrator','Administrator / system'],['user','Logged-in user']]),field(a,'username','User (optional; otherwise exactly one active user)'),field(a,'validation_seconds','Validation retry window (seconds)','number')),field(a,'validate_after_reboot','Validate after reboot','checkbox'));
      opsBox.append(mark(card('Action steps',stepsEditor(a.steps,a,v.os)),'steps'));
      opsBox.append(mark(checkEditor(a,'validation','Post-action validation',v.os),'validation'),mark(checkEditor(a,'requirements','Action requirements',v.os),'action_requirements'));
      opsBox.append(fold(parameters(a,'Action parameters'),!(a.parameters||[]).length),mark(fold(filesEditor(a,v),!(a.files||[]).length),'files'),fold(dependencies(a),!(a.dependencies||[]).length));
      opsBox.append(button(`Remove ${opLabel(state.operation).toLowerCase()} from ${osName(v.os)}`,()=>{if(!confirm(`Remove the ${opLabel(state.operation)} operation for ${osName(v.os)}?`))return;delete v.actions[state.operation];render();}));
    }
    plat.append(cols(config,opsBox));
    root.append(fold(deploymentForm(),true));
    const advanced=node('details');advanced.append(node('summary','Complete definition (JSON)'),jsonField(state,'draft','Complete definition',{}));root.append(fold(card('Advanced',advanced),true));
    root.append(footer(draftExtras()));revealProblem();
  }
  // --- Deploy window ----------------------------------------------------------
  // One place to send published packages to endpoints, opened from a list
  // row, from a selection of several, or from the editor: targets (computers
  // and computer groups), inputs, reboot and expiry, who to tell, and when.
  // "Now" is POST /api/deploy/run per package; a time is a schedule
  // (POST /api/schedules) carrying the same choices.
  const EXPIRY_CHOICES=[['0','Package default'],['3600','1 hour'],['14400','4 hours'],['86400','1 day'],['604800','7 days']];
  const WEEKDAYS=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  function publishedRevisions(p){return revisionsOf(p).filter(r=>r.published&&!r.retired);}
  function deployableRevision(p){const revs=publishedRevisions(p);return revs.find(r=>r.id===p.deploy_revision)||revs[0]||null;}
  function canDeploy(p){return isBuiltin(p)||!!deployableRevision(p);}
  // Local "HH:MM" (and weekday) to the UTC values a schedule stores.
  function toUTC(time,weekday){const [h,m]=time.split(':').map(Number);const d=new Date();d.setHours(h,m,0,0);if(weekday!==undefined){d.setDate(d.getDate()+((weekday-d.getDay()+7)%7));}return {time_of_day:String(d.getUTCHours()).padStart(2,'0')+':'+String(d.getUTCMinutes()).padStart(2,'0'),weekday:d.getUTCDay()};}
  async function openDeployWindow(pkgs){
    pkgs=pkgs.filter(canDeploy);if(!pkgs.length){alert('Publish a version of the package before deploying it.');return;}
    // Built-in packages keep their own drawer, which knows their states.
    if(pkgs.length===1&&isBuiltin(pkgs[0])&&typeof window.openPackage==='function'){window.openPackage(pkgs[0].id);return;}
    pkgs=pkgs.filter(p=>!isBuiltin(p));
    const [groupsRes,eunRes]=await Promise.all([api('/api/groups').catch(()=>({groups:[]})),api('/api/eun').catch(()=>({messages:[]}))]);
    const groups=(groupsRes.groups||[]).filter(g=>g&&g.id),messages=eunRes.messages||[];
    const single=pkgs.length===1,kind=pkgs[0].kind==='action'?'action':'software';
    const w={rev:Object.fromEntries(pkgs.map(p=>[p.id,deployableRevision(p)])),operation:kind==='action'?'run':'install',agents:new Set(state.handoff||[]),groups:new Set(),q:'',tab:'computers',parameters:{},allow_reboot:false,force_remove:false,expire_seconds:0,override_windows:false,plan_id:'',notify_message_id:'',notify_on_finish:true,when:'now',run_at:'',time:'03:00',weekday:1,name:''};
    const overlay=node('div',undefined,'dw-overlay');const dlg=node('div',undefined,'dw');dlg.setAttribute('role','dialog');dlg.setAttribute('aria-modal','true');dlg.setAttribute('aria-labelledby','dw-title');overlay.append(dlg);
    const close=()=>{overlay.remove();document.removeEventListener('keydown',onKey);};
    const onKey=e=>{if(e.key==='Escape')close();};document.addEventListener('keydown',onKey);
    overlay.addEventListener('mousedown',e=>{if(e.target===overlay)close();});
    const variantsOf=p=>w.rev[p.id]?.definition?.variants||[];
    const osSupported=os=>pkgs.every(p=>variantsOf(p).some(v=>v.os===os));
    const opsAvailable=()=>kind==='action'?['run']:['install','update','remove'].filter(op=>pkgs.every(p=>variantsOf(p).some(v=>v.actions?.[op])));
    const groupName=id=>(groups.find(g=>g.id===id)||{}).name||id;
    function draw(){
      dlg.replaceChildren();
      const head=node('div',undefined,'dw-head');head.append(node('h2',single?`Deploy ${pkgs[0].name}`:`Deploy ${pkgs.length} packages`));head.lastChild.id='dw-title';
      const x=button('✕',close);x.className='dw-x';x.setAttribute('aria-label','Close');head.append(x);dlg.append(head);
      const body=node('div',undefined,'dw-body');dlg.append(body);
      // Package and operation.
      const pkgSec=node('section',undefined,'dw-sec');pkgSec.append(node('h3','Package'));
      for(const p of pkgs){const revs=publishedRevisions(p);const holder={value:w.rev[p.id]?.id||''};const f=field(holder,'value',single?'Version':p.name,'text',revs.map(r=>[r.id,(r.label||r.id)+(r.id===p.deploy_revision?' (current)':'')]));f.lastChild.onchange=e=>{w.rev[p.id]=revs.find(r=>r.id===e.target.value);draw();};pkgSec.append(f);}
      const ops=opsAvailable();if(!ops.includes(w.operation))w.operation=ops[0]||w.operation;
      if(kind!=='action'){const f=field(w,'operation','Operation','text',ops.map(o=>[o,opLabel(o)]));f.lastChild.onchange=e=>{w.operation=e.target.value;draw();};pkgSec.append(f);if(!ops.length)pkgSec.append(note('These packages have no operation in common.'));}
      const supported=['windows','darwin','linux'].filter(osSupported);pkgSec.append(note(`Runs on ${supported.map(osName).join(', ')||'no platform these packages share'}; each computer gets its own OS's commands.`));
      // Targets.
      const tSec=node('section',undefined,'dw-sec dw-targets');tSec.append(node('h3','Targets'));
      const tabs=node('div',undefined,'dw-tabs');for(const [t,label] of [['computers',`Computers (${w.agents.size})`],['groups',`Groups (${w.groups.size})`]]){const b=button(label,()=>{w.tab=t;draw();});b.className='dw-tab';b.setAttribute('aria-pressed',String(w.tab===t));tabs.append(b);}
      const search=node('input');search.type='search';search.placeholder=w.tab==='groups'?'Filter groups':'Filter by name, OS, site or IP';search.setAttribute('aria-label',search.placeholder);search.value=w.q;search.className='dw-search';
      search.oninput=()=>{w.q=search.value.toLowerCase();drawList();};tabs.append(search);tSec.append(tabs);
      const list=node('div',undefined,'dw-list');tSec.append(list);
      function drawList(){
        list.replaceChildren();const q=w.q;
        if(w.tab==='groups'){
          const shown=groups.filter(g=>!q||(g.name+' '+(g.description||'')).toLowerCase().includes(q));
          if(!shown.length)list.append(note(groups.length?'No group matches.':'No computer groups yet. Make one under Groups.'));
          for(const g of shown){const lab=node('label',undefined,'dw-item');const cb=node('input');cb.type='checkbox';cb.checked=w.groups.has(g.id);cb.onchange=()=>{cb.checked?w.groups.add(g.id):w.groups.delete(g.id);draw();};lab.append(cb,node('span',g.name,'dw-name'),node('span',`${g.member_count??(g.member_ids||[]).length} computer(s) · ${g.kind||'static'}`,'dw-meta'));list.append(lab);}
          return;
        }
        const shown=state.agents.filter(a=>!q||[a.hostname,a.os,a.site,(a.ips||[]).join(' '),a.platform].join(' ').toLowerCase().includes(q)).sort((a,b)=>String(a.hostname).localeCompare(String(b.hostname)));
        const usable=shown.filter(a=>osSupported(a.os));
        const bar=node('div',undefined,'dw-listbar');const all=button(`Select ${usable.length} shown`,()=>{usable.forEach(a=>w.agents.add(a.agent_id));draw();});const none=button('Clear',()=>{w.agents.clear();draw();});all.className=none.className='cl-link';bar.append(all,none);list.append(bar);
        if(!shown.length)list.append(note('No computer matches.'));
        for(const a of shown){const ok=osSupported(a.os);const lab=node('label',undefined,'dw-item'+(ok?'':' is-off'));const cb=node('input');cb.type='checkbox';cb.disabled=!ok;cb.checked=ok&&w.agents.has(a.agent_id);cb.onchange=()=>{cb.checked?w.agents.add(a.agent_id):w.agents.delete(a.agent_id);draw();};
          const dot=node('span',undefined,'dw-dot'+(a.online?' is-on':''));dot.title=a.online?'Online':'Offline';
          lab.append(cb,dot,osIcons([a.os]),node('span',a.hostname,'dw-name'),node('span',ok?[a.site,a.platform&&a.platform_version?a.platform+' '+a.platform_version:a.platform].filter(Boolean).join(' · '):`no ${osName(a.os)} version in ${single?'this package':'every package'}`,'dw-meta'));list.append(lab);}
      }
      drawList();
      const chosen=[...[...w.agents].map(id=>(state.agents.find(a=>a.agent_id===id)||{}).hostname||id),...[...w.groups].map(id=>'Group: '+groupName(id))];
      const chips=node('div',undefined,'dw-chips');if(!chosen.length)chips.append(node('span','Nothing selected yet: pick computers, groups, or both.','dw-meta'));
      for(const c of chosen.slice(0,12))chips.append(node('span',c,'dw-chip'));if(chosen.length>12)chips.append(node('span',`+${chosen.length-12} more`,'dw-meta'));
      tSec.append(chips);
      // Inputs, for one package.
      const cols2=node('div',undefined,'dw-grid');body.append(pkgSec,tSec,cols2);
      if(single){const rev=w.rev[pkgs[0].id];const defs=new Map();for(const p of rev?.definition?.parameters||[])defs.set(p.name,p);for(const v of variantsOf(pkgs[0]))for(const p of [...(v.parameters||[]),...(v.actions?.[w.operation]?.parameters||[])])defs.set(p.name,p);
        if(defs.size){const sec=node('section',undefined,'dw-sec');sec.append(node('h3','Inputs'));for(const p of defs.values()){const holder={value:w.parameters[p.name]??p.default??''};const f=field(holder,'value',p.label||p.name,p.secret?'password':p.type==='numeric'?'number':p.type==='checkbox'?'checkbox':'text',p.type==='select'?['',...(p.options||[])]:undefined);f.lastChild.addEventListener('input',e=>{w.parameters[p.name]=p.type==='checkbox'?String(e.target.checked):e.target.value;});sec.append(f);}sec.append(note('Blank inputs use each platform\'s default.'));cols2.append(sec);}}
      else cols2.append(Object.assign(node('section',undefined,'dw-sec'),{}),);
      if(!single)cols2.lastChild.append(node('h3','Inputs'),note('Several packages deploy with each one\'s default inputs. Deploy one at a time to set inputs.'));
      // Options.
      const opt=node('section',undefined,'dw-sec');opt.append(node('h3','Options'));
      if(kind!=='action')opt.append(field(w,'allow_reboot','Allow a required reboot','checkbox'));
      if(w.operation==='remove')opt.append(field(w,'force_remove','Uninstall even if other packages depend on it','checkbox'));
      const exp=field({value:String(w.expire_seconds)},'value','Give up on offline computers after','text',EXPIRY_CHOICES);exp.lastChild.onchange=e=>{w.expire_seconds=Number(e.target.value);};opt.append(exp);
      if(w.when==='now'&&state.plans.length){const f=field(w,'plan_id','Rollout plan','text',[['','All at once'],...state.plans.map(p=>[p.id,p.name])]);opt.append(f);}
      if(state.canOverride)opt.append(field(w,'override_windows','Ignore maintenance windows','checkbox'));
      cols2.append(opt);
      // Notify.
      const ntf=node('section',undefined,'dw-sec');ntf.append(node('h3','Notify'));
      const msg=field(w,'notify_message_id','Tell the person at the computer','text',[['','Nothing'],...messages.map(m=>[m.id,`${m.name}${m.kind==='restart'?' (restart prompt)':''}`])]);ntf.append(msg);
      if(!messages.length){const a=node('a','Write an end-user message');a.href='/eun';ntf.append(note('No end-user messages yet.'),a);}
      ntf.append(field(w,'notify_on_finish','Notify me when it finishes','checkbox'),note('A notification in the bell with how many succeeded and failed.'));
      cols2.append(ntf);
      // When.
      const when=node('section',undefined,'dw-sec');when.append(node('h3','When'));
      const seg=node('div',undefined,'dw-tabs');for(const [k,l] of [['now','Now'],['once','Once'],['daily','Daily'],['weekly','Weekly']]){const b=button(l,()=>{w.when=k;draw();});b.className='dw-tab';b.setAttribute('aria-pressed',String(w.when===k));seg.append(b);}when.append(seg);
      if(w.when==='once'){if(!w.run_at){const d=new Date(Date.now()+3600e3);d.setMinutes(0,0,0);w.run_at=new Date(d-d.getTimezoneOffset()*6e4).toISOString().slice(0,16);}when.append(field(w,'run_at','Date and time (your time)','datetime-local'));}
      if(w.when==='daily'||w.when==='weekly'){const r=row(field(w,'time','Time (your time)','time'));if(w.when==='weekly'){const f=field({value:String(w.weekday)},'value','Day','text',WEEKDAYS.map((d,i)=>[String(i),d]));f.lastChild.onchange=e=>{w.weekday=Number(e.target.value);};r.prepend(f);}when.append(r);}
      if(w.when!=='now'){if(!w.name)w.name=`${single?pkgs[0].name:pkgs.length+' packages'} · ${opLabel(w.operation)}`;when.append(field(w,'name','Schedule name'),note('Computers that are offline when it fires are skipped; groups are re-read each time it runs.'));}
      cols2.append(when);
      // Footer.
      const foot=node('div',undefined,'dw-foot');const status=node('div',undefined,'dw-status');status.setAttribute('role','status');status.id='dw-status';
      const go=button(w.when==='now'?'Deploy now':'Create schedule',()=>submit(status),true);
      const acts=node('div',undefined,'dw-acts');if(single&&w.when==='now')acts.append(button('Preview',()=>preview(status)));acts.append(button('Cancel',close),go);
      foot.append(status,acts);dlg.append(foot);
    }
    function request(p){return {package_id:p.id,revision_id:w.rev[p.id]?.id||'',operation:w.operation,agent_ids:[...w.agents],group_ids:[...w.groups],parameters:single?w.parameters:{},allow_reboot:w.allow_reboot,force_remove:w.operation==='remove'&&w.force_remove,expire_seconds:w.expire_seconds,override_windows:state.canOverride&&w.override_windows,plan_id:w.when==='now'?w.plan_id:'',notify_message_id:w.notify_message_id,notify_on_finish:w.notify_on_finish};}
    function check(){if(!w.agents.size&&!w.groups.size)throw Error('Pick at least one computer or group.');if(!opsAvailable().includes(w.operation))throw Error('Pick an operation these packages support.');}
    async function preview(status){try{check();status.textContent='Checking…';const r=await api('/api/deploy/preview','POST',request(pkgs[0]));const skipped=r.skipped||[];status.textContent=`${r.targets} computer(s) would run it.`+(skipped.length?` ${skipped.length} skipped: `+skipped.slice(0,3).map(s=>((state.agents.find(a=>a.agent_id===s.agent_id)||{}).hostname||s.agent_id)+' ('+s.reason+')').join('; '):'');status.className='dw-status';}catch(e){status.textContent=e.message;status.className='dw-status is-error';}}
    async function submit(status){
      try{check();status.className='dw-status';status.textContent=w.when==='now'?'Starting…':'Saving…';const done=[];
        for(const p of pkgs){const req=request(p);
          if(w.when==='now'){const r=await api('/api/deploy/run','POST',req);done.push({p,run:r.run_id,n:r.targets});}
          else{const sched={name:pkgs.length>1?`${w.name} · ${p.name}`:w.name,package_id:p.id,revision_id:req.revision_id,follow_latest:false,operation:req.operation,parameters:req.parameters,agent_ids:req.agent_ids,group_ids:req.group_ids,allow_reboot:req.allow_reboot,force_remove:req.force_remove,expire_seconds:req.expire_seconds,override_windows:req.override_windows,notify_message_id:req.notify_message_id,notify_on_finish:req.notify_on_finish,enabled:true,kind:w.when};
            if(w.when==='once'){if(!w.run_at)throw Error('Pick a date and time.');sched.run_at=new Date(w.run_at).toISOString();sched.time_of_day='00:00';}
            else{const u=toUTC(w.time||'03:00',w.when==='weekly'?w.weekday:undefined);sched.time_of_day=u.time_of_day;if(w.when==='weekly')sched.weekday=u.weekday;}
            const r=await api('/api/schedules','POST',sched);done.push({p,schedule:r});}}
        status.replaceChildren();
        for(const d of done){if(d.run){const a=node('a',`${d.p.name}: started on ${d.n} computer(s) — watch it →`);a.href=`/software?run=${encodeURIComponent(d.run)}#deployments`;a.onclick=e=>{if(e.metaKey||e.ctrlKey||e.button!==0)return;e.preventDefault();close();location.hash='deployments';if(typeof softwareDeployments!=='undefined'){softwareDeployments.reload();softwareDeployments.open(d.run);}};status.append(a,node('br'));}
          else{const a=node('a',`${d.schedule.name}: next run ${d.schedule.next_run_at?fmtTime(d.schedule.next_run_at):'—'} →`);a.href='/software#schedules';status.append(a,node('br'));}}
        status.className='dw-status is-ok';dlg.querySelector('.dw-acts .primary').disabled=true;
      }catch(e){status.textContent=e.message;status.className='dw-status is-error';}
    }
    draw();document.body.append(overlay);dlg.querySelector('.dw-search')?.focus();
  }
  function deploymentForm(){const request={operation:state.operation,agent_ids:[],parameters:{},allow_reboot:false,force_remove:false,expire_seconds:86400,override_windows:false};const root=card('Test and deploy',note('Preview resolves platform variants and dependencies. Live checks run again on each endpoint.'));
    const picker=node('select');picker.multiple=true;picker.size=6;picker.setAttribute('aria-label','Target endpoints');for(const a of state.agents){const opt=node('option',`${a.hostname} · ${osDisplay(a)}${a.online?'':' · offline'}`);opt.value=a.agent_id;if(state.handoff&&state.handoff.has(a.agent_id))opt.selected=true;picker.append(opt);}
    // Targets handed over from a query result arrive pre-selected, and
    // the form says so: a picker that is quietly already filled in is the
    // kind of thing that dispatches to the wrong machines.
    if(state.handoff){const n=[...picker.selectedOptions].length;root.append(note(`${n} endpoint(s) selected from your Interact result${n<state.handoff.size?` (${state.handoff.size-n} of them are not in inventory any more)`:''}. Change the selection if that is not what you meant.`));}
    // A template fills the form in; the form is rebuilt from the request
    // so every field shows what the template set. The picker lives outside
    // the rebuilt part so a chosen target survives a change of template.
    const usable=state.templates.filter(t=>!t.package_id||t.package_id===state.packageID);
    const applyTemplate=t=>{if(!t)return;if(t.plan_id!==undefined)request.plan_id=t.plan_id;request.allow_reboot=!!t.allow_reboot;request.force_remove=!!t.force_remove;if(t.expire_seconds!==undefined)request.expire_seconds=t.expire_seconds;request.override_windows=state.canOverride&&!!t.override_windows;request.parameters={...(t.parameters||{})};};
    const templateHolder={value:''};const dflt=usable.find(t=>t.is_default);if(dflt){templateHolder.value=dflt.id;applyTemplate(dflt);}
    const templateField=field(templateHolder,'value','Template','text',[['','None'],...usable.map(t=>[t.id,t.name+(t.is_default?' (default)':'')])]);
    root.append(picker,templateField);
    const body=node('div');root.append(body);
    const build=()=>{body.replaceChildren();
      body.append(field(request,'plan_id','Rollout plan','text',[['','All selected endpoints'],...state.plans.map(p=>[p.id,p.name])]));
      const inputs=node('div');const renderInputs=()=>{inputs.replaceChildren();const selected=new Set([...picker.selectedOptions].map(o=>o.value));const platforms=new Set(state.agents.filter(a=>selected.has(a.agent_id)).map(a=>a.os));const defs=new Map();for(const p of state.draft.parameters||[])defs.set(p.name,p);for(const v of state.draft.variants){if(platforms.size&&!platforms.has(v.os))continue;for(const p of [...(v.parameters||[]),...(v.actions[state.operation]?.parameters||[])])defs.set(p.name,p);}for(const p of defs.values()){const holder={value:request.parameters[p.name]??p.default??''};const input=field(holder,'value',p.label||p.name,p.secret?'password':p.type==='numeric'?'number':p.type==='checkbox'?'checkbox':'text',p.type==='select'?['',...(p.options||[])]:undefined);input.lastChild.oninput=e=>request.parameters[p.name]=p.type==='checkbox'?String(e.target.checked):e.target.value;inputs.append(input);} };picker.onchange=renderInputs;renderInputs();
      body.append(inputs,note('Unedited inputs use each platform’s configured defaults.'),isAction()?row(field(request,'expire_seconds','Run expiry (seconds; 0 = package default)','number')):row(field(request,'allow_reboot','Allow required reboot','checkbox'),field(request,'force_remove','Override dependent uninstall protection','checkbox'),field(request,'expire_seconds','Expiry (seconds; 0 = package default)','number')));
      if(state.canOverride)body.append(row(field(request,'override_windows','Override maintenance windows (dispatch even while closed)','checkbox')));
    };build();
    templateField.lastChild.onchange=e=>{applyTemplate(usable.find(t=>t.id===e.target.value));build();};
    const result=node('pre',undefined,'deploy-events');result.hidden=true;
    const windowsNote=node('p');windowsNote.hidden=true;windowsNote.className='deploy-note';root.append(windowsNote);
    // The dispatcher would hold the job anyway; saying so before the
    // click is what stops "why is nothing happening" ten minutes later.
    const checkWindows=async(ids)=>{try{const r=await api('/api/maintenance-windows/check','POST',{agent_ids:ids,kind:'deploy'});const waiting=Object.entries(r.waiting||{});if(!waiting.length||request.override_windows){windowsNote.hidden=true;return;}const name=id=>(state.agents.find(a=>a.agent_id===id)||{}).hostname||id;windowsNote.hidden=false;windowsNote.textContent=`${waiting.length} of ${ids.length} endpoint(s) are outside their maintenance window and will wait: ${waiting.slice(0,5).map(([id,why])=>name(id)+' ('+why+')').join('; ')}${waiting.length>5?' …':''}`;}catch(e){windowsNote.hidden=true;}};
    picker.addEventListener('change',()=>checkWindows([...picker.selectedOptions].map(o=>o.value)));
    const submit=async(mode)=>{if(!state.revision)throw Error('Save a draft first');request.agent_ids=[...picker.selectedOptions].map(o=>o.value);if(!request.agent_ids.length)throw Error('Select at least one endpoint');const response=await api('/api/deploy/'+mode,'POST',{...request,package_id:state.packageID,revision_id:state.revision.id});result.hidden=false;result.textContent=JSON.stringify(response,null,2);if(response.run_id){const url=new URL(location);url.searchParams.set('run',response.run_id);url.searchParams.delete('package');url.hash='deployments';history.pushState(null,'',url);window.dispatchEvent(new HashChangeEvent('hashchange'));if(typeof softwareDeployments!=='undefined'){softwareDeployments.reload();softwareDeployments.open(response.run_id);}}};
    const saveTemplate=async()=>{const name=prompt('Template name');if(!name)return;await api('/api/deploy/templates','POST',{name,package_id:state.packageID,operation:state.operation,plan_id:request.plan_id||'',parameters:request.parameters,allow_reboot:!!request.allow_reboot,force_remove:!!request.force_remove,expire_seconds:request.expire_seconds||0,override_windows:!!request.override_windows});const t=await api('/api/deploy/templates');state.templates=t.templates||[];message(`Template "${name}" saved`);};
    root.append(row(button('Preview',()=>act(()=>submit('preview'))),button('Test draft on endpoint',()=>act(async()=>{await save();await submit('test');})),button('Deploy published revision',()=>act(()=>submit('run')),true),button('Save as template',()=>act(saveTemplate))),result);return root;
  }
  function age(seconds){const s=Math.max(0,seconds|0);if(s<90)return s+'s';const m=Math.round(s/60);if(m<90)return m+'m';const h=Math.round(m/60);return h<48?h+'h':Math.round(h/24)+'d';}
  async function logs(id){
    if(state.job!==id)state.sensorResult=null;state.job=id;const u=new URL(location);u.searchParams.set('job',id);history.replaceState(null,'',u);
    const query=new URLSearchParams({search:state.logSearch,before:state.logBefore});
    const data=await api(`/api/deploy/jobs/${id}/logs?${query}`),root=state.logRoot;if(!root?.isConnected)return;
    const active=root.contains(document.activeElement)&&document.activeElement.matches('input,textarea');if(active)return;
    const scroll=root.querySelector('pre')?.scrollTop||0;
    root.replaceChildren(node('div','Endpoint run '+id,'deploy-note'));
    const link=node('a','Download this run’s logs');link.href=`/api/deploy/jobs/${id}/logs?download=1`;
    const share=node('a','Link to this run');share.href=u.toString();
    const search=field(state,'logSearch','Search retained console output');search.lastChild.addEventListener('change',()=>{state.logBefore='';act(()=>logs(id));});
    root.append(row(link,share,button('View endpoint log sensor',()=>act(async()=>{
      state.sensorResult=await api(`/api/deploy/jobs/${id}/log-sensor`);await logs(id);
    }))),search,note('Command exit, sensor evidence, and final outcome are recorded separately. Logs are subject to the retention configured in Deploy settings.'));
    const pre=node('pre',formatEvents(data.events||[])||'No retained log events yet. The endpoint may not have started, or history may have expired.','deploy-events');pre.setAttribute('aria-label','Console output');root.append(pre);pre.scrollTop=scroll;
    if(data.truncated)root.append(note('Showing the latest matching events within the display limit.'),button('Older events',()=>{state.logBefore=data.events[0]?.timestamp||'';act(()=>logs(id));}));
    if(state.logBefore)root.append(button('Return to live output',()=>{state.logBefore='';act(()=>logs(id));}));
    if(state.sensorResult){const result=state.sensorResult;root.append(card('Action run logs sensor',note('Fresh endpoint retrieval, agent context. These logs do not change success criteria.'),node('pre',formatEvents(result.events||[]),'deploy-events'),note(result.truncated?'Results are bounded; older events may be omitted.':'Only locally retained events are available.')));}
  }
  function formatEvents(events){return events.map(e=>`${e.timestamp} [${e.stage}] ${e.exit_code!==undefined?'exit='+e.exit_code+' ':''}${e.message}`).join('\n');}
  async function settings(){const root=$('deploy-settings');if(!root)return;const data=await api('/api/deploy/settings');root.replaceChildren(note('No age-based deletion by default. Oldest ZIP archives are removed when the compressed-size cap is reached. Active and pending uncompressed files consume additional space.'));
    for(const [key,title] of [['endpoint_logs','Endpoint logs'],['server_logs','Server logs — per endpoint']])root.append(card(title,row(field(data[key],'retention_days','Retention days (0 = unlimited)','number'),field(data[key],'archive_mb','ZIP archive limit (MB)','number'),field(data[key],'rotate_mb','Rotate at (MB)','number'),field(data[key],'compress_files','Compress after this many files','number'))));root.append(field(data,'cache_mb','Endpoint package cache (MB)','number'),button('Save Deploy settings',async()=>{try{await api('/api/deploy/settings','PUT',data);status.textContent='Settings saved';}catch(e){status.textContent=e.message;}},true));const status=node('p');root.append(status);
  }
  function syncCatalog(){
    if(!['#actions','#catalog'].includes(location.hash))return;
    const kind=location.hash==='#actions'?'action':'software';
    const workspace=document.querySelector('.deploy-workspace');
    $(kind==='action'?'section-actions':'section-catalog').append(workspace);
    if(state.catalogKind!==kind){state.catalogKind=kind;state.draft=null;state.revision=null;render();}
    // Draw what is loaded now, then again with the current catalog: a
    // package added or published since the page opened would otherwise
    // stay missing until a reload.
    library();refresh().catch(()=>{});
  }
  window.addEventListener('hashchange',syncCatalog);
  // The sidebar link for the section that is already showing changes no
  // hash, so no hashchange fires: with a package open, the click did
  // nothing. Treat it as "back to the list".
  document.addEventListener('click',e=>{
    const a=e.target.closest('#module-subnav a.module-subnav-link');if(!a)return;
    const to=new URL(a.href,location.href);
    if(to.pathname!==location.pathname||!['#actions','#catalog'].includes(to.hash)||to.hash!==location.hash||!state.draft)return;
    e.preventDefault();const u=new URL(location.href);u.searchParams.delete('package');history.replaceState(null,'',u);showEditor(false);
  });
  function renderAction(root){
    const d=state.draft;
    if(d.review_required){const reviewed={value:false};const input=field(reviewed,'value','I reviewed script language, environment parameter bindings, and selected file scopes','checkbox');input.lastChild.onchange=e=>{d.review_required=!e.target.checked;};root.append(card('Review converted package',note('The original package and its consumers remain unchanged. Copied files are in the uploaded library but are not downloaded until explicitly assigned below. Replace $(name) substitution with MUSTRA_PARAM_name environment reads, and check any regex constraints carried over.'),input));}
    root.append(mark(fold(filesEditor(d,{}),!(d.files||[]).length),'files'));
    const plat=card('Command');root.append(plat);
    plat.append(platformTabs(d,os=>d.variants.push(actionVariant(os)),v=>osName(v.os)+(v.arch?.length?' · '+v.arch.join(', '):'')));
    const v=d.variants[state.variant];if(!v){root.append(footer(draftExtras()));revealProblem();return;}
    const a=v.actions.run??=newRun(v.os);a.success_mode||='exit_code';a.identity||='administrator';state.operation='run';
    // Left: the command itself, as in a package's Details | Command view.
    const command=node('div');command.append(node('h4',`${osName(v.os)} command`),mark(scriptEditor(a.steps[0].script,v.os),'steps'),row(field(a,'identity','Run as','text',[['administrator','Administrator / system'],['user','Logged-in user']]),field(a,'username','User (blank = one unambiguous active user)'),field(a,'download_seconds','Download timeout (seconds; 0 = 1800)','number')),note('The download limit covers staging, including retries; the execution timeout starts when the command is prepared.'));
    // Right: how success is judged, and this platform's own inputs and files.
    const mode=field(a,'success_mode','Success criteria','text',[['exit_code','Exit code'],['sensor','Sensor only'],['both','Exit code and sensor']]);
    mode.lastChild.onchange=e=>{a.success_mode=e.target.value;a.validation=a.success_mode==='exit_code'?null:(a.validation||{kind:'sensor',sensor_id:'',quantifier:'any',rows:[]});render();};
    const verify=mark(node('div'),'validation');verify.append(node('h4','Verification'),mode,note('No custom criteria means exit code 0. Failure to start, download failure and timeout never pass.'));
    if(a.success_mode!=='sensor')verify.append(csv(a.steps[0],'success_codes','Successful exit codes (blank = 0)'));
    if(a.success_mode==='sensor'||a.success_mode==='both')verify.append(field(a,'validation_seconds','Verification window (seconds; 0 = one immediate check)','number'),checkEditor(a,'validation','Sensor condition',v.os));
    verify.append(row(csv(v,'arch','Architectures (blank = amd64 and arm64)')),fold(parameters(v,'Platform parameters'),!(v.parameters||[]).length),fold(filesEditor(a,v),!(a.files||[]).length),row(addAnotherVariant(d,v,actionVariant),button(`Remove this ${osName(v.os)} variant`,()=>{if(variantHasWork(v)&&!confirm(`Remove this ${osName(v.os)} command from this package?`))return;d.variants.splice(state.variant,1);state.variant=0;render();})));
    plat.append(cols(command,verify));
    root.append(fold(deploymentForm(),true));
    root.append(footer(draftExtras()));revealProblem();
  }
  async function references(rev){
    $('deploy-reference-panel')?.remove();
    const box=card('Used by · '+(rev.label||rev.id));box.id='deploy-reference-panel';$('deploy-editor').prepend(box);
    const replacement={value:''};
    const choice=field(replacement,'value','Replacement version','text',[['','Select active replacement'],...state.revisions.filter(r=>r.published&&!r.retired&&r.id!==rev.id).map(r=>[r.id,r.label||r.id])]);
    const rows=node('div'),status=note(''),selected=new Map();
    async function preview(){
      selected.clear();rows.replaceChildren();
      const data=await api(`/api/deploy/revisions/${rev.id}/references?replacement=${encodeURIComponent(replacement.value)}`);
      if(!data.references.length)rows.append(note('No schedules or playbook steps currently reference this version.'));
      for(const ref of data.references){
        const label=node('label'),check=node('input');check.type='checkbox';check.disabled=!ref.compatible;
        check.onchange=()=>{if(check.checked)selected.set(ref.key,ref.fingerprint);else selected.delete(ref.key);};
        const link=node('a',ref.name);link.href=ref.url;
        label.append(check,link,document.createTextNode(ref.follow_latest?' · follows latest':' · pinned'));
        rows.append(row(label,note(ref.reason||(ref.compatible?'Compatible; will pin to the replacement version.':'Choose a replacement to check compatibility.'))));
      }
      status.textContent=rev.retired?'This version is retired. Remaining references must be updated before they can run.':'Retirement blocks new runs using this version. Already-dispatched jobs continue.';
    }
    choice.lastChild.onchange=()=>{replacement.value=choice.lastChild.value;act(preview);};
    box.append(choice,rows,status,row(button('Update selected references',()=>act(async()=>{
      if(!selected.size)throw Error('Select compatible references to update');
      await api(`/api/deploy/revisions/${rev.id}/references`,'POST',{replacement:replacement.value,references:Object.fromEntries(selected)});await preview();status.textContent='Selected references updated.';
    }),true),button(rev.retired?'Version retired':'Retire this version',()=>act(async()=>{
      if(rev.retired)return;
      const why=prompt('Retire this version? Remaining consumers will be blocked until updated. Already-dispatched runs continue.\n\nNote to keep on it (optional):','');if(why===null)return;
      await api(`/api/deploy/revisions/${rev.id}/retire`,'POST',{note:why.trim()});rev.retired=true;await refresh();await preview();
    }))));
    const versions=node('details');versions.append(node('summary','Retire the whole package'));
    versions.append(note('Review each version’s Used by list before retiring the package. All published versions will be retired, including older pins.'));
    for(const r of state.revisions.filter(r=>r.published))versions.append(button('Used by '+(r.label||r.id),()=>act(()=>references(r))));
    versions.append(button('Retire package and all published versions',()=>act(async()=>{
      if(!confirm('Retire every published version and disable this package? All remaining references will be blocked.'))return;
      await api(`/api/deploy/revisions/${rev.id}/retire`,'POST',{entire_package:true});await refresh();await openPackage(state.packages.find(p=>p.id===rev.package_id));
    })));
    box.append(versions);await preview();box.scrollIntoView({block:'start'});
  }
  document.addEventListener('mustra:user',()=>act(async()=>{const [agents,builtin,custom,plans,templates]=await Promise.all([api('/api/agents'),api('/api/sensors'),api('/api/sensors/custom'),api('/api/deployment-plans'),api('/api/deploy/templates').catch(()=>({}))]);state.plans=plans.plans||[];state.templates=templates.templates||[];state.canOverride=!!templates.can_override;state.agents=agents.agents||agents||[];state.sensors=[{id:'file_events',name:'File events (covered history)',fields:[{name:'path'},{name:'op'},{name:'at'}]},{id:'process_events',name:'Process events (covered history)',fields:[{name:'name'},{name:'pid'},{name:'cmdline'},{name:'at'}]},...(builtin.sensors||builtin.catalog||[]).map(s=>({id:s.kind,name:s.name,fields:(s.returns||'').split(',').map(x=>x.trim())})),...(custom.sensors||[]).map(s=>({id:'custom_'+s.id,name:s.name,fields:s.fields||[{name:'value'}]}))];await refresh();syncCatalog();render();await settings();const params=new URLSearchParams(location.search);if(params.get('agents'))state.handoff=new Set(params.get('agents').split(',').filter(Boolean));if(params.get('package')){const pkg=state.packages.find(p=>p.id===params.get('package'));const drawer=pkg&&!pkg.deploy_revision&&(params.get('agents')||isBuiltin(pkg));if(pkg&&!drawer){await openPackage(pkg);if(params.get('deploy')==='1'&&canDeploy(pkg))await openDeployWindow([pkg]);}}}));
  // The console viewer follows a running job while it is on screen.
  setInterval(()=>{if(document.hidden||!state.logRoot?.isConnected||!state.job||state.logBefore||state.logLive===false)return;logs(state.job).catch(()=>{});},3000);
  // The Deployments page opens an endpoint's console output and cancels its
  // job through these; Deployment Progress used to host both.
  window.mustraDeployConsole={
    open(jobID,container,live=true){state.logRoot=container;state.logBefore='';state.logSearch='';state.logLive=live;return act(()=>logs(jobID));},
    close(){state.logRoot=null;state.job=null;const u=new URL(location);u.searchParams.delete('job');history.replaceState(null,'',u);},
    cancel(jobID,force){return api(`/api/deploy/jobs/${jobID}/cancel`,'POST',{force:!!force});},
  };
})();
