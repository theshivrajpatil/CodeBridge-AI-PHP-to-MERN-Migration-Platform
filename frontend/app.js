const $ = id => document.getElementById(id);
let scanned = false;
async function api(path, options={}) {
  const response = await fetch(path,{headers:{"Content-Type":"application/json"},...options});
  const data = await response.json().catch(()=>({}));
  if(!response.ok) { const detail=data.detail; const text=typeof detail==="string"?detail:(detail?.message?detail.message+(detail.reasons?.length?" — "+detail.reasons.join("; "):""):JSON.stringify(detail)||`Request failed (${response.status})`); throw new Error(text); }
  return data;
}
function message(id,text,type=""){const el=$(id);el.textContent=text;el.className=`message ${type}`;}
function bytes(n){return n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(1)} MB`;}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function checkModel(){
 try{
  const endpoint="http://127.0.0.1:11434";
  const d=await api(`/api/models?ollama_url=${encodeURIComponent(endpoint)}`);
  $("metric-model").textContent=d.connected?"Connected":"Offline";
  $("model-note").textContent=d.connected?`${d.models.length} model(s) available on this Ollama server`:"Scanning/planning still available";
 }catch{$("metric-model").textContent="Offline";$("model-note").textContent="Scanning/planning still available";}
}
$("scan-form").addEventListener("submit",async e=>{
 e.preventDefault();const button=e.submitter;button.disabled=true;button.textContent="Scanning…";
 message("scan-message","Indexing repository metadata. Large repositories may take a moment.");
 try{
  const d=await api("/api/scan",{method:"POST",body:JSON.stringify({path:$("repo-path").value.trim()})});scanned=true;
  $("metric-files").textContent=d.file_count.toLocaleString();$("metric-php").textContent=d.php_file_count.toLocaleString();
  $("metric-framework").textContent=d.framework_hints.length?d.framework_hints.join(" · "):"No clear signals";
  $("plan-button").disabled=false;$("behavior-button").disabled=false;$("dependencies-button").disabled=false;$("schema-button").disabled=false;$("coverage-button").disabled=false;$("spec-button").disabled=false;
  $("inventory-count").textContent=`${d.files.length} displayed · ${d.file_count} total`;$("report-path").textContent=`Report: ${d.report_file}`;
  $("file-rows").innerHTML=d.files.slice(0,1000).map(f=>`<tr><td>${esc(f.path)}</td><td>${esc(f.extension)}</td><td>${bytes(f.size_bytes)}</td></tr>`).join("")||'<tr><td colspan="3" class="empty">No files found.</td></tr>';
  message("scan-message",`Scan complete: ${d.php_file_count} PHP files. ${d.framework_hints.join("; ")||"No framework identified."}${d.warnings.length?" Warnings: "+d.warnings.join("; "):""}`,"success");
  $("explorer-load").disabled=false;$("units-button").disabled=true;$("units-list").innerHTML='<div class="empty-card">Migration units will appear here.</div>';$("unit-count").textContent="NOT LOADED";$("plan-content").innerHTML='<div class="empty-card">Inventory ready. Build the migration plan to continue.</div>';$("plan-report").textContent="";$("behavior-output").hidden=true;$("dependencies-output").hidden=true;$("schema-output").hidden=true;$("coverage-output").hidden=true;$("spec-output").hidden=true;
 }catch(err){message("scan-message",err.message,"error");}finally{button.disabled=false;button.innerHTML='Scan repository <span>→</span>';}
});
$("plan-button").addEventListener("click",async()=>{
 const b=$("plan-button");b.disabled=true;b.textContent="Building plan…";
 try{const p=await api("/api/plan",{method:"POST",body:JSON.stringify({})});
 $("plan-content").innerHTML=p.steps.map(s=>`<article class="plan-step"><div class="step-number">${String(s.phase).padStart(2,"0")}</div><div><h3>${esc(s.name)}</h3><p>${esc(s.details)}</p></div><div class="plan-status">${esc(s.status)}</div></article>`).join("");
 $("plan-report").textContent=`Plan saved: ${p.report_file} · Existing database preserved by default`;
 }catch(err){$("plan-content").innerHTML=`<div class="empty-card">${esc(err.message)}</div>`;}finally{b.disabled=false;b.innerHTML='Build migration plan <span>→</span>';}
});
$("behavior-button").addEventListener("click",async()=>{
 const b=$("behavior-button");b.disabled=true;b.textContent="Extracting contracts…";
 try{
  const d=await api("/api/behavior",{method:"POST",body:JSON.stringify({})});
  $("behavior-output").textContent=JSON.stringify(d,null,2);$("behavior-output").hidden=false;
  const c=d.coverage||{};
  $("plan-report").textContent=`Behaviour contracts: ${d.route_contract_count||0} routes · ${c.routes_with_method_and_literal_path||0} with literal method/path · authentication, validation, database and response semantics still require review`;
 }catch(err){message("scan-message",err.message,"error");}finally{b.disabled=!scanned;b.innerHTML='Extract behaviour contracts <span>→</span>';}
});

$("dependencies-button").addEventListener("click",async()=>{
 const b=$("dependencies-button");b.disabled=true;b.textContent="Analysing dependencies…";
 try{
  const d=await api("/api/dependencies",{method:"POST",body:JSON.stringify({})});
  $("dependencies-output").textContent=JSON.stringify(d,null,2);$("dependencies-output").hidden=false;
  const c=d.coverage||{};
  $("plan-report").textContent=`Backend dependency analysis: ${d.edge_count||0} evidence edges · ${d.database_operation_count||0} database signals · ${d.unresolved_relationships?.length||0} unresolved relationships · static evidence requires review`;
 }catch(err){message("scan-message",err.message,"error");}finally{b.disabled=!scanned;b.innerHTML='Analyse backend dependencies <span>→</span>';}
});

$("schema-button").addEventListener("click",async()=>{
 const b=$("schema-button");b.disabled=true;b.textContent="Inspecting schema…";
 try{const d=await api("/api/schema",{method:"POST",body:JSON.stringify({})});
  $("schema-output").textContent=JSON.stringify(d,null,2);$("schema-output").hidden=false;
  $("plan-report").textContent=`Schema history: ${d.catalog?.length||0} table candidates · ${d.operations?.length||0} migration operations · static evidence only; not live schema`;
 }catch(err){message("scan-message",err.message,"error");}finally{b.disabled=!scanned;b.innerHTML='Inspect database schema <span>→</span>';}
});

$("coverage-button").addEventListener("click",async()=>{
 const b=$("coverage-button");b.disabled=true;b.textContent="Checking coverage…";
 try{const d=await api("/api/coverage");
  $("coverage-output").textContent=JSON.stringify(d,null,2);$("coverage-output").hidden=false;
  const php=d.php_analysis||{};const dep=d.dependencies||{};
  $("plan-report").textContent=`Coverage: ${php.analysed||0}/${php.discovered||0} PHP files analysed · ${php.ast_parsed||0} AST parsed · ${dep.edge_count||0} dependency edges · generation ${d.generation_enabled?"enabled":"disabled"}`;
 }catch(err){message("scan-message",err.message,"error");}finally{b.disabled=!scanned;b.innerHTML='View analysis coverage <span>→</span>';}
});

$("spec-button").addEventListener("click",async()=>{
 const b=$("spec-button");b.disabled=true;b.textContent="Building specification…";
 try{const d=await api("/api/specification",{method:"POST",body:JSON.stringify({})});
  $("spec-output").textContent=JSON.stringify(d,null,2);$("spec-output").hidden=false;$("units-button").disabled=false;
  $("plan-report").textContent=`Specification validated and saved: ${d.report_file} · ${d.migration_units.length} migration unit(s) · ${d.status} · Human approval required`;
  message("units-message",`Specification saved and validated. Loading ${d.migration_units.length} migration unit(s)…`);
  await refreshUnits();
  message("units-message",`${loadedUnits.length} migration unit(s) loaded successfully. Review decisions do not authorize code generation.` ,"success");
 }catch(err){message("scan-message",err.message,"error");message("units-message",`Specification/review workflow failed: ${err.message}`,"error");}finally{b.disabled=!scanned;b.innerHTML='Generate migration specification <span>→</span>';}
});
checkModel();

// V5.9: visible, fingerprint-bound migration-unit approval workflow.
let loadedUnits = [];
function renderUnits(units, counts={}){
 loadedUnits=units||[];
 const list=$("units-list"), total=loadedUnits.length;
 const approved=Number(counts.APPROVED||0), rejected=Number(counts.REJECTED||0);
 const changes=Number(counts.CHANGES_REQUESTED||0), staleCount=Number(counts.STALE_SOURCE||0);
 const pending=Number(counts.PENDING_REVIEW||0), decided=approved+rejected+changes;
 $("unit-count").textContent=`${total} UNIT(S)`;
 const statuses=["PENDING_REVIEW","APPROVED","REJECTED","CHANGES_REQUESTED","STALE_SOURCE"];
 $("unit-summary").innerHTML=statuses.map(status=>`<div class="unit-stat status-tile-${status.toLowerCase()}"><b>${Number(counts[status]||0)}</b><span>${esc(status.replaceAll("_"," "))}</span></div>`).join("");
 const percent=total?Math.round((decided/total)*100):0;
 $("unit-progress").innerHTML=`<div class="progress-copy"><b>${decided} of ${total} units reviewed</b><span>${percent}% decision coverage · ${pending} pending · ${staleCount} stale</span></div><div class="progress-track" role="progressbar" aria-label="Migration unit review progress" aria-valuemin="0" aria-valuemax="${total}" aria-valuenow="${decided}"><span style="width:${percent}%"></span></div><p>Counts are calculated from the current repository's fingerprint-matched approval records. Approval is a review record only; it does not authorize code generation or database changes.</p>`;
 const filter=$("unit-filter")?.value||"ALL", query=($("unit-search")?.value||"").trim().toLowerCase();
 const visible=loadedUnits.filter(unit=>{
  const matchesStatus=filter==="ALL"||unit.status===filter;
  const searchable=[unit.unit_id,...(unit.source_paths||[]),...(unit.migration_groups||[])].join(" ").toLowerCase();
  return matchesStatus&&(!query||searchable.includes(query));
 });
 if(!total){list.innerHTML='<div class="empty-card">No PHP migration units were produced. Check the specification report and analysis coverage.</div>';return;}
 if(!visible.length){list.innerHTML='<div class="empty-card">No units match the selected status or search text.</div>';return;}
 list.innerHTML=visible.map(u=>{
  const approval=u.approval||{}, stale=u.status==="STALE_SOURCE"||u.source_validation?.valid===false;
  const sourcePaths=u.source_paths||[], risks=u.risks||[];
  const evidence={dependency_edges:u.dependency_edges||[],route_contracts:u.route_contracts||[],callable_contracts:u.callable_contracts||[],database_schema_operations:u.database_schema_operations||[],database_schema_candidates:u.database_schema_candidates||[],symbols:u.symbols||{},file_fingerprints:u.file_fingerprints||{},spec_fingerprint:u.spec_fingerprint};
  const previous=(u.prior_decisions||[]).length?`<div class="unit-history"><b>Previous source/specification versions</b><ul>${u.prior_decisions.map(event=>`<li>${esc(event.decision)} · ${esc(event.actor)} · ${esc(event.decided_at)} — ${esc(event.reason||"")}</li>`).join("")}</ul></div>`:"";
  return `<article class="unit-card" data-unit="${esc(u.unit_id)}" data-fingerprint="${esc(u.spec_fingerprint)}">
   <div class="unit-title-row"><div><div class="unit-kicker">MIGRATION UNIT</div><h3>${esc(u.unit_id)}</h3></div><span class="unit-status status-${esc(String(u.status).toLowerCase())}">${esc(String(u.status).replaceAll("_"," "))}</span></div>
   <div class="unit-meta"><span class="unit-chip">${esc(u.confidence||"UNKNOWN")} CONFIDENCE</span><span class="unit-chip">${sourcePaths.length} SOURCE FILE(S)</span><span class="unit-chip">${Number(u.dependency_edge_count||0)} EDGE(S)</span><span class="unit-chip">${(u.route_contracts||[]).length} ROUTE(S)</span><span class="unit-chip">${(u.callable_contracts||[]).length} CALLABLE(S)</span></div>
   <div class="unit-section"><b>Source files</b><ul class="unit-source-list">${sourcePaths.map(path=>`<li><code>${esc(path)}</code></li>`).join("")}</ul></div>
   <div class="unit-section unit-mapping"><div><b>Migration groups</b><span>${(u.migration_groups||[]).map(esc).join(" · ")||"Unclassified"}</span></div><div><b>Proposed target areas</b><span>${(u.proposed_target_areas||[]).map(esc).join(" · ")||"Manual review required"}</span></div></div>
   <div class="unit-validation ${stale?"invalid":"valid"}"><b>Source integrity:</b> ${stale?"STALE — decisions blocked":"MATCHES ANALYSIS FINGERPRINT"}${stale?`<br>Changed/unavailable files: ${(u.source_validation?.changed_paths||[]).map(esc).join(", ")}`:"<br>All source files match the captured SHA-256 fingerprints."}</div>
   <div class="unit-section unit-risk-section"><b>Review risks (${risks.length})</b><ul>${risks.map(risk=>`<li>${esc(risk)}</li>`).join("")}</ul></div>
   ${approval.decision?`<div class="unit-last-decision"><b>Latest decision: ${esc(approval.decision)}</b><span>${esc(approval.actor)} · ${esc(approval.decided_at)}</span><p>${esc(approval.reason)}</p><small>Audit event: ${esc(String(approval.event_hash||"").slice(0,20))}…</small></div>`:""}
   ${previous}<details class="unit-evidence"><summary>Inspect extracted evidence and fingerprint</summary><pre>${esc(JSON.stringify(evidence,null,2))}</pre></details>
   <div class="unit-actions"><div class="review-heading"><b>Record review decision</b><span>Requires reviewer ID, reason and explicit confirmation</span></div><label>Reviewer identifier<input class="reviewer" maxlength="120" placeholder="Your reviewer ID" value="${esc(approval.actor||sessionStorage.getItem("cb-reviewer")||"")}" ${stale?"disabled":""}></label><label>Decision reason<textarea class="reason" maxlength="2000" placeholder="Explain what you verified, or what must change" ${stale?"disabled":""}>${esc(approval.reason||"")}</textarea></label>
   <label class="review-confirm"><input type="checkbox" class="reviewed-confirm" ${stale?"disabled":""}> I reviewed the source files, dependency evidence, behaviour contracts, risks and target mapping.</label>
   <div class="unit-decision-buttons"><button class="unit-approve" data-decision="APPROVED" ${stale?"disabled":""}>Approve unit</button><button class="unit-reject" data-decision="REJECTED" ${stale?"disabled":""}>Reject unit</button><button class="unit-changes" data-decision="CHANGES_REQUESTED" ${stale?"disabled":""}>Request changes</button></div></div>
   <div class="unit-safety"><span>CODE GENERATION <b>DISABLED</b></span><span>DATABASE WRITES <b>DISABLED</b></span></div></article>`;
 }).join("");
}
async function refreshUnits(){
 const d=await api("/api/migration-units");renderUnits(d.units,d.status_counts);
 const a=await api("/api/migration-approvals/audit");
 const events=a.audit_log||[];
 $("unit-audit").textContent=`INTEGRITY: ${a.integrity} · ${events.length} EVENT(S) · STORE V${a.store_version}\n\n`+events.map((event,index)=>`${String(index+1).padStart(3,"0")}  ${event.decision}  ${event.unit_id}\n     Reviewer: ${event.actor}\n     Time: ${event.decided_at}\n     Reason: ${event.reason}\n     Fingerprint: ${event.spec_fingerprint}\n     Event hash: ${event.event_hash||"LEGACY / NOT HASH-CHAINED"}\n`).join("\n");
}
$("units-button")?.addEventListener("click",async()=>{
 const b=$("units-button");b.disabled=true;b.textContent="Loading units…";
 try{await refreshUnits();message("units-message",`${loadedUnits.length} migration unit(s) loaded. Approval is recorded per exact source/specification version; controlled generation needs explicit enablement and a separate approval (section 04).`,"success");}
 catch(err){message("units-message",err.message,"error");}finally{b.disabled=false;b.innerHTML='Load migration units <span>→</span>';}
});
function currentUnitCounts(){return Object.fromEntries(["PENDING_REVIEW","APPROVED","REJECTED","CHANGES_REQUESTED","STALE_SOURCE"].map(status=>[status,loadedUnits.filter(unit=>unit.status===status).length]));}
$("unit-filter")?.addEventListener("change",()=>renderUnits(loadedUnits,currentUnitCounts()));
$("unit-search")?.addEventListener("input",()=>renderUnits(loadedUnits,currentUnitCounts()));
$("units-list")?.addEventListener("click",async e=>{
 const button=e.target.closest("button[data-decision]");if(!button)return;
 const card=button.closest(".unit-card");const unitId=card?.dataset.unit;
 const actor=card?.querySelector(".reviewer")?.value.trim();const reason=card?.querySelector(".reason")?.value.trim();
 const confirmed=card?.querySelector(".reviewed-confirm")?.checked;
 if(!actor||!reason){message("units-message","Reviewer identifier and decision reason are required.","error");return;}
 if(!confirmed){message("units-message","Confirm that you reviewed the source files, evidence, contracts and risks before recording a decision.","error");return;}
 if(!window.confirm(`${button.dataset.decision.replaceAll("_"," ")} ${unitId}? This records a review decision only; it does not generate code.`))return;
 sessionStorage.setItem("cb-reviewer",actor);
 card.querySelectorAll("button").forEach(x=>x.disabled=true);
 try{
  await api(`/api/migration-units/${encodeURIComponent(unitId)}/decision`,{method:"POST",body:JSON.stringify({decision:button.dataset.decision,actor,reason,expected_fingerprint:card.dataset.fingerprint,confirm_reviewed:true})});
  await refreshUnits();message("units-message",`${unitId}: ${button.dataset.decision} recorded. Audit integrity verified. Code controlled generation needs explicit enablement and a separate approval (section 04).`,"success");
 }catch(err){message("units-message",err.message,"error");card.querySelectorAll("button").forEach(x=>x.disabled=false);}
});


// V5.10: restore the latest local project session after a page refresh or API restart.
async function restoreWorkbenchSession(){
 try{
  const state=await api("/api/state");
  if(!state.scanned)return;
  scanned=true;
  $("repo-path").value=state.project_root||"";
  $("metric-files").textContent=Number(state.file_count||0).toLocaleString();
  $("metric-php").textContent=Number(state.php_file_count||0).toLocaleString();
  $("metric-framework").textContent=(state.framework_hints||[]).join(" · ")||"No clear signals";
  $("plan-button").disabled=false;$("behavior-button").disabled=false;$("dependencies-button").disabled=false;
  $("schema-button").disabled=false;$("coverage-button").disabled=false;$("spec-button").disabled=false;
  $("explorer-load").disabled=false;
  $("inventory-count").textContent=`${(state.files||[]).length} displayed · ${state.file_count} total`;
  $("report-path").textContent=`Report: ${state.report_file||"workspace inventory"}`;
  $("file-rows").innerHTML=(state.files||[]).slice(0,1000).map(f=>`<tr><td>${esc(f.path)}</td><td>${esc(f.extension)}</td><td>${bytes(f.size_bytes)}</td></tr>`).join("")||'<tr><td colspan="3" class="empty">No files found.</td></tr>';
  message("scan-message","Restored the latest local repository session.","success");
  if(state.specification_ready){
   $("units-button").disabled=false;
   const spec=state.specification||{};
   $("plan-report").textContent=`Specification restored: ${spec.report_file} · ${spec.unit_count} migration unit(s) · ${spec.status}`;
   await refreshUnits();
   message("units-message",`${loadedUnits.length} migration unit(s) restored. Approval history remains version-bound.`,"success");
  }else if(state.plan_ready){
   $("plan-report").textContent="Migration plan restored. Generate the migration specification to create review units.";
  }
 }catch(err){console.warn("Could not restore CodeBridge session:",err);}
}
restoreWorkbenchSession();


// V5.12: visual explorer consumes the same deterministic analysis APIs as the reports.
let explorerCy = null;
let explorerGraphSignature = "";
let graphSelectionToken = 0;
function explorerMetric(label,value){return `<div class="explorer-metric"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`;}
function renderSchemaDashboard(schema, deps){
 const rows = [];
 const catalog = schema.catalog || deps.database_schema_catalog || [];
 const ops = schema.operations || deps.database_schema_operations || [];
 const cols = deps.database_schema_column_evidence || [];
 const engines = deps.database_engine_candidates || [];
 (Array.isArray(engines)?engines:[]).forEach(e=>rows.push(`<div class="evidence-row"><strong>Database engine candidate</strong><div>${esc(typeof e==="string"?e:(e.engine||e.name||JSON.stringify(e)))}</div><div class="evidence-meta">Static configuration signal · verify against deployment configuration</div></div>`));
 (Array.isArray(catalog)?catalog:[]).forEach(t=>rows.push(`<div class="evidence-row"><strong>${esc(t.table||t.table_name||t.name||"Table candidate")}</strong><div>${esc(t.source_path||t.source||"Source evidence unavailable")}</div><div class="evidence-meta">${esc(t.status||"STATIC EVIDENCE · NEEDS REVIEW")}</div></div>`));
 (Array.isArray(cols)?cols:[]).forEach(c=>rows.push(`<div class="evidence-row"><strong>${esc(c.table||c.table_candidate||"Table?")} · ${esc(c.column||c.column_name_candidate||"Column?")}</strong><div>Type candidate: ${esc(c.column_type||c.column_type_candidate||"Not identified")}</div><div class="evidence-meta">${esc(c.source_path||"Source path unavailable")} · ${esc(c.status||"NEEDS REVIEW")}</div></div>`));
 (Array.isArray(ops)?ops:[]).forEach(o=>rows.push(`<div class="evidence-row"><strong>${esc(o.operation||o.operation_type||"Schema operation")}</strong><div>${esc(o.table||o.table_name||"Table not resolved")}</div><div class="evidence-meta">${esc(o.source_path||"")} ${esc(o.status||"STATIC EVIDENCE")}</div></div>`));
 if(!rows.length) rows.push('<div class="empty-card">No schema objects were confidently extracted. This is not proof that the application has no database schema.</div>');
 $("schema-dashboard").innerHTML=rows.join("");
 $("schema-count").textContent=`${catalog.length+cols.length+ops.length} evidence item(s)`;
}
function renderPhpStructure(nodes){
 const phpNodes=(nodes||[]).filter(n=>n.kind==="SOURCE_FILE" && (/\.php$/i.test(n.id||"") || (n.symbols||[]).length));
 $("php-structure").innerHTML=phpNodes.length?phpNodes.map(n=>`<div class="structure-row"><strong>${esc(n.id)}</strong><div class="evidence-meta">${esc(n.role||"PHP source")} · ${(n.symbols||[]).length} symbol(s)</div><details><summary>Show detected symbols</summary><ul>${(n.symbols||[]).map(s=>`<li>${esc(s)}</li>`).join("")||"<li>No symbols extracted</li>"}</ul></details></div>`).join(""):'<div class="empty-card">No PHP symbols were extracted in the current analysis.</div>';
 $("structure-count").textContent=`${phpNodes.length} file(s)`;
}
function renderDependencyGraph(data){
 const nodes=Array.isArray(data.nodes)?data.nodes:[], edges=Array.isArray(data.edges)?data.edges:[], subsystems=Array.isArray(data.subsystems)?data.subsystems:[];
 $("graph-count").textContent=`${nodes.length} nodes · ${edges.length} edges`;
 if(!window.cytoscape){$("dependency-graph").innerHTML='<div class="empty-card">Graph renderer did not load. Check internet access and reload this page. Other analysis panels remain available.</div>';return;}
 const nodeMap=new Map(nodes.map(n=>[n.id,n]));
 const pathPanel=$("architecture-paths");
 if(pathPanel){const paths=Array.isArray(data.architecture_paths)?data.architecture_paths:[];pathPanel.innerHTML=`<b>Observed architecture paths · ${paths.length}</b>${paths.length?`<ul>${paths.slice(0,12).map(p=>`<li>${p.files.map(esc).join(" → ")} <small>(${esc(p.status)})</small></li>`).join("")}</ul>`:'<p>No complete route/controller-to-model/database path was established by current static evidence. Missing links are not inferred.</p>'}`;}
 const subsystemByFile=new Map();
 subsystems.forEach(group=>group.files.forEach(path=>subsystemByFile.set(path,group.id)));
 const subsystemSelect=$("graph-subsystem-filter");
 subsystemSelect.innerHTML='<option value="ALL">All subsystems</option>'+subsystems.map(g=>`<option value="${esc(g.id)}">${esc(g.name)} (${g.file_count})</option>`).join("");
 edges.forEach(e=>[e.from,e.to].forEach(id=>{if(id&&!nodeMap.has(id))nodeMap.set(id,{id,kind:"UNRESOLVED_REFERENCE",role:"External or unresolved reference",symbols:[]});}));
 const sortedNodes=[...nodeMap.values()].sort((a,b)=>a.id.localeCompare(b.id));
 const sortedEdges=[...edges].sort((a,b)=>`${a.from}|${a.to}|${a.type||""}`.localeCompare(`${b.from}|${b.to}|${b.type||""}`));
 const signature=JSON.stringify({nodes:sortedNodes.map(n=>n.id),edges:sortedEdges.map(e=>[e.from,e.to,e.type||""])});
 const signatureHash=[...signature].reduce((h,c)=>Math.imul(h^c.charCodeAt(0),16777619)>>>0,2166136261).toString(16);
 const layoutKey=`codebridge.graph.layout.v2:${signatureHash}`;
 let savedPositions={};try{savedPositions=JSON.parse(localStorage.getItem(layoutKey)||"{}");}catch{savedPositions={};}
 const hasSavedLayout=sortedNodes.length>0&&sortedNodes.every(n=>savedPositions[n.id]&&Number.isFinite(savedPositions[n.id].x)&&Number.isFinite(savedPositions[n.id].y));
 const columns=Math.max(1,Math.ceil(Math.sqrt(sortedNodes.length)));
 const presetPositions={};
 sortedNodes.forEach((n,index)=>{const group=subsystemByFile.get(n.id)||"UNASSIGNED";const groupHash=[...group].reduce((a,c)=>((a*31)+c.charCodeAt(0))>>>0,7);const groupX=(groupHash%5)*260;const col=index%columns,row=Math.floor(index/columns);presetPositions[n.id]=hasSavedLayout?savedPositions[n.id]:{x:groupX+col*150,y:row*125};});
 const elements=sortedNodes.map(n=>({data:{id:n.id,label:(n.id.split("/").pop()||n.id),fullPath:n.id,role:n.role||n.kind||"Source",symbols:n.symbols||[],kind:n.kind||"SOURCE_FILE",subsystem:subsystemByFile.get(n.id)||"UNASSIGNED"},position:presetPositions[n.id]}));
 sortedEdges.forEach((e,i)=>{if(e.from&&e.to&&nodeMap.has(e.from)&&nodeMap.has(e.to))elements.push({data:{id:`edge-${i}`,source:e.from,target:e.to,label:e.type||"depends on",confidence:e.confidence||"UNKNOWN",evidence:e.evidence||[],evidence_records:e.evidence_records||[]}});});
 if(explorerCy)explorerCy.destroy();
 const container=$("dependency-graph");
 explorerCy=window.cytoscape({
  container,elements,
  // Fixed renderer pixel ratio avoids embedded-browser hit-test drift.
  pixelRatio:1,
  layout:hasSavedLayout?{name:"preset",fit:true,padding:44}:{name:"cose",randomize:false,animate:false,fit:true,padding:44,nodeRepulsion:12000,idealEdgeLength:145,gravity:.18,numIter:700},
  minZoom:.2,maxZoom:3,wheelSensitivity:.15,boxSelectionEnabled:false,
  style:[
   {selector:"node",style:{"label":"data(label)","font-size":10,"text-wrap":"ellipsis","text-max-width":125,"text-valign":"bottom","text-margin-y":8,"color":"#343b32","background-color":"#17451f","border-width":2,"border-color":"#a4863d","width":38,"height":38,"overlay-opacity":0,"text-background-opacity":0}},
   {selector:'node[kind = "UNRESOLVED_REFERENCE"]',style:{"background-color":"#b5a27a","border-style":"dashed","border-color":"#806d43"}},
   {selector:"edge",style:{"width":1.5,"line-color":"#b6b1a3","target-arrow-color":"#a4863d","target-arrow-shape":"triangle","curve-style":"bezier","arrow-scale":.9,"opacity":.85}},
   {selector:"node:selected",style:{"border-width":4,"border-color":"#bd9136","background-color":"#286536","overlay-color":"#bd9136","overlay-opacity":.12,"overlay-padding":8}},
   {selector:"node.neighbour",style:{"border-width":3,"border-color":"#bd9136"}},
   {selector:"edge.highlight-edge",style:{"width":3,"line-color":"#bd9136","target-arrow-color":"#bd9136","opacity":1}},
   {selector:".filtered-out",style:{"display":"none"}}
  ]
 });
 const showNodeDetail=async node=>{
  const selectionToken=++graphSelectionToken;
  const n=node.data(), connected=node.neighborhood("node").map(x=>x.data("fullPath"));
  const group=subsystems.find(g=>g.id===n.subsystem);
  const evidenceRows=node.connectedEdges().map(edge=>{const d=edge.data();return (d.evidence_records||[]).map(ev=>`${esc(ev.source_path||d.source)}${ev.line?`:${ev.line}`:""} — ${esc(ev.declaration||d.label)}`)}).flat();
  explorerCy.elements().removeClass("neighbour highlight-edge");
  node.neighborhood("node").addClass("neighbour");node.connectedEdges().addClass("highlight-edge");
  const chips=connected.length?`<div class="graph-connections"><b>Connected files:</b>${connected.map(x=>`<span class="graph-chip">${esc(x)}</span>`).join("")}</div>`:'<div class="evidence-meta">No direct neighbours detected.</div>';
  $("graph-detail").innerHTML=`<strong>${esc(n.fullPath)}</strong><br>Role: ${esc(n.role)} · Kind: ${esc(n.kind)}<br>Subsystem: ${esc(group?.name||"Unassigned")}<br>Symbols: ${esc((n.symbols||[]).join(", ")||"None extracted")}<br>${chips}<div class="graph-evidence"><b>Relationship evidence</b>${evidenceRows.length?evidenceRows.map(x=>`<div>${x}</div>`).join(""):'<div>No line-level evidence attached to adjacent edges.</div>'}</div><div class="graph-impact" id="graph-impact"><b>Change impact</b><div>Calculating dependent files…</div></div><span class="evidence-meta">Static evidence only. This is not a runtime call trace.</span>`;
  try{const impact=await api("/api/impact",{method:"POST",body:JSON.stringify({path:n.fullPath})});if(selectionToken!==graphSelectionToken)return;const panel=$("graph-impact");if(panel){const pathRows=Object.entries(impact.impact_paths||{}).map(([file,path])=>`<li><b>${esc(file)}</b><br><span class="impact-path">${path.map(esc).join(" → ")}</span></li>`);panel.innerHTML=`<b>Change impact · ${impact.dependent_count} dependent file(s)</b><div class="impact-columns"><div><b>Direct dependents (${impact.direct_dependents.length})</b>${impact.direct_dependents.length?`<ul>${impact.direct_dependents.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`:'<p>None detected</p>'}</div><div><b>Direct dependencies (${impact.direct_dependencies.length})</b>${impact.direct_dependencies.length?`<ul>${impact.direct_dependencies.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`:'<p>None detected</p>'}</div></div><details><summary>Transitive impact paths</summary>${pathRows.length?`<ul>${pathRows.join("")}</ul>`:'<p>No transitive dependents detected.</p>'}</details><small>${esc(impact.note)}</small>`;}}catch(err){if(selectionToken!==graphSelectionToken)return;const panel=$("graph-impact");if(panel)panel.textContent=`Impact unavailable: ${err.message}`;}
 };
 explorerCy.on("tap","node",ev=>showNodeDetail(ev.target));
 explorerCy.on("tap","edge",ev=>{const e=ev.target.data();explorerCy.elements().removeClass("neighbour highlight-edge");ev.target.addClass("highlight-edge");$("graph-detail").innerHTML=`<strong>${esc(e.source)} → ${esc(e.target)}</strong><br>Relationship: ${esc(e.label)} · Confidence: ${esc(e.confidence)}<br>Evidence: ${esc((e.evidence||[]).join("; ")||"No textual evidence supplied")}<br><span class="evidence-meta">This is a statically inferred relationship, not runtime proof.</span>`;});
 explorerCy.on("tap",ev=>{if(ev.target===explorerCy){explorerCy.elements().removeClass("neighbour highlight-edge");$("graph-detail").textContent="Select a node or edge to inspect its evidence.";}});
 // Persist user-adjusted node positions so a reload does not reshuffle the graph.
 const saveGraphPositions=()=>{if(!explorerCy||explorerCy.destroyed())return;const positions={};explorerCy.nodes().forEach(n=>{const p=n.position();positions[n.id()]={x:p.x,y:p.y};});try{localStorage.setItem(layoutKey,JSON.stringify(positions));}catch{}};
 explorerCy.on("dragfree", "node", saveGraphPositions);
 explorerCy.on("layoutstop", saveGraphPositions);
 explorerGraphSignature=signature;
 // Resize without changing camera position; filtering must not re-layout the graph.
 const resizeGraph=()=>{if(explorerCy&&!explorerCy.destroyed())explorerCy.resize();};
 if(window.ResizeObserver){const ro=new ResizeObserver(()=>{if(explorerCy&&!explorerCy.destroyed())explorerCy.resize();});ro.observe(container);container._graphResizeObserver?.disconnect();container._graphResizeObserver=ro;}
 requestAnimationFrame(()=>{resizeGraph();});
 const applyGraphFilters=()=>{
  if(!explorerCy)return;
  const query=($("graph-search").value||"").trim().toLowerCase(),kind=$("graph-kind-filter").value,subsystem=$("graph-subsystem-filter").value;
  explorerCy.nodes().forEach(node=>{
   const d=node.data(),matchesText=!query||d.fullPath.toLowerCase().includes(query)||d.role.toLowerCase().includes(query)||(d.symbols||[]).some(x=>String(x).toLowerCase().includes(query));
   const matchesKind=kind==="ALL"||d.kind===kind;
   const matchesSubsystem=subsystem==="ALL"||d.subsystem===subsystem;
   node.toggleClass("filtered-out",!(matchesText&&matchesKind&&matchesSubsystem));
  });
  explorerCy.edges().forEach(edge=>edge.toggleClass("filtered-out",edge.source().hasClass("filtered-out")||edge.target().hasClass("filtered-out")));
  const visible=explorerCy.elements().not(".filtered-out");
  $("graph-detail").textContent=query||kind!=="ALL"||subsystem!=="ALL"?`${visible.nodes().length} visible node(s). Filters hide items without changing the graph layout or zoom. Select a node to inspect its relationships.`:"Select a node or edge to inspect its evidence.";
 };
 $("graph-search").oninput=applyGraphFilters;$("graph-kind-filter").onchange=applyGraphFilters;$("graph-subsystem-filter").onchange=applyGraphFilters;
 $("graph-fit").onclick=()=>{const visible=explorerCy.elements().not(".filtered-out");if(visible.length)explorerCy.fit(visible,36);};
 $("graph-reset").onclick=()=>{$("graph-search").value="";$("graph-kind-filter").value="ALL";$("graph-subsystem-filter").value="ALL";explorerCy.elements().removeClass("filtered-out neighbour highlight-edge");explorerCy.nodes().unselect();explorerCy.fit(explorerCy.elements(),44);$("graph-detail").textContent="Select a node or edge to inspect its evidence.";};
}
async function loadVisualExplorer(){
 const b=$("explorer-load");b.disabled=true;b.textContent="Loading analysis…";
 try{
  const [deps,schema,coverage]=await Promise.all([
   api("/api/dependencies",{method:"POST",body:JSON.stringify({})}),
   api("/api/schema",{method:"POST",body:JSON.stringify({})}),
   api("/api/coverage")
  ]);
  renderDependencyGraph(deps);renderSchemaDashboard(schema,deps);renderPhpStructure(deps.nodes||[]);
  const inv=coverage.inventory||{}, php=coverage.php_analysis||{}, dep=coverage.dependencies||{};
  $("explorer-metrics").innerHTML=[
   explorerMetric("REPOSITORY FILES",inv.files||0),explorerMetric("PHP FILES ANALYSED",php.analysed||0),
   explorerMetric("AST PARSED",php.ast_parsed||0),explorerMetric("DEPENDENCY EDGES",dep.edge_count||0)
  ].join("");
  $("explorer-dependency-raw").textContent=JSON.stringify(deps,null,2);
  $("explorer-schema-raw").textContent=JSON.stringify(schema,null,2);
  $("explorer-status").textContent="Loaded from current repository analysis. Static evidence; review required.";
 }catch(err){$("explorer-status").textContent=err.message;}
 finally{b.disabled=false;b.innerHTML='Refresh visual analysis <span>↻</span>';}
}
$("explorer-load").addEventListener("click",loadVisualExplorer);

/* ---- 04 Controlled MERN generation ---- */
let genPreview=null;
function genReady(){$("gen-button").disabled=!(genPreview&&$("gen-reviewer").value.trim()&&$("gen-reason").value.trim()&&(!genPreview.high_risk_flags_requiring_acknowledgement.length||$("gen-ack").checked));}
async function refreshGenStatus(){try{const st=await api("/api/generate/status");message("gen-status",st.enabled?"Generation is enabled. Every run still needs a fingerprint-bound human approval.":st.instructions,st.enabled?"success":"error");}catch(e){message("gen-status",e.message,"error");}}
$("gen-preview-button").addEventListener("click",async()=>{
 const b=$("gen-preview-button");b.disabled=true;genPreview=null;genReady();$("gen-ack-row").hidden=true;$("gen-ack").checked=false;
 try{const d=await api("/api/generate/preview",{method:"POST",body:"{}"});genPreview=d;const risks=d.high_risk_flags_requiring_acknowledgement;
  message("gen-preview",d.contracts.length===0?`0 API contract(s) found, so there is nothing to generate. This project has no API routes (web-only routes such as Blade pages are excluded). Scan a Laravel project that defines routes in routes/api.php, for example examples/laravel_blog_fixture.`:`${d.contracts.length} API contract(s); fingerprint ${d.source_fingerprint.slice(0,16)}…; ${risks.length} HIGH-severity finding(s)${risks.length?": "+risks.join(", "):""}.`,d.contracts.length===0?"error":(risks.length?"error":"success"));
  $("gen-ack-row").hidden=!risks.length;message("gen-message","Fill in reviewer and reason, then generate.");}
 catch(e){message("gen-preview",e.message,"error");}finally{b.disabled=false;genReady();}});
for(const id of ["gen-reviewer","gen-reason","gen-ack"])$(id).addEventListener("input",genReady);
$("gen-button").addEventListener("click",async()=>{
 if(!window.confirm("Generate the project files for review? This approval is bound to the previewed analysis. Nothing is built, run or deployed."))return;
 const b=$("gen-button");b.disabled=true;$("gen-output").hidden=true;message("gen-message","Generating and verifying…");
 const approval={reviewer:$("gen-reviewer").value.trim(),reason:$("gen-reason").value.trim(),source_fingerprint:genPreview.source_fingerprint,approve_all:true,
  acknowledged_risks:$("gen-ack").checked?genPreview.high_risk_flags_requiring_acknowledgement:[]};
 try{const d=await api("/api/generate",{method:"POST",body:JSON.stringify({project_name:$("gen-name").value.trim(),approval})});
  const pm=d.parity?.metrics;const lines=[`Output: ${d.output_directory}`,`Implemented: ${d.counts.IMPLEMENT}   Stubbed (501): ${d.counts.STUB}   Excluded: ${d.counts.EXCLUDE}`,
   pm?`Static parity of generated server: equivalent ${pm.verified_equivalent}, mismatch ${pm.verified_mismatch}, partial ${pm.partially_verified}, not implemented ${pm.not_implemented}, unverified ${pm.unverified} of ${pm.total_source_contracts}`:"Parity not available",
   "","Plan:",...Object.entries(d.plan).filter(([,p])=>p.action!=="IMPLEMENT").map(([id,p])=>`  ${p.action} ${id}: ${p.reason}`),"","Read MIGRATION_REPORT.md and DEPLOYMENT.md in the output directory before using anything. Static parity is not proof of equivalence."];
  $("gen-output").textContent=lines.join("\n");$("gen-output").hidden=false;message("gen-message","Generated for human review. Nothing was built, executed or deployed.","success");}
 catch(e){message("gen-message",e.message,"error");}finally{genReady();}});
refreshGenStatus();
