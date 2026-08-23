const severityCache=new Map();
const terminalStatuses=new Set(["completed","failed","cancelled"]);

function compactSeverityChips(counts){
  if(!counts)return'<span class="muted">—</span>';
  return `<div class="vuln-chips"><span class="vuln-chip critical">C ${counts.CRITICAL||0}</span><span class="vuln-chip high">H ${counts.HIGH||0}</span><span class="vuln-chip medium">M ${counts.MEDIUM||0}</span><span class="vuln-chip low">L ${counts.LOW||0}</span></div>`;
}

async function loadSeverityForJob(job){
  if(!terminalStatuses.has(job.status)||severityCache.has(job.id))return;
  try{
    const summary=await api(`/api/v1/jobs/${encodeURIComponent(job.id)}/summary`);
    severityCache.set(job.id,summary.severity||null);
  }catch{
    severityCache.set(job.id,null);
  }
}

async function hydrateSeverityCache(){
  await Promise.all(state.jobs.map(loadSeverityForJob));
}

function latestPostureJobs(){
  const seen=new Set();
  const current=[];
  for(const job of state.jobs){
    if(job.status!=="completed")continue;
    const counts=severityCache.get(job.id);
    if(!counts)continue;
    const key=`${job.scanner}:${job.target}`;
    if(seen.has(key))continue;
    seen.add(key);
    current.push({...job,counts});
  }
  return current;
}

function severityTotal(counts){return (counts.CRITICAL||0)+(counts.HIGH||0)+(counts.MEDIUM||0)+(counts.LOW||0)+(counts.UNKNOWN||0)}

function renderSecurityDashboard(){
  const current=latestPostureJobs();
  const totals={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
  current.forEach(job=>Object.keys(totals).forEach(key=>totals[key]+=Number(job.counts[key]||0)));
  [["vuln-critical","CRITICAL"],["vuln-high","HIGH"],["vuln-medium","MEDIUM"],["vuln-low","LOW"]].forEach(([id,key])=>{const node=$(id);if(node)node.textContent=totals[key]});

  const mix=$("severity-mix");
  if(mix){
    const total=Math.max(1,totals.CRITICAL+totals.HIGH+totals.MEDIUM+totals.LOW);
    const part=key=>Math.max(0,(totals[key]/total)*100);
    mix.innerHTML=`<div class="severity-summary-bar" aria-label="Current vulnerability severity distribution"><span class="bar-critical" style="width:${part("CRITICAL")}%"></span><span class="bar-high" style="width:${part("HIGH")}%"></span><span class="bar-medium" style="width:${part("MEDIUM")}%"></span><span class="bar-low" style="width:${part("LOW")}%"></span></div><div class="severity-legend"><span><i class="legend-dot bar-critical"></i>Critical ${totals.CRITICAL}</span><span><i class="legend-dot bar-high"></i>High ${totals.HIGH}</span><span><i class="legend-dot bar-medium"></i>Medium ${totals.MEDIUM}</span><span><i class="legend-dot bar-low"></i>Low ${totals.LOW}</span></div>`;
  }

  const priority=$("priority-targets");
  if(priority){
    const ranked=[...current].sort((a,b)=>(b.counts.CRITICAL-a.counts.CRITICAL)||(b.counts.HIGH-a.counts.HIGH)||(b.counts.MEDIUM-a.counts.MEDIUM)||(severityTotal(b.counts)-severityTotal(a.counts))).slice(0,8);
    if(!ranked.length){priority.innerHTML='<div class="empty">Complete a scan to see prioritized targets.</div>';return}
    priority.innerHTML=`<div class="priority-list">${ranked.map(job=>{const total=Math.max(1,severityTotal(job.counts));const width=key=>Math.max(0,(job.counts[key]||0)/total*100);return `<div class="priority-row"><div class="priority-target"><strong title="${escapeHtml(job.target)}">${escapeHtml(job.target)}</strong><small>${escapeHtml(job.scanner)}</small></div><div class="priority-bar" aria-label="${escapeHtml(job.target)} severity mix"><span class="bar-critical" style="width:${width("CRITICAL")}%"></span><span class="bar-high" style="width:${width("HIGH")}%"></span><span class="bar-medium" style="width:${width("MEDIUM")}%"></span><span class="bar-low" style="width:${width("LOW")}%"></span></div><div class="priority-counts">${compactSeverityChips(job.counts)}</div></div>`}).join("")}</div>`;
  }
}

scanTable=function(jobs){
  if(!jobs.length)return'<div class="empty">No scans yet. Run your first scan to get started.</div>';
  return `<div style="overflow:auto"><table class="scan-table"><thead><tr><th>Target</th><th>Scanner</th><th>Status</th><th>Vulnerabilities</th><th>Created</th><th></th></tr></thead><tbody>${jobs.map(job=>`<tr><td class="target-cell" title="${escapeHtml(job.target)}">${escapeHtml(job.target)}</td><td>${escapeHtml(job.scanner)}</td><td><span class="status ${escapeHtml(job.status)}">${escapeHtml(job.status)}</span></td><td class="vuln-cell">${terminalStatuses.has(job.status)?compactSeverityChips(severityCache.get(job.id)):'<span class="muted">Scanning…</span>'}</td><td>${escapeHtml(formatDate(job.created_at))}</td><td><a class="row-link" data-job-id="${escapeHtml(job.id)}">View</a></td></tr>`).join("")}</tbody></table></div>`;
};

const originalRenderJobsForDashboard=renderJobs;
renderJobs=function(){originalRenderJobsForDashboard();renderSecurityDashboard()};

async function refreshSecuritySummaries(){
  await hydrateSeverityCache();
  renderJobs();
}

const scannerSelect=$("scanner");
const targetHelp=$("target-help");
const networkAuthorization=$("network-authorization");
const networkAuthorized=$("network-authorized");
function updateTargetHelp(){
  const scanner=scannerSelect.value;
  const isNetwork=scanner==="network";
  const examples={image:"alpine:3.20",filesystem:"/workspace",sbom:"/workspace/build.cdx.json"};
  if(scanner==="repository"){
    $("target").placeholder="https://github.com/org/repository.git";
    if(targetHelp)targetHelp.textContent="Use a local path such as /workspace, or a public HTTPS GitHub, GitLab, Azure DevOps, or other Git repository URL.";
  }else if(isNetwork){
    $("target").placeholder="server.example.com or 192.0.2.10";
    if(targetHelp)targetHelp.textContent="Active assessment of one hostname or IP address using Nmap and Nuclei. Only scan systems you own or are explicitly authorized to test.";
  }else{
    $("target").placeholder=examples[scanner]||"scan target";
    if(targetHelp)targetHelp.textContent="";
  }
  if(networkAuthorization)networkAuthorization.classList.toggle("hidden",!isNetwork);
  if(networkAuthorized&&!isNetwork)networkAuthorized.checked=false;
}
scannerSelect.addEventListener("change",updateTargetHelp);
updateTargetHelp();

$("scan-form").addEventListener("submit",async event=>{
  if(scannerSelect.value!=="network")return;
  event.preventDefault();
  event.stopImmediatePropagation();
  if(!networkAuthorized?.checked){
    flash("Confirm that you are authorized to security-test this network target.",true);
    return;
  }
  const payload={scanner:"network",target:$("target").value.trim(),timeout:Number($("timeout").value),network_authorized:true};
  if($("fail-on").value)payload.fail_on=$("fail-on").value;
  if($("policy").value.trim())payload.policy=$("policy").value.trim();
  if($("baseline").value.trim())payload.baseline=$("baseline").value.trim();
  try{
    const job=await api("/api/v1/jobs",{method:"POST",body:JSON.stringify(payload)});
    flash("Network assessment queued successfully.");
    event.target.reset();
    $("timeout").value="600";
    updateTargetHelp();
    await loadJobs();
    openJob(job.id);
  }catch(error){
    flash(error.message,true);
  }
},true);

setTimeout(refreshSecuritySummaries,0);
setInterval(refreshSecuritySummaries,7000);
