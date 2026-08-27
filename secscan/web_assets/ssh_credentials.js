let sshCredentialProfiles=[];
let sshCredentialStoreConfigured=null;
let sshTrustedHosts=[];

function renderSshCredentialProfiles(){
  const list=$("ssh-credential-list");
  if(!list)return;
  if(sshCredentialStoreConfigured===false){
    list.innerHTML='<div class="flash error">Encrypted credential storage is disabled. Set SECSCAN_CREDENTIAL_KEY in the service environment and restart secscan.</div>';
    return;
  }
  if(!sshCredentialProfiles.length){
    list.innerHTML='<div class="empty">No SSH credential profiles yet.</div>';
    return;
  }
  list.innerHTML=`<div style="overflow:auto"><table class="scan-table"><thead><tr><th>Name</th><th>Username</th><th>Default</th><th></th></tr></thead><tbody>${sshCredentialProfiles.map(profile=>`<tr><td><strong>${escapeHtml(profile.name)}</strong></td><td>${escapeHtml(profile.username)}</td><td>${profile.is_default?'Yes':'No'}</td><td><div class="actions">${profile.is_default?'':`<button class="secondary" data-ssh-default="${escapeHtml(profile.id)}">Make default</button>`}<button class="secondary" data-ssh-delete="${escapeHtml(profile.id)}">Delete</button></div></td></tr>`).join("")}</tbody></table></div>`;
  list.querySelectorAll("[data-ssh-default]").forEach(button=>button.addEventListener("click",()=>setDefaultSshCredential(button.dataset.sshDefault)));
  list.querySelectorAll("[data-ssh-delete]").forEach(button=>button.addEventListener("click",()=>deleteSshCredential(button.dataset.sshDelete)));
}

function refreshLinuxHostProfileSelect(){
  const select=$("linux-host-profile");
  if(!select)return;
  const current=select.value;
  select.innerHTML='<option value="">Default / server fallback</option>'+sshCredentialProfiles.map(profile=>`<option value="${escapeHtml(profile.id)}">${escapeHtml(profile.name)}${profile.is_default?' (default)':''} — ${escapeHtml(profile.username)}</option>`).join("");
  if([...select.options].some(option=>option.value===current))select.value=current;
}

async function loadSshCredentials(){
  try{
    const capability=await api("/api/v1/ssh-credentials/capability");
    sshCredentialStoreConfigured=Boolean(capability.configured);
    sshCredentialProfiles=sshCredentialStoreConfigured?await api("/api/v1/ssh-credentials"):[];
  }catch(error){
    sshCredentialProfiles=[];
    sshCredentialStoreConfigured=null;
    flash(error.message,true);
  }
  renderSshCredentialProfiles();
  refreshLinuxHostProfileSelect();
}

async function setDefaultSshCredential(profileId){
  try{
    await api(`/api/v1/ssh-credentials/${encodeURIComponent(profileId)}/default`,{method:"PUT"});
    flash("Default SSH credential profile updated.");
    await loadSshCredentials();
  }catch(error){flash(error.message,true)}
}

async function deleteSshCredential(profileId){
  const profile=sshCredentialProfiles.find(item=>item.id===profileId);
  if(!profile||!confirm(`Delete SSH credential profile “${profile.name}”? Host bindings using it will also be removed.`))return;
  try{
    await api(`/api/v1/ssh-credentials/${encodeURIComponent(profileId)}`,{method:"DELETE"});
    flash("SSH credential profile deleted.");
    await loadSshCredentials();
    await loadLinuxHostCapability();
  }catch(error){flash(error.message,true)}
}

function ensureSshTrustPanel(){
  const section=$("ssh-credentials");
  if(!section||$("ssh-host-trust-panel"))return;
  section.insertAdjacentHTML("beforeend",`<div id="ssh-host-trust-panel" class="panel" style="margin-top:1rem"><div class="panel-heading"><div><p class="eyebrow">SSH identity</p><h2>Trusted host keys</h2></div></div><p class="muted">Discovering a key does not trust it. Compare the SHA-256 fingerprint with an independent trusted source before approving it. Changed keys are never accepted automatically.</p><form id="ssh-host-discovery-form"><div class="form-grid"><label>Host<input id="ssh-trust-host" required placeholder="server.example.com"></label><label>SSH port<input id="ssh-trust-port" type="number" min="1" max="65535" value="22" required></label></div><div class="actions"><button class="primary" type="submit">Discover host key</button></div></form><div id="ssh-host-discovery-results"></div><div class="panel-heading" style="margin-top:1rem"><div><p class="eyebrow">Approved</p><h3>Stored trust</h3></div></div><div id="ssh-host-trust-list"><div class="empty">Loading trusted hosts…</div></div></div>`);
  $("ssh-host-discovery-form").addEventListener("submit",discoverSshHostKeys);
}

function renderTrustedHosts(){
  const list=$("ssh-host-trust-list");
  if(!list)return;
  if(!sshTrustedHosts.length){list.innerHTML='<div class="empty">No approved SSH host keys yet.</div>';return;}
  list.innerHTML=`<div style="overflow:auto"><table class="scan-table"><thead><tr><th>Host</th><th>Key</th><th>SHA-256 fingerprint</th><th></th></tr></thead><tbody>${sshTrustedHosts.map(item=>`<tr><td><strong>${escapeHtml(item.host)}</strong>:${item.port}</td><td>${escapeHtml(item.key_type)}</td><td><code>${escapeHtml(item.fingerprint)}</code></td><td><button class="secondary" data-trust-delete-host="${escapeHtml(item.host)}" data-trust-delete-port="${item.port}">Remove trust</button></td></tr>`).join("")}</tbody></table></div>`;
  list.querySelectorAll("[data-trust-delete-host]").forEach(button=>button.addEventListener("click",()=>deleteSshHostTrust(button.dataset.trustDeleteHost,button.dataset.trustDeletePort)));
}

async function loadSshHostTrust(){
  ensureSshTrustPanel();
  try{
    const me=await api("/api/v1/auth/me");
    if(me.role!=="admin"){
      const panel=$("ssh-host-trust-panel");
      if(panel)panel.classList.add("hidden");
      return;
    }
    sshTrustedHosts=await api("/api/v1/admin/ssh-host-trust");
    renderTrustedHosts();
  }catch(error){
    const panel=$("ssh-host-trust-panel");
    if(panel)panel.classList.add("hidden");
  }
}

async function discoverSshHostKeys(event){
  event.preventDefault();
  const host=$("ssh-trust-host").value.trim();
  const port=Number($("ssh-trust-port").value||22);
  const results=$("ssh-host-discovery-results");
  results.innerHTML='<div class="empty">Discovering presented SSH keys…</div>';
  try{
    const response=await api("/api/v1/admin/ssh-host-trust/discover",{method:"POST",body:JSON.stringify({host,port})});
    const approved=response.approved;
    results.innerHTML=`${approved?`<div class="flash">Currently approved: <code>${escapeHtml(approved.fingerprint)}</code></div>`:''}<div style="overflow:auto"><table class="scan-table"><thead><tr><th>Key type</th><th>Presented SHA-256 fingerprint</th><th></th></tr></thead><tbody>${response.discovered.map(item=>`<tr><td>${escapeHtml(item.key_type)}</td><td><code>${escapeHtml(item.fingerprint)}</code></td><td><button class="secondary" data-trust-approve="${escapeHtml(item.id)}">Approve this exact key</button></td></tr>`).join("")}</tbody></table></div><p class="muted">Verify the fingerprint out-of-band before approval. Approval replaces existing trust only after this explicit action.</p>`;
    results.querySelectorAll("[data-trust-approve]").forEach(button=>button.addEventListener("click",()=>approveSshHostKey(button.dataset.trustApprove)));
  }catch(error){results.innerHTML=`<div class="flash error">${escapeHtml(error.message)}</div>`;}
}

async function approveSshHostKey(discoveryId){
  if(!confirm("Approve this exact SSH host key? Verify its SHA-256 fingerprint against an independent trusted source first."))return;
  try{
    const trusted=await api("/api/v1/admin/ssh-host-trust/approve",{method:"POST",body:JSON.stringify({discovery_id:discoveryId})});
    flash(`Approved SSH host key for ${trusted.host}:${trusted.port}.`);
    $("ssh-host-discovery-results").innerHTML="";
    await loadSshHostTrust();
  }catch(error){flash(error.message,true)}
}

async function deleteSshHostTrust(host,port){
  if(!confirm(`Remove approved SSH host key for ${host}:${port}? Future scans will fail strict host-key verification unless compatible known_hosts data is available.`))return;
  try{
    await api(`/api/v1/admin/ssh-host-trust/${encodeURIComponent(host)}/${encodeURIComponent(port)}`,{method:"DELETE"});
    flash("SSH host trust removed.");
    await loadSshHostTrust();
  }catch(error){flash(error.message,true)}
}

$("ssh-credential-form").addEventListener("submit",async event=>{
  event.preventDefault();
  const payload={
    name:$("ssh-profile-name").value.trim(),
    username:$("ssh-profile-user").value.trim(),
    private_key:$("ssh-profile-key").value,
    known_hosts:$("ssh-profile-known-hosts").value,
    is_default:$("ssh-profile-default").checked,
  };
  try{
    await api("/api/v1/ssh-credentials",{method:"POST",body:JSON.stringify(payload)});
    event.target.reset();
    flash("SSH credential profile encrypted and saved.");
    await loadSshCredentials();
    await loadLinuxHostCapability();
  }catch(error){flash(error.message,true)}
});

loadSshCredentials();
loadSshHostTrust();
