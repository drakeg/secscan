let sshCredentialProfiles=[];
let sshCredentialStoreConfigured=null;

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
