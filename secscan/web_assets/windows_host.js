const windowsHostOptions=$("windows-host-options");
const windowsHostAuthorized=$("windows-host-authorized");
let windowsHostConfigured=null;
let windowsHostProfiles=[];

async function loadWindowsHostProfiles(){
  const select=$("windows-host-profile");
  if(!select)return;
  try{
    const capability=await api("/api/v1/ssh-credentials/capability");
    windowsHostProfiles=capability.configured?await api("/api/v1/ssh-credentials"):[];
  }catch{
    windowsHostProfiles=[];
  }
  const current=select.value;
  select.innerHTML='<option value="">Default / server fallback</option>'+windowsHostProfiles.map(profile=>`<option value="${escapeHtml(profile.id)}">${escapeHtml(profile.name)}${profile.is_default?' (default)':''} — ${escapeHtml(profile.username)}</option>`).join("");
  if([...select.options].some(option=>option.value===current))select.value=current;
}

async function loadWindowsHostCapability(){
  try{
    const capability=await api("/api/v1/windows-host-capability");
    windowsHostConfigured=Boolean(capability.configured);
  }catch{
    windowsHostConfigured=null;
  }
  updateWindowsHostUi();
}

async function resolveWindowsHostCredential(){
  if($("scanner").value!=="windows-host")return;
  const target=$("target").value.trim();
  if(!target)return;
  try{
    const resolved=await api(`/api/v1/ssh-credentials/resolve?host=${encodeURIComponent(target)}`);
    if(resolved.profile&&$("windows-host-profile"))$("windows-host-profile").value=resolved.profile.id;
  }catch{}
}

function updateWindowsHostUi(){
  const isWindowsHost=$("scanner").value==="windows-host";
  if(windowsHostOptions)windowsHostOptions.classList.toggle("hidden",!isWindowsHost);
  if(windowsHostAuthorized&&!isWindowsHost)windowsHostAuthorized.checked=false;
  if(!isWindowsHost)return;
  $("target").placeholder="windows-server.example.com or 192.0.2.20";
  const help=$("target-help");
  if(help){
    if(windowsHostConfigured===false){
      help.textContent="Authenticated Windows assessment is not configured. Add an encrypted SSH credential profile or configure the server-side SSH fallback.";
    }else{
      help.textContent="Read-only Windows posture and installed-software assessment over strict key-only OpenSSH. Optionally override the profile username for DOMAIN\\user.";
    }
  }
}

$("scanner").addEventListener("change",updateWindowsHostUi);
$("target").addEventListener("blur",resolveWindowsHostCredential);
$("scan-form").addEventListener("submit",async event=>{
  if($("scanner").value!=="windows-host")return;
  event.preventDefault();
  event.stopImmediatePropagation();
  if(!windowsHostAuthorized.checked){
    flash("Confirm that you are authorized to perform an authenticated assessment of this Windows host.",true);
    return;
  }
  if(windowsHostConfigured===false){
    flash("Windows host scanning is not configured on this secscan service.",true);
    return;
  }
  const payload={
    target:$("target").value.trim(),
    timeout:Number($("timeout").value),
    windows_host_authorized:true,
    ssh_port:Number($("windows-host-port").value||22),
    remember_credential:$("windows-host-remember").checked,
  };
  if($("windows-host-profile").value)payload.credential_profile_id=$("windows-host-profile").value;
  if($("windows-host-user").value.trim())payload.ssh_username=$("windows-host-user").value.trim();
  if($("fail-on").value)payload.fail_on=$("fail-on").value;
  if($("policy").value.trim())payload.policy=$("policy").value.trim();
  if($("baseline").value.trim())payload.baseline=$("baseline").value.trim();
  try{
    const job=await api("/api/v1/windows-host-jobs",{method:"POST",body:JSON.stringify(payload)});
    flash("Authenticated Windows host assessment queued successfully.");
    event.target.reset();
    $("timeout").value="600";
    $("windows-host-port").value="22";
    $("scanner").dispatchEvent(new Event("change"));
    await loadJobs();
    openJob(job.id);
  }catch(error){
    flash(error.message,true);
  }
},true);

loadWindowsHostProfiles();
loadWindowsHostCapability();
updateWindowsHostUi();
