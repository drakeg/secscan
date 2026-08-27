const linuxHostOptions=$("linux-host-options");
const linuxHostAuthorized=$("linux-host-authorized");
let linuxHostConfigured=null;

async function loadLinuxHostCapability(){
  try{
    const capability=await api("/api/v1/linux-host-capability");
    linuxHostConfigured=Boolean(capability.configured);
  }catch{
    linuxHostConfigured=null;
  }
  updateLinuxHostUi();
}

async function resolveLinuxHostCredential(){
  if($("scanner").value!=="linux-host"||!sshCredentialStoreConfigured)return;
  const target=$("target").value.trim();
  if(!target)return;
  try{
    const resolved=await api(`/api/v1/ssh-credentials/resolve?host=${encodeURIComponent(target)}`);
    if(resolved.profile&&$("linux-host-profile"))$("linux-host-profile").value=resolved.profile.id;
  }catch{}
}

function updateLinuxHostUi(){
  const isLinuxHost=$("scanner").value==="linux-host";
  if(linuxHostOptions)linuxHostOptions.classList.toggle("hidden",!isLinuxHost);
  if(linuxHostAuthorized&&!isLinuxHost)linuxHostAuthorized.checked=false;
  if(!isLinuxHost)return;
  $("target").placeholder="server.example.com or 192.0.2.10";
  const help=$("target-help");
  if(help){
    if(linuxHostConfigured===false){
      help.textContent="Authenticated Linux assessment is not configured. Add an encrypted SSH credential profile or configure the server-side SSH fallback.";
    }else{
      help.textContent="Authenticated, read-only Linux posture assessment over SSH. Select a saved credential profile or use the configured default.";
    }
  }
}

$("scanner").addEventListener("change",updateLinuxHostUi);
$("target").addEventListener("blur",resolveLinuxHostCredential);
$("scan-form").addEventListener("submit",async event=>{
  if($("scanner").value!=="linux-host")return;
  event.preventDefault();
  event.stopImmediatePropagation();
  if(!linuxHostAuthorized.checked){
    flash("Confirm that you are authorized to perform an authenticated assessment of this Linux host.",true);
    return;
  }
  if(linuxHostConfigured===false){
    flash("Linux host scanning is not configured on this secscan service.",true);
    return;
  }
  const payload={
    target:$("target").value.trim(),
    timeout:Number($("timeout").value),
    linux_host_authorized:true,
    ssh_port:Number($("linux-host-port").value||22),
    remember_credential:$("linux-host-remember").checked,
  };
  if($("linux-host-profile").value)payload.credential_profile_id=$("linux-host-profile").value;
  if($("fail-on").value)payload.fail_on=$("fail-on").value;
  if($("policy").value.trim())payload.policy=$("policy").value.trim();
  if($("baseline").value.trim())payload.baseline=$("baseline").value.trim();
  try{
    const job=await api("/api/v1/linux-host-jobs",{method:"POST",body:JSON.stringify(payload)});
    flash("Authenticated Linux host assessment queued successfully.");
    event.target.reset();
    $("timeout").value="600";
    $("linux-host-port").value="22";
    $("scanner").dispatchEvent(new Event("change"));
    await loadJobs();
    openJob(job.id);
  }catch(error){
    flash(error.message,true);
  }
},true);

loadLinuxHostCapability();
updateLinuxHostUi();
