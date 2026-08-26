const linuxHostAuthorization=$("linux-host-authorization");
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

function updateLinuxHostUi(){
  const isLinuxHost=$("scanner").value==="linux-host";
  if(linuxHostAuthorization)linuxHostAuthorization.classList.toggle("hidden",!isLinuxHost);
  if(linuxHostAuthorized&&!isLinuxHost)linuxHostAuthorized.checked=false;
  if(!isLinuxHost)return;
  $("target").placeholder="server.example.com or 192.0.2.10";
  const help=$("target-help");
  if(help){
    if(linuxHostConfigured===false){
      help.textContent="Authenticated Linux assessment is not configured on this secscan service. Configure the server-side SSH user, key, known_hosts, and read-only credential mount first.";
    }else{
      help.textContent="Authenticated, read-only Linux posture assessment over SSH. Credentials stay server-side and are never submitted by the browser.";
    }
  }
}

$("scanner").addEventListener("change",updateLinuxHostUi);
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
  };
  if($("fail-on").value)payload.fail_on=$("fail-on").value;
  if($("policy").value.trim())payload.policy=$("policy").value.trim();
  if($("baseline").value.trim())payload.baseline=$("baseline").value.trim();
  try{
    const job=await api("/api/v1/linux-host-jobs",{method:"POST",body:JSON.stringify(payload)});
    flash("Authenticated Linux host assessment queued successfully.");
    event.target.reset();
    $("timeout").value="600";
    $("scanner").dispatchEvent(new Event("change"));
    await loadJobs();
    openJob(job.id);
  }catch(error){
    flash(error.message,true);
  }
},true);

loadLinuxHostCapability();
updateLinuxHostUi();
