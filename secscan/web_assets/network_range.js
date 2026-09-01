(()=>{
  const scanner=$("scanner");
  const form=$("scan-form");
  const authorization=$("network-range-authorization");
  const authorized=$("network-range-authorized");
  const target=$("target");
  const targetHelp=$("target-help");

  function updateRangeUi(){
    const active=scanner.value==="network-range";
    authorization.classList.toggle("hidden",!active);
    if(!active)authorized.checked=false;
    if(active){
      target.placeholder="192.0.2.0/30";
      targetHelp.textContent="Literal IPv4/IPv6 address or CIDR only; at most 16 scannable hosts. Targets run sequentially.";
    }
  }

  scanner.addEventListener("change",()=>setTimeout(updateRangeUi,0));
  updateRangeUi();

  form.addEventListener("submit",async event=>{
    if(scanner.value!=="network-range")return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if(!authorized.checked){
      flash("Confirm that you are authorized to security-test every host in this network range.",true);
      return;
    }
    const payload={
      target:target.value.trim(),
      timeout:Number($("timeout").value),
      network_authorized:true,
    };
    if($("fail-on").value)payload.fail_on=$("fail-on").value;
    if($("policy").value.trim())payload.policy=$("policy").value.trim();
    if($("baseline").value.trim())payload.baseline=$("baseline").value.trim();
    try{
      const job=await api("/api/v1/network-range-jobs",{method:"POST",body:JSON.stringify(payload)});
      flash("Bounded network-range assessment queued successfully.");
      form.reset();
      $("timeout").value="600";
      scanner.dispatchEvent(new Event("change"));
      await loadJobs();
      openJob(job.id);
    }catch(error){
      flash(error.message,true);
    }
  },true);
})();
