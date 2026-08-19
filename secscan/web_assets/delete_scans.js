let currentDeleteJobId=null;

function canDeleteStatus(status){return ["completed","failed","cancelled"].includes(String(status||""))}

async function deleteStoredScan(jobId,target){
  const label=target?` for ${target}`:"";
  if(!window.confirm(`Delete this stored scan${label}? This permanently removes its history and artifacts.`))return;
  try{
    await api(`/api/v1/jobs/${encodeURIComponent(jobId)}/history`,{method:"DELETE"});
    if(currentDeleteJobId===jobId){
      stopDetailPolling();
      currentDeleteJobId=null;
      showView("scans");
    }
    await loadJobs();
    flash("Scan deleted.");
  }catch(error){flash(error.message,true)}
}

function addRowDeleteButtons(root=document){
  root.querySelectorAll("[data-job-id]").forEach(link=>{
    const row=link.closest("tr");
    if(!row||row.querySelector("[data-delete-job-id]"))return;
    const job=state.jobs.find(item=>item.id===link.dataset.jobId);
    if(!job||!canDeleteStatus(job.status))return;
    const cell=link.closest("td");
    if(!cell)return;
    const button=document.createElement("button");
    button.type="button";
    button.className="delete-link";
    button.dataset.deleteJobId=job.id;
    button.textContent="Delete";
    button.addEventListener("click",event=>{
      event.preventDefault();
      event.stopPropagation();
      deleteStoredScan(job.id,job.target);
    });
    cell.append(" ",button);
  });
}

function addDetailDeleteButton(){
  if(!currentDeleteJobId)return;
  const job=state.jobs.find(item=>item.id===currentDeleteJobId);
  if(!job||!canDeleteStatus(job.status))return;
  const panel=document.querySelector("#job-content .panel");
  const heading=panel?.querySelector(".panel-heading");
  if(!heading||heading.querySelector("[data-delete-current-job]"))return;
  const button=document.createElement("button");
  button.type="button";
  button.className="danger";
  button.dataset.deleteCurrentJob="true";
  button.textContent="Delete scan";
  button.addEventListener("click",()=>deleteStoredScan(job.id,job.target));
  heading.appendChild(button);
}

const originalRenderJobs=renderJobs;
renderJobs=function(){originalRenderJobs();addRowDeleteButtons(document)};

const originalOpenJob=openJob;
openJob=async function(id,refresh=false){
  currentDeleteJobId=id;
  await originalOpenJob(id,refresh);
  addDetailDeleteButton();
};
