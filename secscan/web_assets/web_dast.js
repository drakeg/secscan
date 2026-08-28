const webDastScanner = document.getElementById("scanner");
const webDastAuthorization = document.getElementById("web-dast-authorization");
const webDastAuthorized = document.getElementById("web-dast-authorized");
const webDastTarget = document.getElementById("target");
const webDastForm = document.getElementById("scan-form");

function syncWebDastControls() {
  const active = webDastScanner?.value === "web-dast";
  webDastAuthorization?.classList.toggle("hidden", !active);
  if (!active && webDastAuthorized) webDastAuthorized.checked = false;
  if (active && webDastTarget) webDastTarget.placeholder = "https://app.example.com/";
}

webDastScanner?.addEventListener("change", syncWebDastControls);

webDastForm?.addEventListener(
  "submit",
  async (event) => {
    if (webDastScanner?.value !== "web-dast") return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (!webDastAuthorized?.checked) {
      flash("Confirm that you own this application or have explicit authorization to security-test it.", true);
      return;
    }
    const payload = {
      scanner: "web-dast",
      target: webDastTarget.value.trim(),
      timeout: Number(document.getElementById("timeout").value),
      web_authorized: true,
    };
    const failOn = document.getElementById("fail-on").value;
    const policy = document.getElementById("policy").value.trim();
    const baseline = document.getElementById("baseline").value.trim();
    if (failOn) payload.fail_on = failOn;
    if (policy) payload.policy = policy;
    if (baseline) payload.baseline = baseline;
    try {
      const job = await api("/api/v1/jobs", {method: "POST", body: JSON.stringify(payload)});
      flash("Web application assessment queued successfully.");
      webDastForm.reset();
      document.getElementById("timeout").value = "600";
      syncWebDastControls();
      await loadJobs();
      openJob(job.id);
    } catch (error) {
      flash(error.message, true);
    }
  },
  true,
);

syncWebDastControls();
