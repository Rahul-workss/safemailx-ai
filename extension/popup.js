document.getElementById("scanBtn").addEventListener("click", async () => {

  let [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  startScanAnimation();

  chrome.scripting.executeScript(
    {
      target: { tabId: tab.id },
      func: extractEmailContent
    },
    async (results) => {

      if (!results || !results[0] || !results[0].result) {
        showError("Could not extract email content.");
        return;
      }

      let payload = results[0].result;

      try {

        let response = await fetch("http://127.0.0.1:8000/scan-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        let result = await response.json();

        showResult(tab.id, result);
        showPopupResult(result);

      } catch (error) {

        showError("API not reachable. Is the server running?");

      }

    }
  );

});


/* ── PDF download ── */

document.getElementById("downloadPdfBtn").addEventListener("click", async () => {

  try {

    let response = await fetch("http://127.0.0.1:8000/download-pdf");
    let data = await response.json();

    if (data.pdf) {
      let pdfUrl = "http://127.0.0.1:8000" + data.pdf;
      chrome.tabs.create({ url: pdfUrl });
    }

  } catch (err) {

    showError("Failed to download forensic report.");

  }

});


/* ── Scan animation ── */

const STEPS = [
  "Reading headers...",
  "Checking links...",
  "Scanning attachments...",
  "Analysing content..."
];

function startScanAnimation() {
  const btn      = document.getElementById("scanBtn");
  const btnText  = document.getElementById("btnText");
  const progWrap = document.getElementById("progress-wrap");
  const bar      = document.getElementById("progress-bar");
  const label    = document.getElementById("progress-label");
  const result   = document.getElementById("result");
  const pdfBtn   = document.getElementById("downloadPdfBtn");

  result.style.display = "none";
  result.classList.remove("visible", "safe", "threat", "error");
  pdfBtn.classList.remove("show");
  progWrap.style.display = "block";
  btn.disabled = true;
  btnText.textContent = "Scanning...";
  bar.style.width = "0%";

  resetShield();

  let step = 0;
  const tick = setInterval(() => {
    label.textContent = STEPS[step] || "";
    bar.style.width = ((step + 1) / (STEPS.length + 1) * 100) + "%";
    step++;
    if (step > STEPS.length) {
      clearInterval(tick);
      bar.style.width = "100%";
    }
  }, 520);
}


/* ── Show result in popup ── */

function showPopupResult(result) {
  const btn      = document.getElementById("scanBtn");
  const btnText  = document.getElementById("btnText");
  const progWrap = document.getElementById("progress-wrap");
  const el       = document.getElementById("result");
  const title    = document.getElementById("result-title");
  const desc     = document.getElementById("result-desc");
  const pdfBtn   = document.getElementById("downloadPdfBtn");
  const shieldWrap  = document.getElementById("shieldWrap");
  const shieldBody  = document.getElementById("shieldBody");
  const shieldCheck = document.getElementById("shieldCheck");
  const shieldX1    = document.getElementById("shieldX1");
  const shieldX2    = document.getElementById("shieldX2");

  const isSafe  = result.final_label !== "phishing";
  const rawScore = parseFloat(result.final_score);
  const score100 = Math.round(rawScore <= 1 ? rawScore * 100 : rawScore);

  progWrap.style.display = "none";
  btn.disabled = false;
  btnText.textContent = "Scan current email";

  el.className = "";
  el.style.display = "block";

  if (isSafe) {
    el.classList.add("safe");
    title.textContent = "No threats detected";
    desc.textContent  = "Threat score: " + score100 + "/100. This email appears safe.";
    shieldBody.setAttribute("fill", "#edf7e6");
    shieldBody.setAttribute("stroke", "#4caf50");
    shieldCheck.setAttribute("opacity", "1");
    shieldCheck.setAttribute("stroke", "#4caf50");
  } else {
    el.classList.add("threat");
    title.textContent = "Phishing detected";
    desc.textContent  = "Threat score: " + score100 + "/100. Exercise caution before clicking any links.";
    shieldBody.setAttribute("fill", "#fdecea");
    shieldBody.setAttribute("stroke", "#e53935");
    shieldX1.setAttribute("opacity", "1");
    shieldX2.setAttribute("opacity", "1");
  }

  requestAnimationFrame(() => el.classList.add("visible"));

  shieldWrap.classList.add("pulse");
  shieldWrap.addEventListener("animationend", () => shieldWrap.classList.remove("pulse"), { once: true });

  // Show PDF download button
  document.getElementById("downloadPdfBtn").classList.add("show");
}


/* ── Show error in popup ── */

function showError(msg) {
  const btn      = document.getElementById("scanBtn");
  const btnText  = document.getElementById("btnText");
  const progWrap = document.getElementById("progress-wrap");
  const el       = document.getElementById("result");
  const title    = document.getElementById("result-title");
  const desc     = document.getElementById("result-desc");

  progWrap.style.display = "none";
  btn.disabled = false;
  btnText.textContent = "Scan current email";

  el.className = "";
  el.style.display = "block";
  el.classList.add("error");
  title.textContent = "Scan failed";
  desc.textContent  = msg;

  requestAnimationFrame(() => el.classList.add("visible"));
}


/* ── Reset shield to default blue ── */

function resetShield() {
  document.getElementById("shieldBody").setAttribute("fill", "#E3F0FB");
  document.getElementById("shieldBody").setAttribute("stroke", "#1a6fbe");
  document.getElementById("shieldCheck").setAttribute("opacity", "0");
  document.getElementById("shieldX1").setAttribute("opacity", "0");
  document.getElementById("shieldX2").setAttribute("opacity", "0");
}


/* ── Content script: extract email from Gmail tab ── */

async function extractEmailContent() {

  let emailElement = document.querySelector(".a3s");
  if (!emailElement) return null;

  let body = emailElement.innerText;

  let subjectElement = document.querySelector("h2");
  let subject = subjectElement ? subjectElement.innerText : document.title;

  let senderElement = document.querySelector("span[email]");
  let sender = senderElement ? senderElement.getAttribute("email") : "";

  let links = [];
  emailElement.querySelectorAll("a").forEach(a => {
    if (a.href) links.push(a.href);
  });

  let images = [];
  let imgNodes = emailElement.querySelectorAll("img");
  
  for (let img of imgNodes) {
    if (img.src) {
      try {
        // Fetch the image using the browser's credentials (bypasses auth blocks)
        let resp = await fetch(img.src);
        let blob = await resp.blob();
        let reader = new FileReader();
        let base64data = await new Promise((resolve) => {
          reader.onloadend = () => resolve(reader.result);
          reader.readAsDataURL(blob);
        });
        images.push(base64data);
      } catch (err) {
        // Fallback to plain URL if fetch fails
        images.push(img.src);
      }
    }
  }

  return { subject, body, sender, links, images };
}


/* ── In-page banner injected into Gmail tab ── */

function showResult(tabId, result) {

  chrome.scripting.executeScript({
    target: { tabId },
    func: (result) => {

      const existing = document.getElementById("safemail-banner");
      if (existing) existing.remove();

      const rawScore = parseFloat(result.final_score);
      const score100 = Math.round(rawScore <= 1 ? rawScore * 100 : rawScore);
      const isSafe   = result.final_label !== "phishing";

      const banner = document.createElement("div");
      banner.id = "safemail-banner";

      Object.assign(banner.style, {
        position:   "fixed",
        top:        "0",
        left:       "0",
        width:      "100%",
        zIndex:     "999999",
        fontFamily: "'Segoe UI', Arial, sans-serif",
        boxShadow:  "0 2px 12px rgba(0,0,0,0.18)",
        animation:  "smSlideDown 0.35s cubic-bezier(0.22,1,0.36,1)"
      });

      const style = document.createElement("style");
      style.textContent = `
        @keyframes smSlideDown {
          from { transform: translateY(-100%); opacity: 0; }
          to   { transform: translateY(0);     opacity: 1; }
        }
        #safemail-banner * { box-sizing: border-box; }
        #safemail-close {
          background: none; border: none; cursor: pointer;
          color: inherit; opacity: 0.6; font-size: 16px; line-height: 1;
          padding: 0 4px; margin-left: 12px; flex-shrink: 0;
          transition: opacity 0.15s;
        }
        #safemail-close:hover { opacity: 1; }
        #safemail-bar-fill { transition: width 0.8s cubic-bezier(0.22,1,0.36,1); }
      `;
      document.head.appendChild(style);

      const bg     = isSafe ? "#1b5e20" : "#7f0000";
      const accent = isSafe ? "#66bb6a" : "#ef5350";
      const label  = isSafe ? "SAFE"    : "PHISHING";
      const scoreLabel = isSafe
        ? "Threat score: " + score100 + "/100"
        : "Threat score: " + score100 + "/100. Do not click any links.";

      const icon = isSafe
        ? `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`
        : `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`;

      banner.innerHTML = `
        <div style="background:${bg};color:#fff;padding:10px 18px;display:flex;align-items:center;gap:12px;">
          ${icon}
          <div style="flex:1;min-width:0;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
              <span style="font-size:11px;font-weight:700;letter-spacing:0.08em;color:${accent};">SafeMail-X</span>
              <span style="background:${accent};color:${bg};font-size:10px;font-weight:700;padding:1px 7px;border-radius:99px;letter-spacing:0.06em;">${label}</span>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
              <div style="flex:1;height:4px;background:rgba(255,255,255,0.15);border-radius:99px;overflow:hidden;">
                <div id="safemail-bar-fill" style="height:100%;width:0%;background:${accent};border-radius:99px;"></div>
              </div>
              <span style="font-size:12px;font-weight:600;white-space:nowrap;">${score100}<span style="opacity:0.5;font-weight:400;">/100</span></span>
            </div>
            <div style="font-size:11px;margin-top:4px;opacity:0.75;">${scoreLabel}</div>
          </div>
          <button id="safemail-close" title="Dismiss">&#x2715;</button>
        </div>
      `;

      document.body.prepend(banner);

      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          const fill = document.getElementById("safemail-bar-fill");
          if (fill) fill.style.width = score100 + "%";
        });
      });

      document.getElementById("safemail-close").addEventListener("click", () => {
        banner.style.transition = "opacity 0.2s, transform 0.2s";
        banner.style.opacity = "0";
        banner.style.transform = "translateY(-100%)";
        setTimeout(() => banner.remove(), 220);
      });

    },
    args: [result]
  });

}