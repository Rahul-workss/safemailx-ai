import "./style.css";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(ScrollTrigger);

const app = document.querySelector("#app");

app.innerHTML = `
  <div class="site-shell">
    <div class="ambient ambient-a"></div>
    <div class="ambient ambient-b"></div>

    <header class="topbar">
      <a class="brand" href="#hero" aria-label="SafeMail-X AI home">
        <img class="brand-logo-img" src="/logo.png" alt="SafeMail-X AI logo" width="36" height="36" />
        <span class="brand-text">SafeMail-X AI</span>
      </a>

      <div class="topbar-actions">
        <span class="status-pill">Coming Soon</span>
        <a class="nav-link" href="#waitlist">Join the waitlist</a>
      </div>
    </header>

    <main>
      <section class="hero-sequence" id="hero">
        <div class="hero-stage">
          <canvas id="sequence-canvas" aria-hidden="true"></canvas>
          <div class="hero-scrim"></div>
          <div class="hero-grid"></div>

          <div class="hero-hud">
            <div class="hud-header">SYSTEM PIPELINE STATUS</div>
            <div class="hud-pipeline">
              <div class="hud-step" data-hud-step="0">
                <div class="hud-step-icon"><span>01</span></div>
                <div class="hud-step-label">INTAKE &amp;<br>ISOLATION</div>
              </div>
              <div class="hud-connector"><div class="hud-connector-fill"></div></div>
              <div class="hud-step" data-hud-step="1">
                <div class="hud-step-icon"><span>02</span></div>
                <div class="hud-step-label">RULE<br>ENGINE</div>
              </div>
              <div class="hud-connector"><div class="hud-connector-fill"></div></div>
              <div class="hud-step" data-hud-step="2">
                <div class="hud-step-icon"><span>03</span></div>
                <div class="hud-step-label">TF-IDF<br>ML MODEL</div>
              </div>
              <div class="hud-connector"><div class="hud-connector-fill"></div></div>
              <div class="hud-step" data-hud-step="3">
                <div class="hud-step-icon"><span>04</span></div>
                <div class="hud-step-label">LLM<br>REASONING</div>
              </div>
              <div class="hud-connector"><div class="hud-connector-fill"></div></div>
              <div class="hud-step" data-hud-step="4">
                <div class="hud-step-icon"><span>05</span></div>
                <div class="hud-step-label">FORENSIC<br>VERDICT</div>
              </div>
            </div>
            <div class="hud-logs">
              <div class="log-line">[SYS] Pipeline ready. Waiting for input...</div>
            </div>
          </div>


        </div>

        <div class="hero-copy">
          <p class="eyebrow">Coming soon</p>
          <h1>
            SafeMail-X
            <span>AI</span>
          </h1>
          <p class="hero-summary">
            Next-gen email security that actually respects your privacy. Our on-device AI rips through sophisticated phishing attempts to give you the exact "who, what, and how" before you ever click a link.
          </p>

          <div class="hero-actions">
            <a class="primary-button" href="#waitlist">Join the waitlist</a>
            <button class="ghost-button" type="button" data-scroll-target="#story">
              See how it works
            </button>
          </div>

          <div class="hero-metrics">
            <div class="metric">
              <span class="metric-value metric-value--accent">99.2%</span>
              <span class="metric-label">phishing catch rate</span>
            </div>
            <div class="metric">
              <span class="metric-value">3-Layer</span>
              <span class="metric-label">AI + Rules + ML</span>
            </div>
            <div class="metric">
              <span class="metric-value metric-value--green">0 Cloud</span>
              <span class="metric-label">fully local analysis</span>
            </div>
          </div>
        </div>

        <div class="scroll-cue">
          <span>Scroll</span>
          <span class="scroll-line"><span></span></span>
        </div>
      </section>

      <section class="story-section" id="story">
        <div class="section-heading">
          <p class="eyebrow">What SafeMail-X AI does</p>
          <h2>Designed to catch what ordinary filters can miss.</h2>
          <p>
            Phishing can look legitimate, pass basic checks, and still rely on pressure,
            impersonation, or confusing links. SafeMail-X AI combines multiple local signals
            before it makes a call.
          </p>
        </div>

        <div class="story-grid">
          <article class="story-card">
            <span class="story-index">01</span>
            <h3>Rule engine</h3>
            <p>
              A deterministic inspection layer checks sender structure, spoofing clues,
              suspicious headers, impersonation patterns, and risky URL behavior.
            </p>
          </article>

          <article class="story-card">
            <span class="story-index">02</span>
            <h3>Local text model</h3>
            <p>
              A trained statistical model scores the message language for phishing-style
              patterns without sending the email body to a remote scoring service.
            </p>
          </article>

          <article class="story-card">
            <span class="story-index">03</span>
            <h3>AI analyzer</h3>
            <p>
              A local analyzer reviews the message like a human reader would, looking for
              urgency, fear, false authority, and other manipulation tactics.
            </p>
          </article>
        </div>
      </section>

      <section class="feature-band">
        <div class="feature-panel feature-panel-large">
          <p class="eyebrow">Privacy by design</p>
          <h2>Your emails stay under your control.</h2>
          <p>
            SafeMail-X AI is built around local analysis. The rule engine, local model,
            AI analyzer, OCR, and report generation run on your own machine.
          </p>
        </div>

        <div class="feature-panel">
          <h3>No SafeMail-X AI cloud</h3>
          <p>There is no separate SafeMail-X AI server receiving your email content or telemetry.</p>
        </div>

        <div class="feature-panel">
          <h3>Forensic PDF reports</h3>
          <p>Each analysis can produce a structured report with the verdict, score, and triggered signals.</p>
        </div>
      </section>

      <section class="waitlist-section" id="waitlist">
        <div class="waitlist-card">
          <p class="eyebrow">Join the waitlist</p>
          <h2>Get the launch note when SafeMail-X AI is ready.</h2>
          <p class="waitlist-copy">
            Join early access for SafeMail-X AI launch updates and private testing access.
          </p>

          <form class="waitlist-form" id="waitlist-form" method="POST">
            <div class="waitlist-fields">
              <div class="waitlist-field-group">
                <label class="field-label" for="waitlist-name">Full Name</label>
                <input
                  id="waitlist-name"
                  name="name"
                  type="text"
                  autocomplete="name"
                  placeholder="Jane Smith"
                  required
                />
              </div>
              <div class="waitlist-field-group">
                <label class="field-label" for="waitlist-email">Email Address</label>
                <input
                  id="waitlist-email"
                  name="email"
                  type="email"
                  autocomplete="email"
                  placeholder="you@company.com"
                  required
                />
              </div>
            </div>
            <button type="submit" id="submit-button">Join the waitlist</button>
          </form>

          <p class="form-note" id="form-note">
            No spam. Product updates only when there is something useful to share.
          </p>

          <div class="form-message hidden" id="form-message" aria-live="polite"></div>
        </div>
      </section>
    </main>
  </div>
`;

const TOTAL_FRAMES = 240;
// On mobile: load every 4th frame (60 frames) for 75% less memory usage
const isMobile = window.innerWidth <= 720;
const frameStep = isMobile ? 4 : 1;
// Build the list of actual frame indices we will load (0, 4, 8, ... or 0, 1, 2, ...)
const frameIndices = [];
for (let i = 0; i < TOTAL_FRAMES; i += frameStep) {
  frameIndices.push(i);
}
const frameCount = frameIndices.length;

const canvas = document.querySelector("#sequence-canvas");
const context = canvas.getContext("2d");
const heroSection = document.querySelector(".hero-sequence");
const topbar = document.querySelector(".topbar");
const form = document.querySelector("#waitlist-form");
const formMessage = document.querySelector("#form-message");
const formNote = document.querySelector("#form-note");
const submitButton = document.querySelector("#submit-button");

// framePath maps our reduced index back to the actual original filename
const framePath = (reducedIndex) => {
  const actualIndex = frameIndices[reducedIndex];
  return `/images/ezgif-frame-${String(actualIndex + 1).padStart(3, "0")}.jpg`;
};

const imageSequence = Array.from({ length: frameCount }, (_, index) => {
  const image = new Image();
  image.src = framePath(index);
  return image;
});

const playhead = { frame: 0 };

function sizeCanvas() {
  const ratio = window.devicePixelRatio || 1;
  // On mobile, cap ratio at 1 to reduce canvas resolution and save GPU memory
  const cappedRatio = isMobile ? Math.min(ratio, 1) : ratio;
  const width = Math.floor(window.innerWidth * cappedRatio);
  const height = Math.floor(window.innerHeight * cappedRatio);

  canvas.width = width;
  canvas.height = height;
  canvas.style.width = `${window.innerWidth}px`;
  canvas.style.height = `${window.innerHeight}px`;

  renderFrame();
}

function drawCoverImage(image) {
  const canvasWidth = canvas.width;
  const canvasHeight = canvas.height;
  const imageRatio = image.naturalWidth / image.naturalHeight;
  const canvasRatio = canvasWidth / canvasHeight;

  let drawWidth = canvasWidth;
  let drawHeight = canvasHeight;

  if (imageRatio > canvasRatio) {
    drawHeight = canvasHeight;
    drawWidth = drawHeight * imageRatio;
  } else {
    drawWidth = canvasWidth;
    drawHeight = drawWidth / imageRatio;
  }

  const offsetX = (canvasWidth - drawWidth) / 2;
  const offsetY = (canvasHeight - drawHeight) / 2;

  context.clearRect(0, 0, canvasWidth, canvasHeight);
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = isMobile ? "medium" : "high";
  context.drawImage(image, offsetX, offsetY, drawWidth, drawHeight);
}

function renderFrame() {
  const image = imageSequence[Math.round(playhead.frame)];
  if (!image || !image.complete) return;
  drawCoverImage(image);
}

imageSequence[0].addEventListener("load", sizeCanvas);
window.addEventListener("resize", sizeCanvas);

gsap.to(playhead, {
  frame: frameCount - 1,
  ease: "none",
  snap: "frame",
  onUpdate: renderFrame,
  scrollTrigger: {
    trigger: heroSection,
    start: "top top",
    end: "bottom bottom",
    // Higher scrub value on mobile = smoother, less janky
    scrub: isMobile ? 1.2 : 0.35,
  },
});

gsap.from(".hero-copy > *", {
  opacity: 0,
  y: 28,
  duration: 0.9,
  stagger: 0.1,
  ease: "power3.out",
  delay: 0.15,
});

gsap.to(".hero-copy", {
  opacity: 0.32,
  y: -50,
  scrollTrigger: {
    trigger: heroSection,
    start: "top top",
    end: "top+=55% top",
    scrub: true,
  },
});

gsap.to(".scroll-cue", {
  opacity: 0,
  y: 20,
  scrollTrigger: {
    trigger: heroSection,
    start: "top top",
    end: "top+=25% top",
    scrub: true,
  },
});

gsap.from(".story-card", {
  opacity: 0,
  y: 40,
  stagger: 0.14,
  duration: 0.8,
  ease: "power3.out",
  scrollTrigger: {
    trigger: ".story-grid",
    start: "top 78%",
  },
});

gsap.from(".feature-panel", {
  opacity: 0,
  y: 34,
  stagger: 0.1,
  duration: 0.75,
  ease: "power3.out",
  scrollTrigger: {
    trigger: ".feature-band",
    start: "top 80%",
  },
});

gsap.from(".waitlist-card > *", {
  opacity: 0,
  y: 24,
  stagger: 0.08,
  duration: 0.75,
  ease: "power3.out",
  scrollTrigger: {
    trigger: ".waitlist-card",
    start: "top 80%",
  },
});

ScrollTrigger.create({
  start: "top -80",
  onToggle: ({ isActive }) => {
    topbar.classList.toggle("topbar-scrolled", isActive);
  },
});

document.querySelectorAll("[data-scroll-target]").forEach((button) => {
  button.addEventListener("click", () => {
    const target = document.querySelector(button.dataset.scrollTarget);
    if (!target) return;
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

function setFormMessage(message, variant) {
  formMessage.textContent = message;
  formMessage.className = `form-message ${variant}`;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  // 1. Paste your Google Apps Script Web App URL here!
  // (Follow the setup guide in google_apps_script_waitlist.md)
  const GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbwWRpfTLeoM49ePAsN7ALjNItCyWmRNIpxEbZ-2Lem2K8GWDzY47Y1KtMinDKX6rub_/exec";

  const data = new FormData(form);
  const name = (data.get("name") || "").trim();
  const email = (data.get("email") || "").trim();

  if (!name || !email) return;

  if (GOOGLE_SCRIPT_URL === "YOUR_GOOGLE_SCRIPT_WEB_APP_URL_HERE") {
    setFormMessage("Almost there! Please add your Google Script URL in src/main.js to activate the waitlist.", "info");
    return;
  }

  const originalLabel = submitButton.textContent;
  submitButton.disabled = true;
  submitButton.textContent = "Joining...";
  formNote.classList.add("hidden");

  // Format data for Google Apps Script
  const urlParams = new URLSearchParams();
  urlParams.append("Name", name);
  urlParams.append("Email", email);

  try {
    // We use mode: 'no-cors' because Google Scripts does a redirect
    await fetch(GOOGLE_SCRIPT_URL, {
      method: "POST",
      body: urlParams,
      mode: 'no-cors'
    });

    // Since 'no-cors' returns an opaque response, we assume success if it didn't throw
    form.reset();
    submitButton.textContent = "Joined ✓";
    setFormMessage(
      `You're on the list, ${name}! We've also sent a confirmation email to ${email}.`,
      "success"
    );

  } catch (error) {
    submitButton.textContent = "Error";
    setFormMessage("Something went wrong. Please check your internet connection or try again later.", "error");
  }

  window.setTimeout(() => {
    submitButton.disabled = false;
    submitButton.textContent = originalLabel;
  }, 3000);
});

// HUD Overlay Logic
const hudStepEls = document.querySelectorAll('.hud-step');
const hudConnectors = document.querySelectorAll('.hud-connector-fill');
const hudLogs = document.querySelector('.hud-logs');
window.lastActiveStep = -2;

// Initial state: whole HUD slides up from below, steps staggered
gsap.set(".hero-hud", { autoAlpha: 0, y: 80, scale: 0.96 });
gsap.set(".hud-step", { autoAlpha: 0, y: 22 });
gsap.set(".hud-connector-fill", { scaleX: 0, transformOrigin: "left center" });

// Slide HUD in on scroll start
gsap.timeline({
  scrollTrigger: {
    trigger: heroSection,
    start: "top+=5% top",
    end: "top+=22% top",
    scrub: true,
  }
})
  .to(".hero-hud", { autoAlpha: 1, y: 0, scale: 1, ease: "power2.out" })
  .to(".hud-step", { autoAlpha: 1, y: 0, stagger: 0.08, ease: "power2.out" }, "<0.1");

// Slide HUD out at end
gsap.timeline({
  scrollTrigger: {
    trigger: heroSection,
    start: "top+=340% top",
    end: "top+=360% top",
    scrub: true,
  }
}).to(".hero-hud", { autoAlpha: 0, y: -50, scale: 0.94, ease: "power2.in" });

function updateHud(index, activeLog) {
  hudStepEls.forEach((step, i) => {
    step.classList.remove('active', 'completed');
    if (i < index) step.classList.add('completed');
    else if (i === index) step.classList.add('active');
  });

  // Animate connector lines filling in up to (index) position
  hudConnectors.forEach((conn, i) => {
    if (i < index) {
      gsap.to(conn, { scaleX: 1, duration: 0.5, ease: "power2.out" });
    } else {
      gsap.to(conn, { scaleX: 0, duration: 0.3, ease: "power2.in" });
    }
  });

  if (activeLog && index !== window.lastActiveStep) {
    const div = document.createElement('div');
    div.className = 'log-line';
    const timestamp = new Date().toISOString().split('T')[1].substring(0, 8);
    div.textContent = `[${timestamp}] ${activeLog}`;
    hudLogs.appendChild(div);
    while (hudLogs.children.length > 1) {
      hudLogs.removeChild(hudLogs.firstChild);
    }
  }
  window.lastActiveStep = index;
}

ScrollTrigger.create({
  trigger: heroSection,
  start: "top top",
  end: "bottom bottom",
  onUpdate: (self) => {
    const p = self.progress;
    let activeStep = -1;
    let log = "";

    if (p < 0.05) { activeStep = -1; log = ""; }
    else if (p >= 0.05 && p < 0.23) { activeStep = 0; log = "Intake initiated: stripping noise..."; }
    else if (p >= 0.23 && p < 0.41) { activeStep = 1; log = "Rule engine: checking headers & URLs..."; }
    else if (p >= 0.41 && p < 0.58) { activeStep = 2; log = "TF-IDF model: scoring vocabulary..."; }
    else if (p >= 0.58 && p < 0.75) { activeStep = 3; log = "LLM reasoning: analyzing intent..."; }
    else if (p >= 0.75 && p <= 1.0) { activeStep = 4; log = "Compiling forensic PDF report..."; }

    if (activeStep !== window.lastActiveStep) {
      updateHud(activeStep, log);
    }
  }
});
