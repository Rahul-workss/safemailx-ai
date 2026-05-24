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
      <a class="brand" href="#hero" aria-label="TrustMail AI home">
        <img class="brand-logo-img" src="/logo.png" alt="TrustMail AI logo" width="36" height="36" />
        <span class="brand-text">TrustMail AI</span>
      </a>

      <div class="topbar-actions">
        <span class="status-pill">Coming Soon</span>
        <a class="nav-link" href="#waitlist">Join the waitlist</a>
      </div>
    </header>

    <main>
      <section class="hero-sequence" id="hero">
        <div class="hero-stage">
          <video id="sequence-video" aria-hidden="true" src="/animation.mp4" muted playsinline></video>
          <div class="hero-scrim"></div>
          <div class="hero-grid"></div>

          <!-- NEW REDESIGNED HUD — vertical right-side panel -->
          <div class="hero-hud">
            <!-- Top progress bar -->
            <div class="hud-progress-bar">
              <div class="hud-progress-fill" id="hud-progress-fill"></div>
            </div>
            <!-- Chrome window header -->
            <div class="hud-chrome">
              <div class="hud-chrome-dots">
                <div class="hud-chrome-dot"></div>
                <div class="hud-chrome-dot"></div>
                <div class="hud-chrome-dot"></div>
              </div>
              <div class="hud-chrome-title">ANALYSIS PIPELINE</div>
              <div class="hud-chrome-signal"></div>
            </div>
            <!-- Step cards -->
            <div class="hud-steps">
              <div class="hud-step" data-hud-step="0">
                <div class="hud-badge">
                  <span class="hud-badge-num">01</span>
                  <span class="hud-badge-check">✓</span>
                </div>
                <div class="hud-step-content">
                  <div class="hud-step-title">Intake &amp; Isolation</div>
                  <div class="hud-step-desc">Strip noise, extract raw signal</div>
                </div>
                <div class="hud-step-status">IDLE</div>
              </div>
              <div class="hud-step" data-hud-step="1">
                <div class="hud-badge">
                  <span class="hud-badge-num">02</span>
                  <span class="hud-badge-check">✓</span>
                </div>
                <div class="hud-step-content">
                  <div class="hud-step-title">Rule Engine</div>
                  <div class="hud-step-desc">Headers, URLs, spoofing patterns</div>
                </div>
                <div class="hud-step-status">IDLE</div>
              </div>
              <div class="hud-step" data-hud-step="2">
                <div class="hud-badge">
                  <span class="hud-badge-num">03</span>
                  <span class="hud-badge-check">✓</span>
                </div>
                <div class="hud-step-content">
                  <div class="hud-step-title">TF-IDF ML Model</div>
                  <div class="hud-step-desc">Semantic vocabulary scoring</div>
                </div>
                <div class="hud-step-status">IDLE</div>
              </div>
              <div class="hud-step" data-hud-step="3">
                <div class="hud-badge">
                  <span class="hud-badge-num">04</span>
                  <span class="hud-badge-check">✓</span>
                </div>
                <div class="hud-step-content">
                  <div class="hud-step-title">LLM Reasoning</div>
                  <div class="hud-step-desc">Behavioural intent analysis</div>
                </div>
                <div class="hud-step-status">IDLE</div>
              </div>
              <div class="hud-step" data-hud-step="4">
                <div class="hud-badge">
                  <span class="hud-badge-num">05</span>
                  <span class="hud-badge-check">✓</span>
                </div>
                <div class="hud-step-content">
                  <div class="hud-step-title">Forensic Verdict</div>
                  <div class="hud-step-desc">PDF report generation</div>
                </div>
                <div class="hud-step-status">IDLE</div>
              </div>
            </div>
            <!-- Terminal log strip -->
            <div class="hud-terminal">
              <div class="hud-terminal-header">
                <span class="hud-terminal-label">Live Log</span>
                <div class="hud-terminal-line"></div>
              </div>
              <div class="hud-logs">
                <div class="log-line"><span class="log-time">[SYS]</span><span class="log-msg"> Pipeline ready. Awaiting input...<span class="log-cursor"></span></span></div>
              </div>
            </div>
          </div>


        </div>

        <div class="hero-copy">
          <h1>
            TrustMail
            <span>AI</span>
          </h1>
          <p class="eyebrow">Coming soon</p>
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
          <p class="eyebrow"><b>WHAT MAKES US UNIQUE</b></p>
          <h2>Designed to catch what ordinary filters can miss.</h2>
          <p>
            Phishing can look legitimate and pass basic checks. TrustMail AI combines 
            three distinct local intelligence layers to find what others overlook.
          </p>
        </div>

        <div class="story-grid">
          <article class="story-card">
            <span class="story-index">01</span>
            <h3>Triple-Layer Engine</h3>
            <p>
              Every email passes through three distinct intelligence layers: 
              Rule-based heuristics, TF-IDF semantic modeling, and deep LLM reasoning.
            </p>
          </article>

          <article class="story-card">
            <span class="story-index">02</span>
            <h3>Attachment Forensics</h3>
            <p>
              We don't just scan text. TrustMail AI dissects suspicious PDFs 
              and Office documents, identifying hidden scripts and malicious macros.
            </p>
          </article>

          <article class="story-card">
            <span class="story-index">03</span>
            <h3>Zero Data Retention</h3>
            <p>
              Built for total sovereignty. All analysis happens locally. 
              Your private communications never leave your machine or hit a TrustMail cloud.
            </p>
          </article>

          <article class="story-card story-card--centered">
            <span class="story-index">04</span>
            <h3>Evidence-Based Forensic Reports</h3>
            <p>
              We don't just give an opinion. TrustMail AI generates a comprehensive 
              forensic report that breaks down every red flag, so you can see 
              exactly why an email was flagged.
            </p>
          </article>
        </div>
      </section>



      <section class="waitlist-section" id="waitlist">
        <div class="waitlist-card">
          <p class="eyebrow">Join the waitlist</p>
          <h2>Get the launch note when TrustMail AI is ready.</h2>
          <p class="waitlist-copy">
            Join early access for TrustMail AI launch updates and private testing access.
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
      <footer class="site-footer" style="padding: 2rem; text-align: center; color: rgba(255,255,255,0.4); font-size: 0.9rem; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 4rem;">
        <p>&copy; 2026 TrustMail AI. All rights reserved.</p>
        <div style="margin-top: 1rem; display: flex; justify-content: center; gap: 1.5rem;">
          <a href="/privacy.html" style="color: rgba(255,255,255,0.6); text-decoration: none;">Privacy Policy</a>
          <a href="/terms.html" style="color: rgba(255,255,255,0.6); text-decoration: none;">Terms of Service</a>
        </div>
      </footer>
    </main>
  </div>
`;

const isMobile = window.innerWidth <= 720;

const video = document.querySelector("#sequence-video");
const heroSection = document.querySelector(".hero-sequence");
const topbar = document.querySelector(".topbar");
const form = document.querySelector("#waitlist-form");
const formMessage = document.querySelector("#form-message");
const formNote = document.querySelector("#form-note");
const submitButton = document.querySelector("#submit-button");

video.addEventListener("loadedmetadata", () => {
  gsap.to(video, {
    currentTime: video.duration || 10,
    ease: "none",
    scrollTrigger: {
      trigger: heroSection,
      start: "top top",
      end: "bottom bottom",
      scrub: isMobile ? 1.2 : 0.35,
    },
  });
});

// Force load for Safari/iOS
video.load();

gsap.from(".hero-copy > *", {
  opacity: 0,
  y: 28,
  duration: 0.9,
  stagger: 0.1,
  ease: "power3.out",
  delay: 0.15,
});

// Inform GSAP of the percentage-based transform so it doesn't overwrite it
gsap.set(".hero-copy", { xPercent: -50, yPercent: -50 });

gsap.to(".hero-copy", {
  opacity: 0,
  yPercent: -65,
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
  const GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbwo23RPdjHwkOiAqrXsfir4GcKwZ0efPXM5dgp4BwSzwQzIT5ziKW4_4DJWS8SFYJsj/exec";

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

// ── NEW HUD Logic ──────────────────────────────────────────────
const hudStepEls = document.querySelectorAll('.hud-step');
const hudLogs = document.querySelector('.hud-logs');
const hudProgressFill = document.querySelector('#hud-progress-fill');
window.lastActiveStep = -2;

// Slide HUD in from right
const hudStart = isMobile ? "top+=1% top" : "top+=5% top";
const hudEnd = isMobile ? "top+=10% top" : "top+=22% top";

gsap.set(".hero-hud", { autoAlpha: 0, x: 60, scale: 0.95 });
gsap.set(".hud-step", { autoAlpha: 0, x: 16 });

gsap.timeline({
  scrollTrigger: {
    trigger: heroSection,
    start: hudStart,
    end: hudEnd,
    scrub: true,
  }
})
  .to(".hero-hud", { autoAlpha: 1, x: 0, scale: 1, ease: "power2.out" })
  .to(".hud-step", { autoAlpha: 1, x: 0, stagger: 0.1, ease: "power2.out" }, "<0.1");

// Slide HUD out at end
gsap.timeline({
  scrollTrigger: {
    trigger: heroSection,
    start: "top+=340% top",
    end: "top+=360% top",
    scrub: true,
  }
}).to(".hero-hud", { autoAlpha: 0, x: 50, scale: 0.94, ease: "power2.in" });

function updateHud(index, activeLog) {
  hudStepEls.forEach((step, i) => {
    const statusEl = step.querySelector('.hud-step-status');
    step.classList.remove('active', 'completed');

    if (i < index) {
      step.classList.add('completed');
      if (statusEl) statusEl.textContent = 'DONE';
    } else if (i === index) {
      step.classList.add('active');
      if (statusEl) statusEl.textContent = 'RUNNING';
    } else {
      if (statusEl) statusEl.textContent = 'IDLE';
    }
  });

  // Update progress bar (step 0→4 fills 20%→100%)
  if (hudProgressFill) {
    const progress = index < 0 ? 0 : ((index + 1) / 5) * 100;
    hudProgressFill.style.width = progress + '%';
  }

  // Append new log line
  if (activeLog && index !== window.lastActiveStep) {
    const existing = hudLogs.querySelector('.log-line');
    if (existing) existing.remove();

    const div = document.createElement('div');
    div.className = 'log-line';
    const timestamp = new Date().toISOString().split('T')[1].substring(0, 8);
    div.innerHTML = `<span class="log-time">[${timestamp}]</span><span class="log-msg"> ${activeLog}<span class="log-cursor"></span></span>`;
    hudLogs.appendChild(div);
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
