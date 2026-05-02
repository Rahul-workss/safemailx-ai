
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

/* ═══════════════════════════════════════════════════════════
   CANVAS IMAGE SEQUENCE
   ═══════════════════════════════════════════════════════════ */
const canvas = document.getElementById('hero-canvas');
const ctx    = canvas.getContext('2d');
const FRAMES = 240;

canvas.width  = 1920;
canvas.height = 1080;

const pad = i => String(i).padStart(3, '0');
const src = i => `/images/ezgif-frame-${pad(i + 1)}.jpg`;

const images = Array.from({ length: FRAMES }, (_, i) => {
  const img = new Image();
  img.src = src(i);
  return img;
});

const state = { frame: 0 };

function renderFrame() {
  const img = images[Math.round(state.frame)];
  if (!img?.complete) return;
  
  // High-quality rendering
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Cover-fit: centre & fill without distortion
  const scale = Math.max(canvas.width / img.naturalWidth, canvas.height / img.naturalHeight);
  const w = img.naturalWidth  * scale;
  const h = img.naturalHeight * scale;
  const x = (canvas.width  - w) / 2;
  const y = (canvas.height - h) / 2;
  ctx.drawImage(img, x, y, w, h);
}

images[0].onload = renderFrame;

// Scrub frame with scroll
gsap.to(state, {
  frame: FRAMES - 1,
  ease: 'none',
  snap: 'frame',
  scrollTrigger: {
    trigger: '#hero-animation',
    start: 'top top',
    end: 'bottom bottom',
    scrub: 0.5,
    onUpdate: renderFrame,
  },
});


/* ═══════════════════════════════════════════════════════════
   PANEL ANIMATION SYSTEM
   ─────────────────────────────────────────────────────────
   Each panel uses ONE timeline with three phases:
     fadeIn → hold → fadeOut
   All controlled by a single scrubbed ScrollTrigger.
   This ensures perfect bidirectional scroll (forward & back).

   The section is 500vh tall → 400vh of scroll distance.
   ScrollTrigger percentages = viewport-height units scrolled.
   ═══════════════════════════════════════════════════════════ */

/**
 * Animate a panel in and out with a single scrubbed timeline.
 * @param {string} id - Panel CSS selector
 * @param {number} inStart - Start fade-in (% of viewport height scrolled)
 * @param {number} inEnd   - End fade-in
 * @param {number} outStart - Start fade-out
 * @param {number} outEnd   - End fade-out
 * @param {object} fromProps - Initial transform state (e.g. { x: 60 })
 */
function animatePanel(id, inStart, inEnd, outStart, outEnd, fromProps = {}) {
  const totalRange = outEnd - inStart;
  const fadeInDur  = (inEnd   - inStart)  / totalRange;
  const holdDur    = (outStart - inEnd)    / totalRange;
  const fadeOutDur = (outEnd   - outStart) / totalRange;

  const tl = gsap.timeline({
    scrollTrigger: {
      trigger: '#hero-animation',
      start: `top -${inStart}%`,
      end:   `top -${outEnd}%`,
      scrub: 0.6,
    },
  });

  // Phase 1: Fade in + slide in
  tl.fromTo(id,
    { opacity: 0, ...fromProps },
    { opacity: 1, x: 0, y: 0, duration: fadeInDur, ease: 'power2.out' }
  );

  // Phase 2: Hold (visible, do nothing)
  tl.to(id, { duration: holdDur });

  // Phase 3: Fade out
  tl.to(id, { opacity: 0, duration: fadeOutDur, ease: 'power2.in' });
}


/* ── Hero Panel ──────────────────────────────────────────── */
// Hero is visible immediately on page load, then fades out as user scrolls
gsap.set('#panel-hero', { opacity: 1 });

// Animate in the hero content on page load (not scroll-driven)
gsap.fromTo('#panel-hero .center-content > *',
  { opacity: 0, y: 25 },
  { opacity: 1, y: 0, stagger: 0.12, duration: 0.9, ease: 'power3.out', delay: 0.2 }
);

// Fade out the hero panel as the user starts scrolling
gsap.to('#panel-hero', {
  opacity: 0,
  scrollTrigger: {
    trigger: '#hero-animation',
    start: 'top top',
    end: 'top -55%',
    scrub: 0.5,
  },
});

/* ── Layer 1: Pre-Filter ─────────────────────────────────── */
animatePanel('#panel-layer1', 55, 80, 120, 145, { x: 60 });

/* ── Layer 2: LLM Analysis ───────────────────────────────── */
animatePanel('#panel-layer2', 145, 170, 230, 255, { x: -60 });

/* ── Layer 3: Sandbox ────────────────────────────────────── */
animatePanel('#panel-layer3', 250, 275, 340, 370, { x: 60 });


/* ═══════════════════════════════════════════════════════════
   STAGGERED DETAILS INSIDE PANELS
   ═══════════════════════════════════════════════════════════ */

// Each panel's inner elements (feature list items, visual cards) 
// animate independently for extra polish.
const layerPanels = [
  { id: '#panel-layer1', scrollIn: 65 },
  { id: '#panel-layer2', scrollIn: 155 },
  { id: '#panel-layer3', scrollIn: 260 },
];

layerPanels.forEach(({ id, scrollIn }) => {
  // Feature list items stagger in
  gsap.fromTo(`${id} .feature-list li`,
    { opacity: 0, x: 15 },
    {
      opacity: 1, x: 0,
      stagger: 0.08,
      scrollTrigger: {
        trigger: '#hero-animation',
        start: `top -${scrollIn}%`,
        end:   `top -${scrollIn + 25}%`,
        scrub: 0.8,
      },
    }
  );

  // Visual card scales in
  gsap.fromTo(`${id} .layer-visual`,
    { opacity: 0, scale: 0.9, y: 20 },
    {
      opacity: 1, scale: 1, y: 0,
      scrollTrigger: {
        trigger: '#hero-animation',
        start: `top -${scrollIn + 5}%`,
        end:   `top -${scrollIn + 30}%`,
        scrub: 0.8,
      },
    }
  );
});


/* ═══════════════════════════════════════════════════════════
   HIDE PANELS WHEN SCROLLED PAST THE HERO SECTION
   ═══════════════════════════════════════════════════════════ */
// Once the user scrolls past the hero-animation section entirely,
// hide all fixed panels so they don't cover the about/waitlist sections.
ScrollTrigger.create({
  trigger: '#hero-animation',
  start: 'bottom bottom',
  onEnterBack: () => {
    document.querySelectorAll('.panel').forEach(p => p.style.display = 'flex');
  },
  onLeave: () => {
    document.querySelectorAll('.panel').forEach(p => p.style.display = 'none');
  },
});


/* ═══════════════════════════════════════════════════════════
   NAVBAR
   ═══════════════════════════════════════════════════════════ */
ScrollTrigger.create({
  start: 'top -80',
  onToggle: self => {
    document.getElementById('navbar').style.borderBottomColor =
      self.isActive ? 'rgba(0,168,255,0.2)' : 'rgba(255,255,255,0.07)';
  },
});


/* ═══════════════════════════════════════════════════════════
   ABOUT SECTION
   ═══════════════════════════════════════════════════════════ */
gsap.fromTo('.about-title, .about-sub',
  { opacity: 0, y: 20 },
  {
    opacity: 1, y: 0,
    stagger: 0.15,
    duration: 0.8,
    ease: 'power3.out',
    scrollTrigger: { trigger: '#about-section', start: 'top 80%' },
  }
);

gsap.fromTo('.acard',
  { opacity: 0, y: 30 },
  {
    opacity: 1, y: 0,
    stagger: 0.12,
    duration: 0.8,
    ease: 'power3.out',
    scrollTrigger: { trigger: '#about-section', start: 'top 75%' },
  }
);


/* ═══════════════════════════════════════════════════════════
   WAITLIST SECTION
   ═══════════════════════════════════════════════════════════ */
gsap.fromTo('.waitlist-title, .waitlist-sub, .input-row, .waitlist-note',
  { opacity: 0, y: 25 },
  {
    opacity: 1, y: 0,
    stagger: 0.1,
    duration: 0.8,
    ease: 'power3.out',
    scrollTrigger: { trigger: '#waitlist-section', start: 'top 75%' },
  }
);


/* ═══════════════════════════════════════════════════════════
   WAITLIST FORM HANDLER (Formspree)
   ═══════════════════════════════════════════════════════════ */
document.getElementById('year').textContent = new Date().getFullYear();

const form    = document.getElementById('waitlist-form');
const formMsg = document.getElementById('form-msg');
const btn     = document.getElementById('submit-btn');

form.addEventListener('submit', async e => {
  e.preventDefault();
  const originalHTML = btn.innerHTML;
  btn.innerHTML = 'Joining...';
  btn.disabled = true;

  try {
    const res = await fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      headers: { Accept: 'application/json' },
    });

    if (res.ok) {
      form.reset();
      showMsg("🎉 You're on the list! We'll reach out soon.", 'success');
    } else {
      const j = await res.json();
      showMsg(j.errors?.map(x => x.message).join(', ') || 'Something went wrong.', 'error');
    }
  } catch {
    showMsg('Network error. Please try again.', 'error');
  } finally {
    btn.innerHTML = originalHTML;
    btn.disabled = false;
  }
});

function showMsg(text, type) {
  formMsg.textContent = text;
  formMsg.className = `form-msg ${type}`;
  formMsg.classList.remove('hidden');
  setTimeout(() => formMsg.classList.add('hidden'), 6000);
}
