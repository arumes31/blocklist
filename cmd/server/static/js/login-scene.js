(() => {
  'use strict';
  const canvas = document.getElementById('loginScene');
  const button = document.getElementById('motionToggle');
  const picker = document.getElementById('backgroundVariant');
  const description = document.getElementById('backgroundDescription');
  // Start the approved Neural Mesh default independently of earlier previews.
  const preferenceKey = 'blocklist.login.background.v2';
  if (!canvas || !button) return;
  const scene = typeof window.createAetherScene === 'function' && typeof SimplexNoise === 'function'
    ? window.createAetherScene(canvas) : null;
  if (!scene) {
    button.disabled = true;
    button.textContent = 'Animation unavailable';
    if (picker) picker.disabled = true;
    return;
  }
  const descriptions = {
    original: 'The original red flow, reactive particles and roaming scanners.',
    ember: 'Warm currents carry glowing embers across the screen.',
    vortex: 'Crimson particles spiral around a slow-moving core.',
    aurora: 'Cool ribbons of teal and blue drift in flowing waves.',
    mesh: 'Blue particles drift through a living network of connections.',
    sonar: 'Red particles radiate out through expanding signal rings.'
  };
  let frame = 0, last = 0;
  // The product explicitly autoplays its original branding, including over RDP.
  // Pause is a page-local choice, never inferred from OS settings or old storage.
  let paused = false;
  function resize() {
    scene.resize();
    scene.render();
  }
  function chooseBackground(value, persist = false) {
    const selected = scene.setVariant(value);
    if (picker) picker.value = selected;
    if (description) description.textContent = descriptions[selected];
    if (persist) {
      try { localStorage.setItem(preferenceKey, selected); } catch (_) { /* Storage is optional. */ }
    }
  }
  function loop(time) {
    frame = 0;
    if (paused || document.hidden) return;
    // Advance by elapsed time, not frame count, including slower remote sessions.
    if (time - last >= 32) {
      const elapsed = time - last;
      last = time;
      scene.render(elapsed);
    }
    frame = requestAnimationFrame(loop);
  }
  function sync() {
    cancelAnimationFrame(frame); frame = 0;
    const stopped = paused || document.hidden;
    canvas.dataset.motion = stopped ? 'paused' : 'playing';
    button.textContent = paused ? 'Play animation' : 'Pause animation';
    button.setAttribute('aria-pressed', String(!paused));
    button.title = 'Play or pause the login background and original animated logo.';
    document.querySelectorAll('.animated-logo').forEach(img => {
      if (!img.complete || !img.naturalWidth) return;
      let poster = img.nextElementSibling;
      if (!poster || !poster.classList.contains('logo-poster')) {
        poster = document.createElement('canvas'); poster.className = 'logo-img logo-poster';
        poster.width = img.naturalWidth; poster.height = img.naturalHeight;
        const posterContext = poster.getContext('2d');
        if (!posterContext) return;
        posterContext.drawImage(img, 0, 0);
        poster.setAttribute('role', 'img'); poster.setAttribute('aria-label', img.alt);
        img.after(poster);
      }
      img.hidden = stopped; poster.hidden = !stopped;
    });
    if (!paused && !document.hidden) { last = performance.now(); frame = requestAnimationFrame(loop); }
  }
  button.addEventListener('click', () => {
    paused = !paused;
    sync();
  });
  if (picker) picker.addEventListener('change', () => chooseBackground(picker.value, true));
  document.addEventListener('visibilitychange', sync);
  addEventListener('resize', resize);
  addEventListener('scroll', scene.updateAvoidRects, { passive: true });
  addEventListener('load', sync);
  // Form swaps and validation can change its height without resizing the window.
  let observer;
  if (typeof ResizeObserver === 'function') {
    observer = new ResizeObserver(scene.updateAvoidRects);
    document.querySelectorAll('#loginContainer, .buttons-container').forEach(el => observer.observe(el));
  }
  addEventListener('pagehide', event => {
    // A back-forward cache entry retains its scene for normal visibility resume.
    if (event.persisted) return;
    cancelAnimationFrame(frame);
    observer?.disconnect();
    scene.dispose();
  });
  let selected = 'mesh';
  try { selected = localStorage.getItem(preferenceKey) || selected; } catch (_) { /* Use Neural Mesh. */ }
  chooseBackground(selected);
  sync();
})();
