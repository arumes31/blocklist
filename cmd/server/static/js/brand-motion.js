(() => {
  const image = document.querySelector('.brand-wordmark');
  if (!image) return;
  let poster;
  function sync() {
    if (!image.complete || !image.naturalWidth) return;
    if (!poster) {
      poster = document.createElement('canvas'); poster.className = 'brand-wordmark';
      poster.width = image.naturalWidth; poster.height = image.naturalHeight;
      poster.getContext('2d').drawImage(image, 0, 0);
      poster.setAttribute('role', 'img'); poster.setAttribute('aria-label', image.alt); image.after(poster);
    }
    // Keep the original APNG active in visible pages, including remote sessions.
    image.hidden = document.hidden; poster.hidden = !document.hidden;
  }
  image.addEventListener('load', sync); document.addEventListener('visibilitychange', sync); sync();
})();
