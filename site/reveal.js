// Sections fade up once as they enter. Anything already on screen is shown at once, so a fast scroll
// or a failed observer never leaves content hidden.
const io = 'IntersectionObserver' in window && new IntersectionObserver(entries => {
  for (const e of entries) if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
}, { rootMargin: '0px 0px 15% 0px' });
for (const el of document.querySelectorAll('.reveal')) {
  if (!io || el.getBoundingClientRect().top < innerHeight) el.classList.add('in');
  else io.observe(el);
}
