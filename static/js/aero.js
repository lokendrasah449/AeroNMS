/* AeroNMS — Frontend JS v1.1 */

// ─── Theme ────────────────────────────────────────────────────────────────────
function applyTheme(mode) {
  if (mode === 'light') {
    document.body.classList.add('light-mode');
  } else {
    document.body.classList.remove('light-mode');
  }
}

function toggleTheme() {
  const isLight = document.body.classList.contains('light-mode');
  const next = isLight ? 'dark' : 'light';
  applyTheme(next);
  localStorage.setItem('aeronms-theme', next);
}

// Apply saved theme immediately (before paint to avoid flash)
(function () {
  const saved = localStorage.getItem('aeronms-theme') || 'dark';
  applyTheme(saved);
})();

// ─── Live Clock ───────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('liveClock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}
setInterval(updateClock, 1000);
updateClock();

// ─── Sidebar Toggle (mobile) ─────────────────────────────────────────────────
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  if (sb) sb.classList.toggle('open');
}

document.addEventListener('click', (e) => {
  const sb  = document.getElementById('sidebar');
  const btn = document.querySelector('.sidebar-toggle');
  if (sb && sb.classList.contains('open') && !sb.contains(e.target) && e.target !== btn) {
    sb.classList.remove('open');
  }
});
