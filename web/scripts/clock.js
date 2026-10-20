// ==============================================================================
// PROJECT 2501 // REAL-TIME SYSTEM CLOCK
// ==============================================================================

export function initClock() {
  function update() {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];
    
    const sysTimeEl = document.getElementById('system-time');
    if (sysTimeEl) sysTimeEl.textContent = timeStr;

    const clockEl = document.getElementById('clock');
    if (clockEl) clockEl.textContent = timeStr;
  }

  update();
  setInterval(update, 1000);
}
