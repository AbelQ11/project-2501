// ==============================================================================
// PROJECT 2501 // REAL-TIME SSE TELEMETRY STREAM & ANALYTICS
// ==============================================================================

export function initTelemetry(channelFilter = null) {
  const telemetryLog = document.getElementById('telemetry-log') || document.getElementById('events');
  const feedRateEl = document.getElementById('feed-rate');
  const breachCountEl = document.getElementById('breach-count');

  let messageCount = 0;
  let lastRateCheck = Date.now();

  function formatTime() {
    return new Date().toISOString().split('T')[1].slice(0, 12);
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[character]));
  }

  function createTelemetryRow(event) {
    const row = document.createElement('div');
    row.className = 'flex items-center gap-3 py-0.5 border-b border-[#00ff66]/10 text-xs font-mono';
    
    const status = event.entry.status || 200;
    // ThreatLevel::None is serialized as the string "None"; Suspicious/Critical
    // are objects. A plain Boolean(event.threat) was always true.
    const hasThreat = event.threat !== undefined
      && event.threat !== null
      && event.threat !== 'None';
    const isThreat = hasThreat || status >= 400;
    const statusBg = isThreat ? 'bg-[#ff003c]/20 text-[#ff003c] border border-[#ff003c]/40' : 'bg-[#00ff66]/20 text-white';

    row.innerHTML = `
      <span class="text-[#00cc52]/50 shrink-0">${formatTime()}</span>
      <span class="${statusBg} px-1 text-[11px] font-bold rounded-sm">${status}</span>
      <span class="text-[#00e5ff] truncate max-w-[220px] md:max-w-xs" title="${escapeHtml(event.entry.path)}">${escapeHtml(event.entry.method || 'GET')} ${escapeHtml(event.entry.path)}</span>
      <span class="text-[#00cc52]/70 shrink-0">SRC: ${escapeHtml(event.entry.remote_addr)}</span>
      <span class="text-[#ff9900] shrink-0 font-semibold">[${escapeHtml(event.channel)}]</span>
      ${isThreat ? '<span class="text-[#ff003c] font-bold animate-pulse">[BREACH]</span>' : ''}
      <span class="text-[#00ff66]/50 ml-auto shrink-0">${Number(event.entry.body_bytes_sent || 0).toLocaleString()} B</span>
    `;
    return row;
  }

  // Update streaming rate counter every 2 seconds
  if (feedRateEl) {
    setInterval(() => {
      const now = Date.now();
      const elapsed = (now - lastRateCheck) / 1000;
      if (elapsed > 0) {
        const rate = (messageCount / elapsed).toFixed(1);
        feedRateEl.textContent = `STREAM: ${rate} msg/s`;
      }
      messageCount = 0;
      lastRateCheck = now;
    }, 2000);
  }

  // Establish SSE connection
  const source = new EventSource('/api/live');

  source.addEventListener('message', (e) => {
    try {
      const data = JSON.parse(e.data);

      // If a channel filter is defined, skip messages not matching
      const targetChannel = channelFilter || window.CHANNEL_FILTER;
      if (targetChannel && data.channel !== targetChannel) {
        return;
      }

      messageCount++;

      if (telemetryLog) {
        const row = createTelemetryRow(data);
        telemetryLog.prepend(row);
        // Keep last 15 items in HUD
        if (telemetryLog.children.length > 15) {
          telemetryLog.removeChild(telemetryLog.lastChild);
        }
      }

      // If threat detected and counter exists, bump counter
      const hasThreat = data.threat !== undefined
        && data.threat !== null
        && data.threat !== 'None';
      if (hasThreat && breachCountEl) {
        const current = parseInt(breachCountEl.textContent, 10) || 0;
        breachCountEl.textContent = current + 1;
      }
    } catch (err) {
      console.error('Project 2501 SSE parsing error:', err);
    }
  });

  source.addEventListener('error', () => {
    if (feedRateEl) {
      feedRateEl.textContent = 'STREAM: RECONNECTING...';
    }
  });
}
