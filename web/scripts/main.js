// ==============================================================================
// PROJECT 2501 // MAIN APPLICATION BOOTSTRAPPER
// Coordinates info, clock, oscilloscope, telemetry, and stats modules
// ==============================================================================

import { initClock } from './clock.js';
import { initOscilloscope } from './oscilloscope.js';
import { initTelemetry } from './telemetry.js';
import { initStats } from './stats.js';

async function initInfo() {
  try {
    const response = await fetch('/api/info');
    if (!response.ok) return;

    const info = await response.json();

    const interfaceEl = document.getElementById('target-interface');
    if (interfaceEl) interfaceEl.textContent = info.interface || 'unknown';

    const ipEl = document.getElementById('target-ip');
    if (ipEl) ipEl.textContent = info.server_public_ip || 'not configured';

    const nav = document.querySelector('header nav');
    if (nav && Array.isArray(info.channels)) {
      nav.innerHTML = '';

      const allLink = document.createElement('a');
      allLink.href = '/';
      allLink.className = window.CHANNEL_FILTER
        ? 'nav-tab px-3 py-1.5 border border-[#00ff66]/40 text-[#00ff66]'
        : 'nav-tab active px-3 py-1.5 border border-[#00ff66]';
      allLink.textContent = 'ALL CHANNELS';
      nav.appendChild(allLink);

      info.channels.forEach((channel) => {
        const link = document.createElement('a');
        link.href = `/sites/${encodeURIComponent(channel.name)}.html`;
        const isActive = window.CHANNEL_FILTER === channel.name;
        link.className = isActive
          ? 'nav-tab active px-3 py-1.5 border border-[#00ff66]'
          : 'nav-tab px-3 py-1.5 border border-[#00ff66]/40 text-[#00ff66]';
        link.textContent = String(channel.name).toUpperCase();
        nav.appendChild(link);
      });
    }
  } catch (error) {
    console.warn('Project 2501 info fetch warning:', error);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const channel = window.CHANNEL_FILTER || null;
  initInfo();
  initClock();
  initOscilloscope();
  initTelemetry(channel);
  initStats(channel);
});
