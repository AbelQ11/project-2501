// ==============================================================================
// PROJECT 2501 // HISTORICAL ANALYTICS & STATS CONSUMER
// Fetches 24h metrics from /api/stats and updates HUD tables & Active Ban List
// ==============================================================================

export function initStats(channelFilter = null) {
  const ingressEl = document.getElementById('ingress-24h');
  const breachEl = document.getElementById('breach-count');
  const banCountEl = document.getElementById('banned-count');
  const topPagesList = document.getElementById('top-pages-list');
  const topReferrersList = document.getElementById('top-referrers-list');
  const geoTelemetryList = document.getElementById('geo-telemetry-list');
  const bannedIpsBody = document.getElementById('banned-ips-body');
  const threatSrcEl = document.getElementById('threat-src');
  const threatTargetEl = document.getElementById('threat-target');
  const activeVisitorsEl = document.getElementById('active-dives');

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[character]));
  }

  function buildAsciiBar(pct) {
    const totalBars = 10;
    const filled = Math.min(totalBars, Math.max(0, Math.round((pct / 100) * totalBars)));
    const empty = totalBars - filled;
    return `[${'█'.repeat(filled)}${'░'.repeat(empty)}]`;
  }

  function formatTimeRemaining(seconds) {
    if (seconds <= 0) return 'EXPIRED';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  }

  async function fetchStats() {
    try {
      const targetChannel = channelFilter || window.CHANNEL_FILTER;
      const url = targetChannel
        ? `/api/stats?channel=${encodeURIComponent(targetChannel)}`
        : '/api/stats';

      const res = await fetch(url);
      if (!res.ok) return;

      const data = await res.json();

      // 1. Ingress 24h metric badge
      if (ingressEl && data.ingress_24h !== undefined) {
        ingressEl.textContent = Number(data.ingress_24h).toLocaleString();
      }

      // 2. Breach count badge
      if (breachEl && data.breaches_blocked !== undefined) {
        breachEl.textContent = data.breaches_blocked;
      }

      // 3. Active sessions badge (fed by the in-memory session pool)
      if (activeVisitorsEl && data.active_visitors !== undefined) {
        activeVisitorsEl.textContent = Number(data.active_visitors).toLocaleString();
      }

      // 4. Active bans count badge
      if (banCountEl && data.active_bans_count !== undefined) {
        banCountEl.textContent = data.active_bans_count;
      }

      // 4. Top target sectors (pages)
      if (topPagesList && data.top_pages && data.top_pages.length > 0) {
        topPagesList.innerHTML = '';
        data.top_pages.forEach(p => {
          const li = document.createElement('li');
          li.className = 'flex justify-between items-center text-white';
          li.innerHTML = `
            <span class="truncate max-w-[200px]" title="${escapeHtml(p.path)}">${escapeHtml(p.path)}</span>
            <span class="text-[#00ff66] font-bold ml-2">${Number(p.hits).toLocaleString()}</span>
          `;
          topPagesList.appendChild(li);
        });
      }

      // 5. Top referrers (neural origins)
      if (topReferrersList && data.top_referrers && data.top_referrers.length > 0) {
        topReferrersList.innerHTML = '';
        data.top_referrers.forEach(r => {
          const li = document.createElement('li');
          li.className = 'flex justify-between items-center text-white';
          li.innerHTML = `
            <span class="truncate max-w-[190px]" title="${escapeHtml(r.domain)}">${escapeHtml(r.domain)}</span>
            <span class="text-[#00ff66] font-bold ml-2">${Number(r.pct).toFixed(0)}% <span class="text-[10px] text-[#00cc52]/60">(${Number(r.hits).toLocaleString()})</span></span>
          `;
          topReferrersList.appendChild(li);
        });
      }

      // 6. Dynamic Geo-Telemetry resolution
      if (geoTelemetryList && data.geo_stats && data.geo_stats.length > 0) {
        geoTelemetryList.innerHTML = '';
        data.geo_stats.forEach(g => {
          const li = document.createElement('li');
          li.className = 'flex justify-between items-center text-white';
          const bar = buildAsciiBar(g.pct);
          li.innerHTML = `
            <span class="truncate max-w-[170px]"><b>[${escapeHtml(g.country_code)}]</b> ${escapeHtml(g.country_name)}</span>
            <span class="text-[#00ff66] font-bold text-xs ml-2">${Number(g.pct).toFixed(0)}% <span class="text-[10px] text-[#00cc52]/60 font-mono">${bar}</span></span>
          `;
          geoTelemetryList.appendChild(li);
        });
      }

      // 7. Active Banned IPs Table
      if (bannedIpsBody) {
        bannedIpsBody.innerHTML = '';
        if (data.banned_ips && data.banned_ips.length > 0) {
          data.banned_ips.forEach(ban => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-[#ff003c]/20 hover:bg-[#ff003c]/10 text-xs font-mono';
            const banTime = new Date(ban.banned_at * 1000).toISOString().split('T')[1].slice(0, 8);
            tr.innerHTML = `
              <td class="py-1.5 px-2 text-[#ff003c] font-bold">
                <span class="border border-[#ff003c]/40 px-1 py-0.5 bg-[#ff003c]/10 mr-1.5">[${escapeHtml(ban.country)}]</span>
                ${escapeHtml(ban.ip)}
              </td>
              <td class="py-1.5 px-2 text-[#ff9900] truncate max-w-[140px]">${escapeHtml(ban.channel)}</td>
              <td class="py-1.5 px-2 text-white/90 truncate max-w-[260px]" title="${escapeHtml(ban.reason)}">${escapeHtml(ban.reason)}</td>
              <td class="py-1.5 px-2 text-[#00cc52]/70">${escapeHtml(banTime)}</td>
              <td class="py-1.5 px-2 text-right">
                <div class="flex items-center justify-end gap-2">
                  <span class="bg-[#ff003c]/20 border border-[#ff003c]/60 text-[#ff003c] px-2 py-0.5 rounded text-[11px] font-bold">
                    KERNEL DROP (${escapeHtml(formatTimeRemaining(ban.remaining_seconds))})
                  </span>
                  <button class="unban-btn bg-[#030a05] hover:bg-[#ff003c]/30 border border-[#ff003c]/60 hover:border-[#ff003c] text-[#ff003c] px-2 py-0.5 rounded text-[10px] font-bold transition-all shadow-[0_0_8px_rgba(255,0,60,0.3)]">
                    UNBAN
                  </button>
                </div>
              </td>
            `;
            const unbanButton = tr.querySelector('.unban-btn');
            if (unbanButton) {
              unbanButton.addEventListener('click', () => window.unbanIp(ban.ip));
            }
            bannedIpsBody.appendChild(tr);
          });
        } else {
          bannedIpsBody.innerHTML = `
            <tr>
              <td colspan="5" class="py-3 text-center text-[#00ff66]/60 font-mono text-xs">
                [✓] PERIMETER SECURE // NO ACTIVE ICE BANS
              </td>
            </tr>
          `;
        }
      }

      // 8. Recent threat banner
      if (data.recent_threats && data.recent_threats.length > 0) {
        const latest = data.recent_threats[0];
        if (threatSrcEl) {
          threatSrcEl.textContent = `SRC: ${latest.source_ip} [${latest.channel}]`;
        }
        if (threatTargetEl) {
          threatTargetEl.textContent = `${latest.threat_type} ──► ${latest.details}`;
        }
      }
    } catch (err) {
      console.warn('Project 2501 stats fetch warning:', err);
    }
  }

  // Global 1-Click Unban action
  window.unbanIp = async function(ip) {
    if (!confirm(`[攻性防壁] Revoke kernel firewall ban for ${ip}?`)) return;
    try {
      const res = await fetch('/api/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      if (res.ok) {
        fetchStats();
      }
    } catch (err) {
      console.error('Failed to unban IP:', err);
    }
  };

  // Manual ICE Ban action
  const banBtn = document.getElementById('ban-engage-btn');
  const banIpInput = document.getElementById('ban-ip-input');
  const banReasonInput = document.getElementById('ban-reason-input');
  const banDurationSelect = document.getElementById('ban-duration-select');

  if (banBtn && banIpInput) {
    banBtn.addEventListener('click', async () => {
      const ip = banIpInput.value.trim();
      if (!ip) {
        banIpInput.style.borderColor = '#ff003c';
        banIpInput.placeholder = '⚠ ENTER TARGET IP';
        setTimeout(() => {
          banIpInput.style.borderColor = '';
          banIpInput.placeholder = 'TARGET IP ADDRESS';
        }, 2000);
        return;
      }

      if (!confirm(`[攻性防壁] ENGAGE kernel firewall DROP rule on ${ip}?`)) return;

      const reason = banReasonInput ? banReasonInput.value.trim() || undefined : undefined;
      const duration_minutes = banDurationSelect ? parseInt(banDurationSelect.value) : 60;

      banBtn.disabled = true;
      banBtn.textContent = '⏳ ENGAGING...';

      try {
        const res = await fetch('/api/ban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, reason, duration_minutes }),
        });
        const data = await res.json();

        if (data.status === 'success') {
          banBtn.textContent = '✓ ICE ENGAGED';
          banBtn.style.borderColor = '#00ff66';
          banBtn.style.color = '#00ff66';
          banIpInput.value = '';
          if (banReasonInput) banReasonInput.value = '';
          fetchStats();
        } else if (data.status === 'rejected') {
          banBtn.textContent = '⚠ WHITELISTED';
          banBtn.style.borderColor = '#ff9900';
          banBtn.style.color = '#ff9900';
        } else {
          banBtn.textContent = '✗ FAILED';
        }
      } catch (err) {
        console.error('Failed to ban IP:', err);
        banBtn.textContent = '✗ ERROR';
      }

      setTimeout(() => {
        banBtn.disabled = false;
        banBtn.textContent = '▶ ENGAGE ICE BAN';
        banBtn.style.borderColor = '';
        banBtn.style.color = '';
      }, 2500);
    });

    // Allow Enter key to trigger ban from IP input
    banIpInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') banBtn.click();
    });
  }

  fetchStats();
  setInterval(fetchStats, 10000);
}
