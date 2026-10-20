// ==============================================================================
// PROJECT 2501 // GHOST LINE OSCILLOSCOPE (EEG WAVEFORM CANVAS)
// ==============================================================================

export function initOscilloscope() {
  const canvas = document.getElementById('ghost-line-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let phase = 0;

  function resizeCanvas() {
    if (canvas.parentElement) {
      canvas.width = canvas.parentElement.clientWidth;
      canvas.height = canvas.parentElement.clientHeight;
    }
  }

  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();

  function drawGhostWave() {
    ctx.fillStyle = 'rgba(2, 8, 4, 0.2)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.beginPath();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = '#00ff66';
    ctx.shadowColor = '#00ff66';
    ctx.shadowBlur = 8;

    const midY = canvas.height / 2;
    for (let x = 0; x < canvas.width; x++) {
      const y = midY
        + Math.sin((x * 0.02) + phase) * 25
        + Math.sin((x * 0.05) - phase * 1.5) * 12
        + (Math.random() - 0.5) * 4;
      if (x === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }
    ctx.stroke();
    phase += 0.06;
    requestAnimationFrame(drawGhostWave);
  }

  requestAnimationFrame(drawGhostWave);
}
