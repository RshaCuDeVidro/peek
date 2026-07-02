/* ═══ Peek Dashboard — Full Feature English Script ═══ */

/* ─── State ─── */
let activeFilter = 'all';
let searchQuery = '';
let groupBy = 'none';
let scanInterval = null;
let lastLogIndex = 0;
let cameraData = [];
let map = null;
let mapMarkers = [];
let statusChart = null;
let speedChart = null;
let selectedCam = null;
let lastCameraCount = 0;
let isFirstStatusCheck = true;

/* ─── DOM ─── */
const $ = id => document.getElementById(id);
const consoleEl   = $('console');
const resultsWrap = $('resultsWrap');
const progressFill = $('progressFill');
const progressPct  = $('progressPct');
const statusDot    = $('statusDot');
const statusLabel  = $('statusLabel');
const statTotal    = $('statTotal');
const statOpen     = $('statOpen');
const statAuth     = $('statAuth');
const activityText = $('activityText');
const liveModal    = $('liveModal');
const modalTitle   = $('modalTitle');
const modalVideo   = $('modalVideo');
const mainGrid     = $('mainGrid');
const detailPanel  = $('detailPanel');
const dpTitle      = $('dpTitle');
const dpContent    = $('dpContent');
const toastContainer = $('toastContainer');
const historyModal = $('historyModal');
const historyBody  = $('historyBody');

/* ─── Init ─── */
window.addEventListener('DOMContentLoaded', () => {
  initMap();
  initCharts();
  initFilterTabs();
  checkStatus();
  
  // Periodically check Redis status
  checkRedisStatus();
  setInterval(checkRedisStatus, 2000);

  window.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeLive(); closeDetail(); historyModal.classList.remove('active'); }
    if (e.key === 's' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      $('btnScan').click();
    }
  });
  liveModal.addEventListener('click', e => { if (e.target === liveModal) closeLive(); });
  historyModal.addEventListener('click', e => { if (e.target === historyModal) historyModal.classList.remove('active'); });
});

/* ═══════════ TOAST SYSTEM ═══════════ */
function toast(msg, type = 'info') {
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.innerHTML = `<span class="toast-dot"></span><span>${msg}</span>`;
  toastContainer.appendChild(t);
  setTimeout(() => { t.classList.add('fade-out'); setTimeout(() => t.remove(), 300); }, 3500);
}

/* ═══════════ FILTER TABS ═══════════ */
function initFilterTabs() {
  document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeFilter = tab.dataset.filter;
      renderGrid();
    });
  });
}

/* ═══════════ REDIS QUEUE INTEGRATION ═══════════ */
function onSourceChange(val) {
  if (val === 'redis') {
    $('targetsField').style.display = 'none';
    $('redisStatusField').style.display = 'block';
    checkRedisStatus();
  } else {
    $('targetsField').style.display = 'block';
    $('redisStatusField').style.display = 'none';
  }
}

async function checkRedisStatus() {
  try {
    const r = await fetch('/api/redis-status');
    if (r.ok) {
      const d = await r.json();
      if (d.connected) {
        $('redisStatusBadge').textContent = 'Connected';
        $('redisStatusBadge').style.color = 'var(--green)';
        $('redisQueueCount').textContent = d.queue_length;
      } else {
        $('redisStatusBadge').textContent = 'Disconnected';
        $('redisStatusBadge').style.color = 'var(--red)';
        $('redisQueueCount').textContent = '0';
      }
    }
  } catch (e) {
    $('redisStatusBadge').textContent = 'Error';
    $('redisStatusBadge').style.color = 'var(--red)';
    $('redisQueueCount').textContent = '0';
  }
}

function toggleSettings() {
  const modal = $('settingsModal');
  const active = modal.classList.contains('active');
  if (active) {
    modal.classList.remove('active');
  } else {
    loadWebSettings();
    modal.classList.add('active');
  }
}

async function loadWebSettings() {
  try {
    const r = await fetch('/api/redis-settings');
    if (r.ok) {
      const data = await r.json();
      $('setRedisHost').value = data.host || 'localhost';
      $('setRedisPort').value = data.port || 6379;
      $('setRedisDb').value = data.db || 0;
      $('setRedisContinuous').checked = !!data.continuous;
      $('setAIDetectFace').checked = data.detect_face !== false;
      $('setAIDetectPerson').checked = data.detect_person !== false;
      $('setAutoExportJson').checked = !!data.auto_export_json;
      $('setAutoExportCsv').checked = !!data.auto_export_csv;
    }
  } catch(e){}
}

async function saveWebSettings() {
  const payload = {
    host: $('setRedisHost').value.trim(),
    port: parseInt($('setRedisPort').value) || 6379,
    db: parseInt($('setRedisDb').value) || 0,
    continuous: $('setRedisContinuous').checked,
    detect_face: $('setAIDetectFace').checked,
    detect_person: $('setAIDetectPerson').checked,
    auto_export_json: $('setAutoExportJson').checked,
    auto_export_csv: $('setAutoExportCsv').checked
  };
  try {
    const r = await fetch('/api/redis-settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    if (r.ok) {
      toast('Configuration saved successfully!', 'success');
      toggleSettings();
      checkRedisStatus();
    } else {
      toast('Failed to save settings.', 'error');
    }
  } catch(e) {
    toast(e.message, 'error');
  }
}

/* ═══════════ SEARCH ═══════════ */
function onSearch(val) {
  searchQuery = val.toLowerCase().trim();
  renderGrid();
}

/* ═══════════ GROUPING ═══════════ */
function onGroupChange(val) {
  groupBy = val;
  renderGrid();
}

/* ═══════════ CHARTS ═══════════ */
function initCharts() {
  // Status doughnut
  try {
    statusChart = new Chart($('statusChart').getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: ['Open', 'With Password', 'Blocked'],
        datasets: [{ data: [0,0,0], backgroundColor: ['#10b981','#f59e0b','#c026d3'], borderWidth: 0, spacing: 2 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '72%',
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#16161a', titleColor: '#a1a1aa', bodyColor: '#fafafa', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1, titleFont: { size: 10 }, bodyFont: { size: 11 }, padding: 8 } }
      }
    });
  } catch(e){}

  // Speed line chart
  try {
    speedChart = new Chart($('speedChart').getContext('2d'), {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          data: [],
          borderColor: '#c026d3',
          backgroundColor: 'rgba(192,38,211,0.08)',
          borderWidth: 1.5,
          fill: true,
          tension: .4,
          pointRadius: 0,
          pointHoverRadius: 3
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { display: false },
          y: { display: true, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#52525b', font: { size: 9, family: 'JetBrains Mono' }, callback: v => v.toFixed(0) }, beginAtZero: true }
        },
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#16161a', titleColor: '#a1a1aa', bodyColor: '#fafafa', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1, titleFont: { size: 10 }, bodyFont: { size: 11 }, padding: 8, callbacks: { label: ctx => `${ctx.parsed.y.toFixed(1)} IPs/s` } } },
        interaction: { intersect: false, mode: 'index' }
      }
    });
  } catch(e){}
}

function updateStatusChart(open, auth, locked) {
  if (!statusChart) return;
  statusChart.data.datasets[0].data = [open, auth, locked];
  statusChart.update('none');
}

function pushSpeed(rate) {
  if (!speedChart) return;
  const now = new Date();
  const label = `${now.getMinutes()}:${String(now.getSeconds()).padStart(2,'0')}`;
  speedChart.data.labels.push(label);
  speedChart.data.datasets[0].data.push(rate);
  if (speedChart.data.labels.length > 60) {
    speedChart.data.labels.shift();
    speedChart.data.datasets[0].data.shift();
  }
  speedChart.update('none');
}

/* ═══════════ MAP ═══════════ */
function initMap() {
  try {
    map = L.map('map', { zoomControl: false, attributionControl: false }).setView([-15,-55], 3);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 19 }).addTo(map);
    
    // Auto invalidateSize when widgets panel height is resized
    const widgetsEl = document.querySelector('.widgets');
    if (widgetsEl && typeof ResizeObserver !== 'undefined') {
      const ro = new ResizeObserver(() => {
        if (map) map.invalidateSize();
      });
      ro.observe(widgetsEl);
    }
  } catch(e){}
}

function clearMarkers() { mapMarkers.forEach(m => map.removeLayer(m)); mapMarkers = []; }

function addMarker(lat, lon, ip, make, loc) {
  if (!map) return;
  const icon = L.divIcon({ className: 'fuchsia-marker', iconSize: [10,10], iconAnchor: [5,5] });
  const m = L.marker([lat, lon], { icon }).addTo(map);
  m.bindPopup(`<div style="font-family:Inter;font-size:.76rem"><b style="color:#c026d3">${ip}</b><br><span style="color:#06b6d4">${make}</span><br><span style="color:#71717a">${loc}</span></div>`);
  mapMarkers.push(m);
}

function plotCameraMarker(c) {
  if (c.geo && c.geo.lat !== null && c.geo.lon !== null) {
    addMarker(c.geo.lat, c.geo.lon, c.ip, c.make, `${c.geo.city || ''}, ${c.geo.country || ''}`);
  }
}

/* ═══════════ CONSOLE LOG WITH SYNTAX HIGHLIGHTING ═══════════ */
function log(msg, type = '') {
  const el = document.createElement('div');
  el.className = 'ln' + (type === 'error' ? ' err' : type === 'success' ? ' ok' : '');
  
  // Apply regex syntax highlighting
  let html = msg;
  
  // Highlight IP addresses (IPv4 pattern)
  html = html.replace(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, '<span style="color:var(--accent);font-weight:600;">$&</span>');
  
  // Highlight credentials (ex: admin:password or admin:admin123)
  html = html.replace(/\b([a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+)\b/g, '<span style="color:var(--green);font-weight:600;">$&</span>');
  
  // Highlight paths/RTSP protocols
  html = html.replace(/\b(rtsp:\/\/[^\s]+)\b/g, '<span style="color:var(--cyan);text-decoration:underline;">$&</span>');
  html = html.replace(/(\/[a-zA-Z0-9_\-\/]+)/g, '<span style="color:var(--cyan);">$&</span>');
  
  el.innerHTML = html;
  consoleEl.appendChild(el);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setActivity(msg) { if (activityText) activityText.textContent = msg; }

/* ═══════════ SCAN ═══════════ */
function getFormData() {
  const isRedis = $('targetSource').value === 'redis';
  const raw = $('targets').value.trim();
  const targets = raw ? raw.split('\n').map(t=>t.trim()).filter(Boolean) : ['192.168.1.0/24'];
  return {
    use_redis: isRedis,
    targets, workers: parseInt($('threads').value)||50, timeout: 5.0,
    ports: $('ports').value.split(',').map(p=>p.trim()).filter(Boolean),
    snapshot: $('chkScreenshot').checked, geoip: $('chkGeoip').checked, ai: $('chkAI').checked
  };
}

async function startScan() {
  const data = getFormData();
  try {
    if (data.use_redis) {
      log('[SCAN] Consuming targets from Redis queue (reecanner:queue)...','success');
    } else {
      log('[SCAN] Initializing manual sweep...','success');
    }
    toast('Initializing scan...','info');
    setActivity('Connecting...');
    const r = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
    const res = await r.json();
    if (r.ok) {
      log(`[SCAN] Active Targets: ${res.targets_count}`,'success');
      toast(`Scan started — ${res.targets_count} targets`,'success');
      $('btnScan').disabled = true;
      $('btnStop').disabled = false;
      lastLogIndex = 0; cameraData = []; lastCameraCount = 0;
      resultsWrap.innerHTML = '';
      clearMarkers();
      updateStatusChart(0,0,0);
      if (speedChart) { speedChart.data.labels = []; speedChart.data.datasets[0].data = []; speedChart.update('none'); }
      statusDot.className = 'status-dot scanning';
      statusLabel.textContent = 'Scanning';
      if (scanInterval) clearInterval(scanInterval);
      scanInterval = setInterval(checkStatus, 500);
    } else { log(`[ERROR] ${res.error}`,'error'); toast(res.error,'error'); }
  } catch(e) { log(`[ERROR] ${e.message}`,'error'); toast(e.message,'error'); }
}

async function stopScan() {
  try {
    await fetch('/api/stop', { method: 'POST' });
    log('[SCAN] Cancelled.','error');
    toast('Scan cancelled','warning');
    $('btnStop').disabled = true;
  } catch(e) { log(`[ERROR] ${e.message}`,'error'); }
}

async function runDiscovery() {
  log('[DISCOVERY] Broadcasting multicast ONVIF UDP probes...','success');
  toast('Discovering local network...','info');
  try {
    const r = await fetch('/api/discover');
    if (r.ok) {
      const d = await r.json();
      const ips = d.ips || [];
      if (ips.length > 0) {
        log(`[DISCOVERY] Found ${ips.length} ONVIF camera(s)!`,'success');
        toast(`Discovered ${ips.length} local camera(s)!`,'success');
        const cur = $('targets').value.trim();
        $('targets').value = (cur ? cur+'\n' : '') + ips.join('\n');
      } else {
        log('[DISCOVERY] No ONVIF devices responded.','error');
        toast('No local ONVIF cameras found','warning');
      }
    }
  } catch(e) { log(`[ERROR] ${e.message}`,'error'); }
}

/* ═══════════ STATUS POLLING ═══════════ */
async function checkStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();

    if (d.status === 'running') {
      statusDot.className = 'status-dot scanning';
      statusLabel.textContent = 'Scanning';
      $('btnScan').disabled = true; $('btnStop').disabled = false;
      $('scanModeBadge').textContent = 'Active';
      if (!scanInterval) scanInterval = setInterval(checkStatus, 500);
      if (d.rate) pushSpeed(d.rate);
    } else {
      statusDot.className = 'status-dot active';
      statusLabel.textContent = d.status === 'idle' ? 'Ready' : d.status === 'completed' ? 'Finished' : d.status;
      $('btnScan').disabled = false; $('btnStop').disabled = true;
      $('scanModeBadge').textContent = 'Manual';
      if (scanInterval) { clearInterval(scanInterval); scanInterval = null; }
    }

    // Progress
    let pct = 0;
    if (d.total > 0) pct = Math.round((d.done/d.total)*100);
    progressFill.style.width = pct+'%';
    progressPct.textContent = pct+'%';

    // Logs
    if (d.logs && d.logs.length > lastLogIndex) {
      for (let i = lastLogIndex; i < d.logs.length; i++) {
        const l = d.logs[i]; let t = '';
        if (l.includes('[ERROR]')||l.includes('failed')) t = 'error';
        if (l.includes('[SCANNER]')||l.includes('found')) t = 'success';
        log(l, t);
      }
      setActivity(d.logs[d.logs.length-1]);
      lastLogIndex = d.logs.length;
    }

    // Cameras
    if (d.cameras) {
      cameraData = d.cameras;

      // Handle notifications
      if (isFirstStatusCheck) {
        // Silent load on refresh/F5
        lastCameraCount = cameraData.length;
        isFirstStatusCheck = false;
        cameraData.forEach(c => {
          if (c.status !== 'CLOSED' && c.status !== 'ERROR') plotCameraMarker(c);
        });
      } else if (cameraData.length > lastCameraCount) {
        const diff = cameraData.length - lastCameraCount;
        if (diff > 3) {
          // Grouped notification
          toast(`📷 Discovered ${diff} new cameras`,'success');
          for (let i = lastCameraCount; i < cameraData.length; i++) {
            const c = cameraData[i];
            if (c.status !== 'CLOSED' && c.status !== 'ERROR') plotCameraMarker(c);
          }
        } else {
          // Individual notifications
          for (let i = lastCameraCount; i < cameraData.length; i++) {
            const c = cameraData[i];
            if (c.status !== 'CLOSED' && c.status !== 'ERROR') {
              plotCameraMarker(c);
              const statusText = c.open ? 'OPEN' : 'AUTH';
              toast(`📷 ${c.ip} — ${c.make} [${statusText}]`, c.open ? 'success' : 'warning');
            }
          }
        }
        lastCameraCount = cameraData.length;
      }

      renderGrid();

      const openN = cameraData.filter(c => c.status==='OPEN').length;
      const authN = cameraData.filter(c => c.status==='OPEN_AUTH'||c.status==='OPEN(AUTH)').length;
      const lockN = cameraData.filter(c => c.status==='AUTH').length;
      statTotal.textContent = d.total_expanded || cameraData.length;
      statOpen.textContent = openN;
      statAuth.textContent = authN + lockN;
      updateStatusChart(openN, authN, lockN);
    }
  } catch(e){}
}

/* ═══════════ RENDER GRID ═══════════ */
function getFilteredCameras() {
  return cameraData.filter(c => {
    if (c.status === 'CLOSED' || c.status === 'ERROR') return false;
    if (activeFilter === 'open' && !c.open) return false;
    if (activeFilter === 'auth' && c.status !== 'AUTH') return false;
    if (searchQuery) {
      const hay = `${c.ip} ${c.make} ${c.status} ${c.port} ${c.credential||''} ${c.onvif?.manufacturer||''} ${c.onvif?.model||''}`.toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  });
}

function getSubnet(ip) {
  const parts = ip.split('.');
  return parts.length >= 3 ? parts.slice(0,3).join('.')+'.0/24' : ip;
}

function renderGrid() {
  resultsWrap.innerHTML = '';
  const filtered = getFilteredCameras();

  if (filtered.length === 0) {
    resultsWrap.innerHTML = `<div style="text-align:center;padding:50px 20px;color:var(--text-muted);font-size:.8rem">No results found.</div>`;
    return;
  }

  if (groupBy === 'none') {
    const grid = document.createElement('div');
    grid.className = 'results-grid';
    filtered.forEach(c => grid.appendChild(createCamCard(c)));
    resultsWrap.appendChild(grid);
  } else {
    const groups = {};
    filtered.forEach(c => {
      let key;
      if (groupBy === 'make') key = c.make || 'Unknown';
      else if (groupBy === 'subnet') key = getSubnet(c.ip);
      else if (groupBy === 'status') key = c.status;
      else key = 'Other';
      if (!groups[key]) groups[key] = [];
      groups[key].push(c);
    });

    Object.keys(groups).sort().forEach(key => {
      const header = document.createElement('div');
      header.className = 'group-header';
      header.innerHTML = `${key} <span class="count">${groups[key].length}</span>`;
      resultsWrap.appendChild(header);

      const grid = document.createElement('div');
      grid.className = 'results-grid';
      groups[key].forEach(c => grid.appendChild(createCamCard(c)));
      resultsWrap.appendChild(grid);
    });
  }
}

function createCamCard(cam) {
  const isOpen = cam.status === 'OPEN';
  const isAuth = cam.status === 'OPEN_AUTH' || cam.status === 'OPEN(AUTH)';
  let badge = 'AUTH', badgeCls = 'auth';
  if (isOpen) { badge = 'OPEN'; badgeCls = 'open'; }
  else if (isAuth) { badge = 'W/ PASS'; badgeCls = 'open'; }

  let snapHtml = `<div class="empty"><svg fill="none" viewBox="0 0 24 24" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6.827 6.175A2.31 2.31 0 015.186 7.23c-.38.054-.757.112-1.134.175C2.999 7.58 2.25 8.507 2.25 9.574V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9.574c0-1.067-.75-1.994-1.802-2.169a47.865 47.865 0 00-1.134-.175 2.31 2.31 0 01-1.64-1.055l-.822-1.316a2.192 2.192 0 00-1.736-1.039 48.774 48.774 0 00-5.232 0 2.192 2.192 0 00-1.736 1.039l-.821 1.316z"/><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 12.75a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0zM18.75 10.5h.008v.008h-.008V10.5z"/></svg><span>No snapshot</span></div>`;
  if (cam.snapshot) snapHtml = `<img src="${cam.snapshot}" alt="${cam.ip}" onerror="this.style.display='none'">`;

  const card = document.createElement('div');
  card.className = `cam-card ${isOpen?'is-open':'is-auth'} ${selectedCam&&selectedCam.ip===cam.ip?'selected':''}`;
  card.onclick = () => openDetail(cam);
  card.innerHTML = `
    <div class="cam-top"><span class="cam-ip">${cam.ip}:${cam.port}</span><span class="cam-badge ${badgeCls}">${badge}</span></div>
    <div class="cam-snap">${snapHtml}</div>
    <div class="cam-meta">
      <div class="cam-row"><span class="k">Manufacturer</span><span class="v pink">${cam.make||'—'}</span></div>
      <div class="cam-row"><span class="k">Stream</span><span class="v">${cam.stream?(cam.stream.video||'-'):'N/A'}</span></div>
    </div>`;
  return card;
}

/* ═══════════ DETAIL PANEL ═══════════ */
function openDetail(cam) {
  selectedCam = cam;
  mainGrid.classList.add('panel-open');

  dpTitle.textContent = `${cam.ip}:${cam.port}`;

  let snapHtml = `<div class="empty-detail">No snapshot captured</div>`;
  if (cam.snapshot) snapHtml = `<img src="${cam.snapshot}" alt="${cam.ip}">`;

  let threatHtml = '';
  if (cam.threats && cam.threats.length > 0) {
    const counts = {};
    cam.threats.forEach(t => counts[t]=(counts[t]||0)+1);
    const parts = [];
    if (counts.person) parts.push(`👤 ${counts.person} person(s)`);
    if (counts.face) parts.push(`👁 ${counts.face} face(s)`);
    threatHtml = `<div class="dp-section"><h4>AI Objects</h4>${parts.map(p=>`<div class="dp-row"><span class="v" style="color:var(--red)">${p}</span></div>`).join('')}</div>`;
  }

  let onvifHtml = '';
  if (cam.onvif) {
    onvifHtml = `<div class="dp-section"><h4>ONVIF</h4>
      <div class="dp-row"><span class="k">Manufacturer</span><span class="v" style="color:var(--cyan)">${cam.onvif.manufacturer||'—'}</span></div>
      <div class="dp-row"><span class="k">Model</span><span class="v">${cam.onvif.model||'—'}</span></div>
      <div class="dp-row"><span class="k">Firmware</span><span class="v">${cam.onvif.firmware||'—'}</span></div>
    </div>`;
  }

  let statusColor = 'var(--yellow)';
  let statusText = cam.status;
  if (cam.status === 'OPEN') { statusColor = 'var(--green)'; statusText = 'Open (No password)'; }
  else if (cam.status === 'OPEN_AUTH' || cam.status === 'OPEN(AUTH)') { statusColor = 'var(--green)'; statusText = 'Open (With credentials)'; }
  else if (cam.status === 'AUTH') { statusColor = 'var(--yellow)'; statusText = 'Requires authentication'; }

  dpContent.innerHTML = `
    <div class="dp-snap">${snapHtml}</div>
    <div class="dp-section"><h4>Information</h4>
      <div class="dp-row"><span class="k">Status</span><span class="v" style="color:${statusColor}">${statusText}</span></div>
      <div class="dp-row"><span class="k">Manufacturer</span><span class="v" style="color:var(--accent)">${cam.make||'—'}</span></div>
      <div class="dp-row"><span class="k">Port</span><span class="v">${cam.port}</span></div>
      <div class="dp-row"><span class="k">Transport</span><span class="v" style="color:var(--cyan)">${cam.transport?cam.transport.toUpperCase():'TCP'}</span></div>
      ${cam.stream?`<div class="dp-row"><span class="k">Video</span><span class="v">${cam.stream.video||'—'}</span></div><div class="dp-row"><span class="k">Audio</span><span class="v">${cam.stream.audio||'—'}</span></div>`:''}
      ${cam.credential?`<div class="dp-row"><span class="k">Credentials</span><span class="v" style="color:var(--green)">${cam.credential}</span></div>`:''}
      ${cam.geo?`<div class="dp-row"><span class="k">Location</span><span class="v" style="color:var(--cyan)">${cam.geo.city || 'Private Subnet'}, ${cam.geo.country || 'LAN'}</span></div>`:''}
    </div>
    ${onvifHtml}
    ${threatHtml}
    <div class="dp-actions">
      ${cam.open?`<button class="btn btn-primary" onclick="openLive('${cam.ip}','${cam.url}')">▶ Watch Live</button>`:''}
      ${cam.open?`<button class="btn btn-secondary" id="dp-copy" onclick="copyUrl('${cam.url}','dp-copy')">Copy URL</button>`:''}
      <button class="btn btn-danger" onclick="deleteCamera('${cam.ip}')" style="margin-top:4px">🗑 Delete Camera</button>
    </div>`;

  renderGrid();
}

async function deleteCamera(ip) {
  if (!confirm(`Are you sure you want to remove camera ${ip} from scan details and DB?`)) return;
  try {
    const r = await fetch(`/api/delete-camera?ip=${ip}`, { method: 'POST' });
    if (r.ok) {
      toast(`Camera ${ip} removed.`,'success');
      closeDetail();
      cameraData = cameraData.filter(c => c.ip !== ip);
      const openN = cameraData.filter(c => c.status==='OPEN').length;
      const authN = cameraData.filter(c => c.status==='OPEN_AUTH'||c.status==='OPEN(AUTH)').length;
      const lockN = cameraData.filter(c => c.status==='AUTH').length;
      statTotal.textContent = cameraData.length;
      statOpen.textContent = openN;
      statAuth.textContent = authN + lockN;
      updateStatusChart(openN, authN, lockN);
      clearMarkers();
      cameraData.forEach(c => plotCameraMarker(c));
      renderGrid();
    }
  } catch(e) { toast(e.message,'error'); }
}

function closeDetail() {
  selectedCam = null;
  mainGrid.classList.remove('panel-open');
  renderGrid();
}

/* ═══════════ EXPORT CSV ═══════════ */
function exportCSV() {
  const data = getFilteredCameras();
  if (data.length === 0) { toast('No data to export','warning'); return; }

  const headers = ['IP','Port','Manufacturer','Status','URL','Credentials','Video','Audio','Transport','City','Country'];
  const rows = data.map(c => [
    c.ip, c.port, c.make||'', c.status, c.url||'', c.credential||'',
    c.stream?.video||'', c.stream?.audio||'', c.transport||'',
    c.geo?.city||'', c.geo?.country||''
  ]);

  let csv = headers.join(',') + '\n';
  rows.forEach(r => { csv += r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',') + '\n'; });

  downloadFile(csv, `peek_export_${dateStr()}.csv`, 'text/csv');
  toast(`${data.length} cameras exported (CSV)`,'success');
}

/* ═══════════ EXPORT JSON ═══════════ */
function exportJSON() {
  const data = getFilteredCameras();
  if (data.length === 0) { toast('No data to export','warning'); return; }

  const json = JSON.stringify({ exported_at: new Date().toISOString(), total: data.length, cameras: data }, null, 2);
  downloadFile(json, `peek_export_${dateStr()}.json`, 'application/json');
  toast(`${data.length} cameras exported (JSON)`,'success');
}

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function dateStr() {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}_${String(d.getHours()).padStart(2,'0')}${String(d.getMinutes()).padStart(2,'0')}`;
}

/* ═══════════ REPORT WITH SNAPSHOT THUMBNAILS ═══════════ */
function generateReport() {
  const data = getFilteredCameras();
  if (data.length === 0) { toast('No data to compile in report','warning'); return; }

  const openN = data.filter(c=>c.status==='OPEN').length;
  const authN = data.filter(c=>c.status==='OPEN_AUTH'||c.status==='OPEN(AUTH)').length;
  const lockN = data.filter(c=>c.status==='AUTH').length;

  const camRows = data.map((c,i) => {
    let snapCell = `<span style="color:#52525b;font-size:0.7rem">N/A</span>`;
    if (c.snapshot) {
      snapCell = `<img src="${c.snapshot}" style="width:72px;height:45px;object-fit:cover;border-radius:4px;border:1px solid rgba(255,255,255,0.08)">`;
    }
    
    return `
    <tr>
      <td>${i+1}</td>
      <td>${snapCell}</td>
      <td><code>${c.ip}:${c.port}</code></td>
      <td><span class="make-lbl">${c.make||'—'}</span></td>
      <td><span class="badge ${c.open?'badge-open':'badge-auth'}">${c.status}</span></td>
      <td>${c.credential ? `<code class="cred">${c.credential}</code>` : '—'}</td>
      <td>${c.stream?(c.stream.video||'—'):'—'}</td>
      <td><span class="transport">${c.transport?c.transport.toUpperCase():'—'}</span></td>
      <td>${c.threats&&c.threats.length?c.threats.map(t=>`<span class="threat">${t}</span>`).join(' '):'—'}</td>
    </tr>`;
  }).join('');

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Peek — Audit Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',sans-serif;background:#09090b;color:#fafafa;padding:50px 20px;line-height:1.5}
  .container{max-width:1100px;margin:0 auto}
  .header-card{background:#111114;border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:30px;margin-bottom:24px;position:relative;overflow:hidden}
  .header-card::after{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:linear-gradient(to bottom,#c026d3,#7c3aed)}
  h1{font-size:1.8rem;font-weight:800;margin-bottom:6px;letter-spacing:-0.5px}
  .subtitle{color:#71717a;font-size:.82rem}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:30px}
  .stat{background:#111114;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:20px;text-align:center}
  .stat .n{font-size:2rem;font-weight:800;font-family:'JetBrains Mono',monospace;line-height:1}
  .stat .l{font-size:.7rem;color:#71717a;text-transform:uppercase;letter-spacing:1px;font-weight:600;margin-top:8px}
  .stat .n.pink{color:#c026d3} .stat .n.green{color:#10b981} .stat .n.yellow{color:#f59e0b} .stat .n.red{color:#ef4444}
  .table-card{background:#111114;border:1px solid rgba(255,255,255,.06);border-radius:14px;overflow:hidden;margin-bottom:30px}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;padding:14px 16px;background:rgba(255,255,255,.02);color:#71717a;font-size:.7rem;text-transform:uppercase;letter-spacing:1px;font-weight:700;border-bottom:1px solid rgba(255,255,255,.06)}
  td{padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.04);color:#a1a1aa;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(255,255,255,.01);color:#fafafa}
  code{font-family:'JetBrains Mono',monospace;color:#06b6d4;font-size:.8rem;background:rgba(6,182,212,.08);padding:3px 6px;border-radius:4px}
  code.cred{color:#10b981;background:rgba(16,185,129,.08)}
  .badge{padding:3px 8px;border-radius:6px;font-size:.68rem;font-weight:700;letter-spacing:0.3px;display:inline-block}
  .badge-open{color:#10b981;background:rgba(16,185,129,.1)}
  .badge-auth{color:#f59e0b;background:rgba(245,158,11,.1)}
  .make-lbl{color:#c026d3;font-weight:600}
  .transport{color:#a1a1aa;font-weight:500}
  .threat{font-size:.65rem;font-weight:600;color:#ef4444;background:rgba(239,68,68,.1);padding:2px 6px;border-radius:4px;display:inline-block;margin:1px}
  .footer{color:#52525b;font-size:.72rem;text-align:center;margin-top:40px;padding-top:20px;border-top:1px solid rgba(255,255,255,.04)}
  .print-btn{position:fixed;top:20px;right:20px;background:linear-gradient(135deg,#c026d3,#7c3aed);color:#fff;border:none;padding:10px 20px;border-radius:8px;font-family:Inter,sans-serif;font-weight:600;cursor:pointer;font-size:.82rem;z-index:100;box-shadow:0 4px 15px rgba(192,38,211,.3);transition:all 0.2s}
  .print-btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(192,38,211,.45)}
  @media print{
    body{background:#fff;color:#111;padding:20px 0}
    .header-card, .stat, .table-card{background:#fff;border:1px solid #e2e8f0;color:#111;box-shadow:none}
    td, th{border-bottom:1px solid #e2e8f0;color:#334155}
    tr:hover td{background:none;color:#334155}
    code{background:#f1f5f9;color:#0369a1}
    code.cred{background:#f0fdf4;color:#15803d}
    .badge-open{background:#f0fdf4;color:#166534}
    .badge-auth{background:#fef9c3;color:#854d0e}
    .print-btn, .footer{display:none}
    h1{color:#111}
    .subtitle{color:#64748b}
    img{border:1px solid #ccc!important}
  }
</style></head><body>
<button class="print-btn" onclick="window.print()">🖨 Print / Save PDF</button>
<div class="container">
  <div class="header-card">
    <h1>Security Audit Report</h1>
    <div class="subtitle">Generated on ${new Date().toLocaleString('en-US')} • Peek RTSP Core Engine</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="n pink">${data.length}</div><div class="l">Active Cameras</div></div>
    <div class="stat"><div class="n green">${openN}</div><div class="l">No Password</div></div>
    <div class="stat"><div class="n yellow">${authN}</div><div class="l">With Password</div></div>
    <div class="stat"><div class="n red">${lockN}</div><div class="l">Blocked</div></div>
  </div>
  <div class="table-card">
    <table><thead><tr><th>#</th><th>Snapshot</th><th>IP / Port</th><th>Manufacturer</th><th>Status</th><th>Credentials</th><th>Video</th><th>Transport</th><th>AI Objects</th></tr></thead><tbody>${camRows}</tbody></table>
  </div>
  <div class="footer">Peek Scanner • Report generated confidentially</div>
</div></body></html>`;

  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  toast('Report loaded in a new tab','success');
}

/* ═══════════ SCAN HISTORY (SQLite DB Backed) ═══════════ */
async function toggleHistory() {
  const active = historyModal.classList.contains('active');
  if (active) { historyModal.classList.remove('active'); return; }

  historyBody.innerHTML = '<div class="history-empty">Fetching history records...</div>';
  historyModal.classList.add('active');

  try {
    const r = await fetch('/api/scans');
    if (!r.ok) throw new Error('Failed to fetch scans history');
    const scans = await r.json();

    if (scans.length === 0) {
      historyBody.innerHTML = '<div class="history-empty">No scans recorded in the database.</div>';
      return;
    }

    historyBody.innerHTML = `<div class="history-list">${scans.map(h => {
      const d = new Date(h.timestamp);
      const dateStr = d.toLocaleDateString('en-US',{day:'2-digit',month:'short',year:'numeric'});
      const timeStr = d.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
      
      let targetsTrimmed = h.targets_raw && h.targets_raw.length > 32 ? h.targets_raw.substring(0, 32) + '...' : h.targets_raw || '—';

      return `<div class="history-item" onclick="loadHistoricalScan(${h.id})" style="cursor:pointer">
        <span class="history-date">${dateStr}<br>${timeStr}</span>
        <div class="history-info">
          <span class="history-target">${targetsTrimmed}</span>
          <div class="history-stats">
            <span class="hs">📡 ${h.total} targets</span>
            <span class="hs g">📷 ${h.cameras_count} found</span>
            <span class="hs y">🔓 ${h.open_count} open</span>
          </div>
        </div>
      </div>`;
    }).join('')}</div>`;
  } catch (e) {
    historyBody.innerHTML = `<div class="history-empty" style="color:var(--red)">Error: ${e.message}</div>`;
  }
}

async function loadHistoricalScan(scanId) {
  toast('Loading historical scan session...','info');
  try {
    const r = await fetch(`/api/scan-details?id=${scanId}`);
    if (!r.ok) throw new Error('Could not retrieve scan details');
    const d = await r.json();

    cameraData = d.cameras || [];
    lastCameraCount = cameraData.length;
    
    // Clear and restore map markers
    clearMarkers();
    cameraData.forEach(c => plotCameraMarker(c));

    // Populate counters
    const openN = cameraData.filter(c => c.status === 'OPEN').length;
    const authN = cameraData.filter(c => c.status === 'OPEN_AUTH' || c.status === 'OPEN(AUTH)').length;
    const lockN = cameraData.filter(c => c.status === 'AUTH').length;

    statTotal.textContent = d.total || cameraData.length;
    statOpen.textContent = openN;
    statAuth.textContent = authN + lockN;
    
    updateStatusChart(openN, authN, lockN);
    renderGrid();

    // Restore terminal logs
    consoleEl.innerHTML = '';
    if (d.logs && d.logs.length > 0) {
      d.logs.forEach(l => {
        let t = '';
        if (l.includes('[ERROR]')||l.includes('failed')) t = 'error';
        if (l.includes('[SCANNER]')||l.includes('found')) t = 'success';
        log(l, t);
      });
    } else {
      consoleEl.innerHTML = `<div class="ln ok">» Historical scan loaded (${new Date(d.timestamp).toLocaleString('en-US')})</div>`;
    }
    
    // Close history dialog
    historyModal.classList.remove('active');
    toast(`Scan session #${d.id} restored.`,'success');
  } catch(e) {
    toast(`Error: ${e.message}`,'error');
  }
}

/* ═══════════ COPY URL ═══════════ */
function copyUrl(url, btnId) {
  navigator.clipboard.writeText(url).then(() => {
    log(`[CLIPBOARD] Copied: ${url}`,'success');
    toast('URL copied!','success');
    const btn = $(btnId);
    if (btn) { btn.textContent = '✓ Copied'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy URL'; btn.classList.remove('copied'); }, 1500); }
  }).catch(e => toast(e.message,'error'));
}

/* ═══════════ LIVE STREAM ═══════════ */
function openLive(ip, url) {
  modalTitle.textContent = `Live View — ${ip}`;
  modalVideo.innerHTML = `
    <span class="fallback" id="streamLoader">Establishing RTSP connection...</span>
    <img src="/api/stream-live?url=${encodeURIComponent(url)}" alt="Live ${ip}" onload="document.getElementById('streamLoader').style.display='none'" onerror="document.getElementById('streamLoader').textContent='Failed to receive video frames'">
  `;
  liveModal.classList.add('active');
  toast(`Streaming ${ip}...`,'info');
}

function closeLive() {
  modalVideo.innerHTML = '';
  liveModal.classList.remove('active');
}
