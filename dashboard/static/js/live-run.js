/**
 * nagapasha dashboard — live run WebSocket client
 *
 * Handles:
 * - Form submission to create new engagements
 * - WebSocket connection for live updates
 * - Rendering stats, findings, and progress
 * - Pause/resume/kill actions
 */

const API_BASE = '';
const WS_PROTOCOL = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
const WS_HOST = window.location.host;

// State
let ws = null;
let currentEngagementId = null;
let statsTimer = null;

// DOM elements
const engagementForm = document.getElementById('engagement-form');
const engagementListContainer = document.getElementById('engagement-list-container');
const liveRunSection = document.getElementById('live-run');
const btnPause = document.getElementById('btn-pause');
const btnResume = document.getElementById('btn-resume');
const btnKill = document.getElementById('btn-kill');

// ---------------------------------------------------------------------------
// Form submission
// ---------------------------------------------------------------------------

engagementForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const targetUrl = document.getElementById('target-url').value.trim();
  const targetMethod = document.getElementById('target-method').value.trim() || 'GET';
  const targetNotes = document.getElementById('target-notes').value.trim();

  if (!targetUrl) return;

  try {
    const response = await fetch(`${API_BASE}/api/engagements`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_host: targetUrl,
        target_url: targetUrl,
        method: targetMethod,
        notes: targetNotes || null,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const engagementId = data.engagement_id;

    // Clear form
    engagementForm.reset();

    // Load engagement list
    await loadEngagements();

    // Start live tracking for this engagement
    connectWebSocket(engagementId);
  } catch (error) {
    console.error('Failed to create engagement:', error);
    alert(`Failed to create engagement: ${error.message}`);
  }
});

// ---------------------------------------------------------------------------
// Engagement list
// ---------------------------------------------------------------------------

async function loadEngagements() {
  try {
    const response = await fetch(`${API_BASE}/api/engagements`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const engagements = await response.json();
    renderEngagementList(engagements);
  } catch (error) {
    console.error('Failed to load engagements:', error);
  }
}

function renderEngagementList(engagements) {
  if (engagements.length === 0) {
    engagementListContainer.innerHTML = `
      <div class="empty-state">
        <h3>No active engagements</h3>
        <p>Submit a URL above to start a new engagement.</p>
      </div>
    `;
    return;
  }

  engagementListContainer.innerHTML = engagements.map(eng => `
    <div class="engagement-item" data-id="${eng.id}">
      <div class="engagement-info">
        <div class="engagement-target">${escapeHtml(eng.method)} ${escapeHtml(eng.target_url)}</div>
        <div class="engagement-url">${escapeHtml(eng.target_host)}</div>
        <div class="engagement-meta">
          Created: ${formatDateTime(eng.created_at)}
          ${eng.status ? `| Status: <span class="status-badge ${eng.status}">${escapeHtml(eng.status)}</span>` : ''}
        </div>
      </div>
      <div class="status-badge ${eng.status || ''}">
        ${eng.status || 'unknown'}
      </div>
    </div>
  `).join('');

  // Add click handlers
  engagementListContainer.querySelectorAll('.engagement-item').forEach(item => {
    item.addEventListener('click', () => {
      const engagementId = item.dataset.id;
      connectWebSocket(engagementId);
    });
  });
}

// ---------------------------------------------------------------------------
// WebSocket connection
// ---------------------------------------------------------------------------

function connectWebSocket(engagementId) {
  // Close existing connection
  if (ws) {
    ws.close();
  }

  currentEngagementId = engagementId;

  // Build WebSocket URL
  const wsUrl = `${WS_PROTOCOL}${WS_HOST}/ws/${engagementId}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log('WebSocket connected');
    updateButtons();
  };

  ws.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      handleWebSocketMessage(message);
    } catch (error) {
      console.error('Failed to parse message:', error);
    }
  };

  ws.onclose = () => {
    console.log('WebSocket disconnected');
  };

  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
}

function handleWebSocketMessage(message) {
  switch (message.type) {
    case 'status':
      updateStats(message.data);
      break;
    case 'finding':
      addFinding(message.data);
      break;
    case 'action_result':
      if (message.success) {
        updateButtons();
      }
      break;
    case 'error':
      console.error('Server error:', message.message);
      break;
  }
}

// ---------------------------------------------------------------------------
// UI updates
// ---------------------------------------------------------------------------

function updateStats(data) {
  // Status
  const statusBadge = document.createElement('span');
  statusBadge.className = `status-badge ${data.status}`;
  statusBadge.textContent = data.status;
  document.getElementById('stat-status').innerHTML = '';
  document.getElementById('stat-status').appendChild(statusBadge);

  // Stats
  document.getElementById('stat-fired').textContent = data.total_fired || 0;
  document.getElementById('stat-hits').textContent = data.hits || 0;
  document.getElementById('stat-near-misses').textContent = data.near_misses || 0;
  document.getElementById('stat-payloads').textContent = data.payload_count || 0;

  // Progress
  const progress = data.progress || 0;
  document.getElementById('progress-percent').textContent = `${progress}%`;
  document.getElementById('progress-fill').style.width = `${progress}%`;

  // Update page title
  document.title = `nagapasha — ${data.status} (${data.total_fired} fired)`;

  // Update button states
  updateButtons();

  // If completed, show completion message
  if (data.status === 'completed' || data.status === 'killed') {
    showCompletionMessage(data.status);
  }
}

function addFinding(finding) {
  // Hide empty state if present
  const emptyState = document.querySelector('#findings-feed .empty-state');
  if (emptyState) {
    emptyState.remove();
  }

  const findingEl = document.createElement('div');
  findingEl.className = `finding-card ${finding.severity === 'confirmed' ? 'confirmed' : 'near_miss'}`;

  const severityLabel = finding.severity === 'confirmed' ? 'confirmed' : 'near_miss';

  findingEl.innerHTML = `
    <div class="finding-header">
      <span class="finding-severity">${severityLabel}</span>
      <span class="finding-parameter">${escapeHtml(finding.parameter_name)}</span>
      <span class="finding-attack-class">${escapeHtml(finding.attack_class)}</span>
    </div>
    <div class="finding-payload">${escapeHtml(finding.payload)}</div>
    ${finding.evidence_req ? `
      <div class="finding-evidence">
        <strong>Request:</strong> ${escapeHtml(finding.evidence_req)}
      </div>
    ` : ''}
    ${finding.evidence_resp ? `
      <div class="finding-evidence">
        <strong>Response:</strong> ${escapeHtml(finding.evidence_resp)}
      </div>
    ` : ''}
  `;

  // Prepend to feed
  const feed = document.getElementById('findings-feed');
  feed.insertBefore(findingEl, feed.firstChild);
}

function updateButtons() {
  if (!currentEngagementId) return;

  // Fetch current status
  fetch(`${API_BASE}/api/live/${currentEngagementId}`)
    .then(res => res.json())
    .then(data => {
      const status = data.status;
      btnPause.disabled = status !== 'running';
      btnResume.disabled = status !== 'paused';
      btnKill.disabled = status === 'completed' || status === 'killed' || !status;
    })
    .catch(() => {
      // Ignore errors — buttons will remain disabled
    });
}

function showCompletionMessage(status) {
  const feed = document.getElementById('findings-feed');
  const msg = document.createElement('div');
  msg.className = 'finding-card';
  msg.style.background = status === 'completed' ? 'var(--success-bg)' : 'var(--danger-bg)';

  msg.innerHTML = `
    <div class="finding-header">
      <span style="font-weight: 500;">
        ${status === 'completed' ? '✓ Engagement completed' : '✗ Engagement killed'}
      </span>
    </div>
    <div class="finding-evidence">
      Total fired: ${document.getElementById('stat-fired').textContent} |
      Hits: ${document.getElementById('stat-hits').textContent} |
      Near-misses: ${document.getElementById('stat-near-misses').textContent}
    </div>
  `;

  feed.insertBefore(msg, feed.firstChild);
}

// ---------------------------------------------------------------------------
// Button handlers
// ---------------------------------------------------------------------------

btnPause.addEventListener('click', () => sendAction('pause'));
btnResume.addEventListener('click', () => sendAction('resume'));
btnKill.addEventListener('click', () => {
  if (confirm('Are you sure you want to kill this engagement?')) {
    sendAction('kill');
  }
});

function sendAction(action) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  ws.send(JSON.stringify({ action }));
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatDateTime(isoString) {
  if (!isoString) return '';
  const date = new Date(isoString);
  return date.toLocaleString();
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

loadEngagements();
