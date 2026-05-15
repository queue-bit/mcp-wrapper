/* mcp-wrapper admin UI helpers */

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initVaultMethodToggle();
  initPanelToggles();
});

/* ── Tabs (settings page) ──────────────────────────────────────── */
function initTabs() {
  document.querySelectorAll('.tab-nav').forEach(nav => {
    const container = nav.closest('.tabs');
    if (!container) return;

    nav.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.dataset.tab;

        nav.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        container.querySelectorAll('.tab-panel').forEach(panel => {
          panel.classList.toggle('active', panel.id === target);
        });
      });
    });

    // Activate first tab
    const first = nav.querySelector('.tab-btn');
    if (first && !nav.querySelector('.tab-btn.active')) first.click();
  });
}

/* ── Vault auth method field toggle ───────────────────────────── */
function initVaultMethodToggle() {
  const select = document.getElementById('vault_auth_method');
  if (!select) return;

  const sections = {
    token:      document.getElementById('vault-token-fields'),
    approle:    document.getElementById('vault-approle-fields'),
    aws:        document.getElementById('vault-role-fields'),
    kubernetes: document.getElementById('vault-role-fields'),
    gcp:        document.getElementById('vault-role-fields'),
  };

  function update() {
    const method = select.value;
    Object.values(sections).forEach(el => { if (el) el.style.display = 'none'; });
    const active = sections[method];
    if (active) active.style.display = 'block';
  }

  select.addEventListener('change', update);
  update();
}

/* ── Rules panel helpers ───────────────────────────────────────── */
function addToolRow(serverName, btn) {
  const container = btn.closest('.rules-server-block') || btn.closest('.rules-panel-defaults');
  const input = btn.previousElementSibling;
  const name = (input && input.value || '').trim();
  if (!name) return;

  if (container.querySelector('[data-tool-name="' + CSS.escape(name) + '"]')) {
    input.value = '';
    return;
  }
  input.value = '';

  const esc = name.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const div = document.createElement('div');
  div.className = 'rules-tool-item';
  div.dataset.toolName = name;
  div.innerHTML =
    '<div class="rules-tool-row">' +
      '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;flex:1;min-width:0">' +
        '<input type="checkbox" checked>' +
        '<span class="rules-tool-name mono">' + esc + '</span>' +
      '</label>' +
    '</div>';

  div.querySelector('input[type="checkbox"]').name = serverName + '__tool__' + name;

  let list = container.querySelector('.rules-tool-list');
  if (!list) {
    list = document.createElement('div');
    list.className = 'rules-tool-list';
    container.querySelector('.rules-add-tool').before(list);
  } else {
    const placeholder = list.querySelector('p.text-muted');
    if (placeholder) placeholder.remove();
  }
  list.appendChild(div);
}

/* ── Param filter helpers ──────────────────────────────────────── */
function onParamSelectChange(select) {
  const row = select.closest('.param-add-row');
  const custom = row.querySelector('.param-custom-input');
  if (!custom) return;
  custom.style.display = select.value === '' ? 'inline-block' : 'none';
  if (select.value === '') custom.focus();
}

function addParamFilter(serverName, toolName, btn) {
  const addRow = btn.closest('.param-add-row');
  const container = btn.closest('.param-filters');
  const select = addRow.querySelector('.param-name-select');
  const custom = addRow.querySelector('.param-custom-input');

  let paramName = '';
  if (select && select.value !== '') {
    paramName = select.value;
  } else if (custom) {
    paramName = custom.value.trim();
  }
  if (!paramName) return;

  // Deduplicate within this tool's filter list
  if (container.querySelector(`.param-filter-row[data-param="${CSS.escape(paramName)}"]`)) return;

  const esc = paramName.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const base = serverName + '__constrain__' + toolName + '__param__' + paramName;
  const div = document.createElement('div');
  div.className = 'param-filter-row';
  div.dataset.param = paramName;
  div.innerHTML =
    '<span class="param-filter-label mono">' + esc + '</span>' +
    '<input type="text" class="mini-input mono pf-allowlist" placeholder="val1, val2, …" title="Allowlist">' +
    '<input type="text" class="mini-input mono pf-pattern" placeholder="regex" title="Regex pattern">' +
    '<button type="button" class="btn-remove-param" title="Remove filter" onclick="removeParamFilter(this)">\xd7</button>';
  div.querySelector('.pf-allowlist').name = base + '__allowlist';
  div.querySelector('.pf-pattern').name = base + '__pattern';

  container.insertBefore(div, addRow);

  // Remove the used option from the select so it can't be added again
  if (select && select.value !== '') {
    select.querySelector(`option[value="${CSS.escape(paramName)}"]`)?.remove();
    select.value = select.options[0]?.value ?? '';
    onParamSelectChange(select);
  }
  if (custom) custom.value = '';
}

function removeParamFilter(btn) {
  const row = btn.closest('.param-filter-row');
  const paramName = row.dataset.param;
  const container = row.closest('.param-filters');

  // Restore the option in the select (before "— custom —")
  const select = container.querySelector('.param-name-select');
  if (select && paramName) {
    const customOpt = select.querySelector('option[value=""]');
    if (!select.querySelector(`option[value="${CSS.escape(paramName)}"]`)) {
      const opt = document.createElement('option');
      opt.value = paramName;
      opt.textContent = paramName;
      select.insertBefore(opt, customOpt ?? null);
    }
  }
  row.remove();
}

/* ── Audit Detail Side Pane ────────────────────────────────────── */
function openAuditDetail(eventId) {
  const pane = document.getElementById('audit-pane');
  const backdrop = document.getElementById('audit-backdrop');
  const body = document.getElementById('audit-pane-body');
  if (!pane) return;

  document.querySelectorAll('tr.audit-row').forEach(r => r.classList.remove('active'));
  const row = document.querySelector('tr.audit-row[data-event-id="' + eventId + '"]');
  if (row) row.classList.add('active');

  body.innerHTML = '<div class="audit-pane-loading">Loading…</div>';
  backdrop.style.display = 'block';
  pane.classList.add('open');

  fetch('/admin/audit/' + eventId)
    .then(r => r.text())
    .then(html => { body.innerHTML = html; })
    .catch(() => { body.innerHTML = '<div class="audit-pane-loading">Failed to load event.</div>'; });
}

function closeAuditDetail() {
  const pane = document.getElementById('audit-pane');
  const backdrop = document.getElementById('audit-backdrop');
  if (!pane) return;
  pane.classList.remove('open');
  backdrop.style.display = 'none';
  document.querySelectorAll('tr.audit-row').forEach(r => r.classList.remove('active'));
}

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeAuditDetail();
});

/* ── Inline panel toggles (Add Agent / Add Server) ────────────── */
function initPanelToggles() {
  document.querySelectorAll('[data-toggle-panel]').forEach(btn => {
    btn.addEventListener('click', () => {
      const panelId = btn.dataset.togglePanel;
      const panel = document.getElementById(panelId);
      if (!panel) return;
      const open = panel.classList.toggle('open');
      btn.textContent = open ? (btn.dataset.labelClose || 'Cancel') : (btn.dataset.labelOpen || btn.textContent);
    });
  });

  // Close panel on cancel buttons inside panels
  document.querySelectorAll('[data-close-panel]').forEach(btn => {
    btn.addEventListener('click', () => {
      const panelId = btn.dataset.closePanel;
      const panel = document.getElementById(panelId);
      if (panel) panel.classList.remove('open');
      // Reset the toggle button label
      const toggle = document.querySelector(`[data-toggle-panel="${panelId}"]`);
      if (toggle) toggle.textContent = toggle.dataset.labelOpen || 'Add';
    });
  });
}
