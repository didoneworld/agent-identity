const defaultRecord = {
  agent_id_protocol_version: "0.2.0",
  agent: {
    did: "did:web:agents.didone.world:catalog:planner",
    display_name: "Planner Agent",
    owner: "didoneworld",
    role: "planner",
    environment: "prod",
    version: "v1",
    status: "active",
    trust_level: "internal",
    capabilities: ["planning", "registry-write"]
  },
  authorization: {
    mode: "delegated",
    subject_context: "on_behalf_of_user",
    delegation_proof_formats: ["oauth_token_exchange"],
    scope_reference: "https://agents.didone.world/policies/planner",
    expires_at: "2026-12-31T23:59:59Z",
    max_delegation_depth: 1,
    attenuation_required: true,
    human_approval_required: false
  },
  governance: {
    provisioning: "internal_iam",
    audit_endpoint: "https://agents.didone.world/audit/planner",
    status_endpoint: "https://agents.didone.world/status/planner",
    deprovisioning_endpoint: "https://agents.didone.world/deprovision/planner",
    identity_chain_preserved: true
  },
  bindings: {
    a2a: {
      endpoint_url: "https://agents.didone.world/a2a/planner",
      agent_card_name: "PlannerAgent"
    },
    acp: {
      endpoint_url: null
    },
    anp: {
      did: null,
      endpoint_url: null
    }
  },
  extensions: {}
};

const defaultBlueprint = {
  blueprint_id: "bp-basic-planner",
  display_name: "Basic Planner Agent Blueprint",
  description: "Vendor-neutral DID-first template for planner agents.",
  publisher: "Didone World",
  verified_publisher: true,
  publisher_domain: "didone.world",
  sign_in_audience: "single_tenant",
  identifier_uris: ["api://didone.world/agents/planner"],
  app_roles: [{ value: "Planner.Execute", description: "Run planning tasks" }],
  optional_claims: { access_token: ["did", "blueprint_id"] },
  group_membership_claims: [],
  token_encryption_key_id: null,
  certification: { profile: "agent-did-blueprint-v1" },
  info_urls: { marketing: "https://didone.world/agents", support: "https://didone.world/support", terms_of_service: "https://didone.world/terms", privacy: "https://didone.world/privacy" },
  tags: ["did", "blueprint"],
  status: "active",
  permissions: { required_resource_access: [], inheritable_permissions: [], consent_grants: [], direct_agent_grants: [], denied_permissions: [] },
  owners: ["user:agent-platform-owner"],
  sponsors: ["group:automation-sponsors"],
  extension_fields: { alignment_profile: "microsoft-entra-agent-id" }
};

const state = {
  apiKey: localStorage.getItem("aidp_api_key") || "",
  records: [],
  organizations: [],
  apiKeys: [],
  auditEvents: [],
  identityProviders: [],
  fgaTuples: [],
  blueprints: []
};

const els = {
  sessionStatus: document.getElementById("session-status"),
  sessionKey: document.getElementById("session-key"),
  bootstrapForm: document.getElementById("bootstrap-form"),
  bootstrapResult: document.getElementById("bootstrap-result"),
  sessionForm: document.getElementById("session-form"),
  sessionResult: document.getElementById("session-result"),
  recordForm: document.getElementById("record-form"),
  recordResult: document.getElementById("record-result"),
  recordsList: document.getElementById("records-list"),
  recordsEmpty: document.getElementById("records-empty"),
  organizationsList: document.getElementById("organizations-list"),
  apiKeysList: document.getElementById("api-keys-list"),
  auditList: document.getElementById("audit-list"),
  idpList: document.getElementById("idp-list"),
  idpEmpty: document.getElementById("idp-empty"),
  fgaList: document.getElementById("fga-list"),
  fgaEmpty: document.getElementById("fga-empty"),
  refreshAll: document.getElementById("refresh-all"),
  clearSession: document.getElementById("clear-session"),
  blueprintForm: document.getElementById("blueprint-form"),
  blueprintResult: document.getElementById("blueprint-result"),
  blueprintsList: document.getElementById("blueprints-list"),
  blueprintsEmpty: document.getElementById("blueprints-empty")
};

els.recordForm.record_json.value = JSON.stringify(defaultRecord, null, 2);
els.blueprintForm.blueprint_json.value = JSON.stringify(defaultBlueprint, null, 2);

function setResult(node, value) {
  node.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function setApiKey(key) {
  state.apiKey = key.trim();
  if (state.apiKey) {
    localStorage.setItem("aidp_api_key", state.apiKey);
  } else {
    localStorage.removeItem("aidp_api_key");
  }
  updateSession();
}

function updateSession() {
  if (state.apiKey) {
    els.sessionStatus.textContent = "Connected";
    els.sessionKey.textContent = `${state.apiKey.slice(0, 14)}...${state.apiKey.slice(-4)}`;
  } else {
    els.sessionStatus.textContent = "Not connected";
    els.sessionKey.textContent = "unset";
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (state.apiKey) {
    headers.set("X-API-Key", state.apiKey);
  }
  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    throw new Error(typeof payload === "string" ? payload : payload.detail || JSON.stringify(payload));
  }
  return payload;
}

function renderOrganizations() {
  els.organizationsList.innerHTML = "";
  state.organizations.forEach((item) => {
    const node = document.createElement("div");
    node.className = "mini-card";
    node.innerHTML = `<strong>${item.name}</strong><div class="audit-meta">${item.slug}</div>`;
    els.organizationsList.appendChild(node);
  });
}

function renderApiKeys() {
  els.apiKeysList.innerHTML = "";
  state.apiKeys.forEach((item) => {
    const node = document.createElement("div");
    node.className = "mini-card";
    const status = item.is_active ? "active" : "revoked";
    node.innerHTML = `
      <strong>${item.label}</strong>
      <div class="audit-meta">${item.role} · ${status}</div>
      <div class="audit-meta">${item.key_prefix}...${item.last_four}</div>
    `;
    els.apiKeysList.appendChild(node);
  });
}

function renderAudit() {
  els.auditList.innerHTML = "";
  state.auditEvents.forEach((item) => {
    const node = document.createElement("div");
    node.className = "audit-card";
    node.innerHTML = `
      <div class="audit-top">
        <strong>${item.action}</strong>
        <span class="pill">${new Date(item.created_at).toLocaleString()}</span>
      </div>
      <div class="audit-meta">${item.actor_label}</div>
      <div class="audit-meta">${item.reason || ""}</div>
    `;
    els.auditList.appendChild(node);
  });
}


function renderIdentityProviders() {
  els.idpList.innerHTML = "";
  els.idpEmpty.style.display = state.identityProviders.length ? "none" : "block";
  state.identityProviders.forEach((item) => {
    const node = document.createElement("div");
    node.className = "mini-card";
    node.innerHTML = `
      <strong>${item.provider_type.toUpperCase()} · ${item.label}</strong>
      <div class="audit-meta">Slug: ${item.organization_slug}</div>
      <div class="audit-meta">Entity: ${item.issuer || item.entity_id || "n/a"}</div>
    `;
    els.idpList.appendChild(node);
  });
}

function renderFgaTuples() {
  els.fgaList.innerHTML = "";
  els.fgaEmpty.style.display = state.fgaTuples.length ? "none" : "block";
  state.fgaTuples.forEach((item) => {
    const node = document.createElement("div");
    node.className = "mini-card";
    node.innerHTML = `
      <strong>${item.subject}</strong>
      <div class="audit-meta">${item.relation} @ ${item.resource}</div>
    `;
    els.fgaList.appendChild(node);
  });
}

function renderBlueprints() {
  els.blueprintsList.innerHTML = "";
  els.blueprintsEmpty.style.display = state.blueprints.length ? "none" : "block";
  state.blueprints.forEach((item) => {
    const node = document.createElement("div");
    node.className = "record-card";
    node.innerHTML = `
      <div class="record-top">
        <div>
          <p class="record-title">${item.display_name}</p>
          <div class="audit-meta">${item.blueprint_id} · ${item.publisher}</div>
        </div>
        <span class="pill ${item.status === "active" ? "active" : "disabled"}">${item.status}</span>
      </div>
      <div class="record-meta">Owners: ${(item.owners || []).join(", ") || "n/a"}</div>
      <div class="record-meta">Sponsors: ${(item.sponsors || []).join(", ") || "n/a"}</div>
      <div class="record-meta">Pages: blueprint detail · credentials · required resource access · inheritable permissions · child agent identities · sponsors and owners · audit events</div>
    `;
    els.blueprintsList.appendChild(node);
  });
}

function renderRecords() {
  els.recordsList.innerHTML = "";
  els.recordsEmpty.style.display = state.records.length ? "none" : "block";
  state.records.forEach((item) => {
    const node = document.createElement("div");
    const statusClass = item.status === "active" ? "active" : "disabled";
    node.className = "record-card";
    node.innerHTML = `
      <div class="record-top">
        <div>
          <p class="record-title">${item.display_name}</p>
          <div class="audit-meta">${item.did}</div>
        </div>
        <span class="pill ${statusClass}">${item.status}</span>
      </div>
      <div class="record-meta">Environment: ${item.environment} · Protocol: ${item.protocol_version}</div>
      <div class="record-actions">
        <button data-action="load">Load JSON</button>
        <button data-action="deprovision" class="ghost">Deprovision</button>
      </div>
    `;

    node.querySelector('[data-action="load"]').addEventListener("click", () => {
      els.recordForm.record_json.value = JSON.stringify(item.record, null, 2);
      setResult(els.recordResult, item.record);
    });

    node.querySelector('[data-action="deprovision"]').addEventListener("click", async () => {
      const reason = window.prompt("Reason for deprovisioning", "security review");
      if (!reason) return;
      try {
        const payload = await api(`/v1/agent-records/${item.id}/deprovision`, {
          method: "POST",
          body: JSON.stringify({ reason })
        });
        setResult(els.recordResult, payload);
        await refreshAuthedData();
      } catch (error) {
        setResult(els.recordResult, String(error));
      }
    });

    els.recordsList.appendChild(node);
  });
}

async function refreshAuthedData() {
  if (!state.apiKey) return;
  const [organizations, apiKeys, records, auditEvents, identityProviders, fgaTuples, blueprints] = await Promise.all([
    api("/v1/organizations"),
    api("/v1/api-keys"),
    api("/v1/agent-records"),
    api("/v1/audit-events"),
    api("/v1/identity-providers"),
    api("/v1/fga/tuples"),
    api("/v1/blueprints")
  ]);
  state.organizations = organizations;
  state.apiKeys = apiKeys;
  state.records = records;
  state.auditEvents = auditEvents;
  state.identityProviders = identityProviders;
  state.fgaTuples = fgaTuples;
  state.blueprints = blueprints;
  renderOrganizations();
  renderApiKeys();
  renderRecords();
  renderAudit();
  renderIdentityProviders();
  renderFgaTuples();
  renderBlueprints();
}

els.bootstrapForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  try {
    const result = await api("/v1/bootstrap", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    setResult(els.bootstrapResult, result);
    setApiKey(result.api_key);
    els.sessionForm.api_key.value = result.api_key;
    await refreshAuthedData();
  } catch (error) {
    setResult(els.bootstrapResult, String(error));
  }
});

els.sessionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setApiKey(els.sessionForm.api_key.value);
  try {
    await refreshAuthedData();
    setResult(els.sessionResult, "Session connected.");
  } catch (error) {
    setResult(els.sessionResult, String(error));
  }
});

els.blueprintForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const payload = JSON.parse(els.blueprintForm.blueprint_json.value);
    const result = await api("/v1/blueprints", { method: "POST", body: JSON.stringify(payload) });
    setResult(els.blueprintResult, result);
    await refreshAuthedData();
  } catch (error) {
    setResult(els.blueprintResult, String(error));
  }
});

els.recordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const payload = JSON.parse(els.recordForm.record_json.value);
    const result = await api("/v1/agent-records", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    setResult(els.recordResult, result);
    await refreshAuthedData();
  } catch (error) {
    setResult(els.recordResult, String(error));
  }
});

els.refreshAll.addEventListener("click", async () => {
  try {
    await refreshAuthedData();
  } catch (error) {
    setResult(els.sessionResult, String(error));
  }
});

els.clearSession.addEventListener("click", () => {
  setApiKey("");
  els.sessionForm.api_key.value = "";
  state.records = [];
  state.organizations = [];
  state.apiKeys = [];
  state.auditEvents = [];
  state.identityProviders = [];
  state.fgaTuples = [];
  state.blueprints = [];
  renderOrganizations();
  renderApiKeys();
  renderRecords();
  renderAudit();
  renderIdentityProviders();
  renderFgaTuples();
  renderBlueprints();
});

updateSession();
els.sessionForm.api_key.value = state.apiKey;
if (state.apiKey) {
  refreshAuthedData().catch((error) => setResult(els.sessionResult, String(error)));
}

function renderLifecycleDashboard() {
  const target = document.getElementById("lifecycle-summary");
  if (!target) return;
  const records = state.records || [];
  const counts = records.reduce((acc, item) => {
    const stateName = item.lifecycle_state || (item.status === "disabled" ? "suspended" : "active");
    acc[stateName] = (acc[stateName] || 0) + 1;
    return acc;
  }, {});
  const queues = [
    ["Pending reviews", counts.pending_review || 0],
    ["Renewal queue", counts.pending_renewal || 0],
    ["Credential rotation queue", counts.pending_rotation || 0],
    ["Deprovisioning jobs", counts.deprovisioning || 0],
    ["Quarantine queue", counts.quarantined || 0],
    ["Risk findings", "policy-driven"],
    ["Audit timeline", state.auditEvents.length],
    ["Webhook delivery logs", "replay + DLQ"],
  ];
  target.innerHTML = queues.map(([label, value]) => `<div class="audit-card"><div class="audit-top"><strong>${label}</strong><span>${value}</span></div></div>`).join("");
}

const originalRenderRecords = renderRecords;
renderRecords = function lifecycleAwareRenderRecords() {
  originalRenderRecords();
  renderLifecycleDashboard();
};
