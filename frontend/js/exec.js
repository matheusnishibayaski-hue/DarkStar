export function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

export function detectTool(t) {
  if (t.tool) return t.tool.toLowerCase();
  const cmd = (t.command || "").trim();
  return cmd.split(/\s+/)[0]?.split("/").pop()?.toLowerCase() || "";
}

function getCombinedOutput(t) {
  return [t.stdout, t.stderr].filter(Boolean).join("\n");
}

function parseNmapOutput(text) {
  const rows = [];
  const re = /^(\d+\/(tcp|udp))\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$/gim;
  let m;
  while ((m = re.exec(text)) !== null) {
    rows.push({
      port: m[1],
      state: m[3],
      service: m[4] || "—",
      version: (m[5] || "—").trim() || "—",
    });
  }
  return rows;
}

function parseNucleiOutput(text) {
  const findings = [];
  const re = /\[?(critical|high|medium|low|info)\]?[^\n]*/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const full = m[0].trim();
    const sev = (m[1] || "info").toLowerCase();
    if (full.length > 5) findings.push({ severity: sev, text: full });
  }
  return findings;
}

function severityClass(sev) {
  const s = (sev || "info").toLowerCase();
  if (s === "critical" || s === "high") return "sev-critical";
  if (s === "medium") return "sev-medium";
  return "sev-info";
}

function buildNmapDashboard(rows) {
  if (!rows.length) return null;
  const wrap = document.createElement("div");
  wrap.className = "dash-panel dash-nmap";
  wrap.innerHTML = `
    <div class="dash-title">// nmap — portas detectadas (${rows.length})</div>
    <table class="dash-table">
      <thead><tr><th>Porta</th><th>Estado</th><th>Serviço</th><th>Versão</th></tr></thead>
      <tbody>
        ${rows.map((r) => `
          <tr class="${r.state === "open" ? "row-open" : ""}">
            <td>${escapeHtml(r.port)}</td>
            <td>${escapeHtml(r.state)}</td>
            <td>${escapeHtml(r.service)}</td>
            <td>${escapeHtml(r.version)}</td>
          </tr>`).join("")}
      </tbody>
    </table>
  `;
  return wrap;
}

function buildNucleiDashboard(findings) {
  if (!findings.length) return null;
  const wrap = document.createElement("div");
  wrap.className = "dash-panel dash-nuclei";
  wrap.innerHTML = `<div class="dash-title">// nuclei — achados (${findings.length})</div>`;
  for (const f of findings.slice(0, 30)) {
    const card = document.createElement("div");
    card.className = `vuln-card ${severityClass(f.severity)}`;
    card.textContent = f.text;
    wrap.appendChild(card);
  }
  if (findings.length > 30) {
    const more = document.createElement("div");
    more.className = "dash-more";
    more.textContent = `+ ${findings.length - 30} achados adicionais no log completo`;
    wrap.appendChild(more);
  }
  return wrap;
}

export function buildExecBlock(t) {
  const badgeClass = t.blocked ? "status-blocked" : t.success ? "status-ok" : "status-fail";
  const badgeText = t.blocked ? "blocked" : t.success ? "ok" : `exit ${t.exit_code}`;
  const output = getCombinedOutput(t) || "(sem saída)";
  const tool = detectTool(t);

  const block = document.createElement("div");
  block.className = "term-exec";

  const header = document.createElement("div");
  header.className = "term-exec-header";
  header.innerHTML = `
    <span class="${badgeClass}">[${badgeText}]</span>
    <span class="exec-cmd">$ ${escapeHtml(t.command)}</span>
  `;

  const body = document.createElement("div");
  body.className = "term-exec-body";

  if (t.blocked) {
    const tip = document.createElement("div");
    tip.className = "exec-blocked-tip";
    const reason = String(t.block_reason || t.stderr || output || "").slice(0, 400);
    const scopeHint = /escopo|allowed_targets|fora do escopo/i.test(reason);
    const toolHint = /whitelist|não permitid|not allowed|ferramenta/i.test(reason);
    tip.innerHTML = `
      <strong>Comando bloqueado</strong>
      <p>${escapeHtml(reason || "Validação de segurança impediu a execução.")}</p>
      <ul>
        ${scopeHint ? "<li>Inclua o alvo em <code>ALLOWED_TARGETS</code> no <code>.env</code> e reinicie o servidor.</li>" : ""}
        ${toolHint ? "<li>Use uma ferramenta da whitelist (painel <strong>tools</strong>) ou peça um binário permitido.</li>" : ""}
        ${!scopeHint && !toolHint ? "<li>Verifique escopo (<code>ALLOWED_TARGETS</code>), whitelist e ausência de <code>..</code> nos args.</li>" : ""}
        <li>Fluxo lab: <code>nmap -sV scanme.nmap.org</code> → Relatório (<kbd>Alt+R</kbd>) para triagem/PDF.</li>
      </ul>
    `;
    body.appendChild(tip);
  }

  let hasDashboard = false;

  if (tool === "nmap" || output.match(/\d+\/tcp\s+open/i)) {
    const rows = parseNmapOutput(output);
    const dash = buildNmapDashboard(rows);
    if (dash) { body.appendChild(dash); hasDashboard = true; }
  }

  if (tool === "nuclei" || output.match(/\[(critical|high|medium)\]/i)) {
    const findings = parseNucleiOutput(output);
    const dash = buildNucleiDashboard(findings);
    if (dash) { body.appendChild(dash); hasDashboard = true; }
  }

  const rawWrap = document.createElement("div");
  rawWrap.className = hasDashboard ? "exec-raw hidden" : "exec-raw";
  rawWrap.textContent = output;
  body.appendChild(rawWrap);

  const actions = document.createElement("div");
  actions.className = "exec-actions";

  if (hasDashboard) {
    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "exec-btn";
    toggleBtn.textContent = "Ver Log Completo";
    toggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      rawWrap.classList.toggle("hidden");
      toggleBtn.textContent = rawWrap.classList.contains("hidden") ? "Ver Log Completo" : "Ocultar Log";
    });
    actions.appendChild(toggleBtn);
  }

  if (t.log_file_id) {
    const logBtn = document.createElement("a");
    logBtn.className = "exec-btn";
    logBtn.href = `/api/logs/${t.log_file_id}`;
    logBtn.target = "_blank";
    logBtn.rel = "noopener";
    logBtn.textContent = `log ${t.log_file_id.slice(0, 8)}`;
    actions.appendChild(logBtn);
  }

  body.appendChild(actions);
  block.appendChild(header);
  block.appendChild(body);

  header.addEventListener("click", (e) => {
    if (e.target.closest(".exec-btn")) return;
    block.classList.toggle("open");
  });

  if (hasDashboard) block.classList.add("open");
  return block;
}
