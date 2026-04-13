// Shared navigation component
function renderNav(activePage) {
  const pages = [
    { id: "overview",   label: "📋 Overview",       href: "result_overview.html" },
    { id: "traffic",    label: "🌐 Traffic",         href: "result_traffic.html" },
    { id: "security",   label: "🛡️ Security",        href: "result_security.html" },
    { id: "charts",     label: "📈 Visualizations",  href: "result_charts.html" },
    { id: "ai",         label: "✨ AI Assistant",    href: "result_ai.html" },
  ];

  const tabs = pages.map(p =>
    `<a href="${p.href}" class="tab-link ${p.id === activePage ? 'active' : ''}">${p.label}</a>`
  ).join("");

  return `
  <nav class="topnav">
    <div class="nav-brand">
      <a href="index.html" class="nav-logo-link">
        <div class="nav-logo">🔬</div>
        <span class="nav-title">NT<span>DAP</span></span>
      </a>
    </div>
    <div class="nav-tabs">${tabs}</div>
    <a href="upload.html" class="nav-new">+ New Analysis</a>
  </nav>`;
}

function getResult() {
  const raw = sessionStorage.getItem("ntdap_result");
  if (!raw) {
    document.body.innerHTML = `
      <div style="text-align:center;padding:100px 20px;font-family:sans-serif;color:#8b949e">
        <div style="font-size:48px;margin-bottom:16px">📭</div>
        <h2 style="color:#e6edf3;margin-bottom:8px">No Results Found</h2>
        <p>Please <a href="upload.html" style="color:#00d4ff">upload a PCAP file</a> first.</p>
      </div>`;
    return null;
  }
  return JSON.parse(raw);
}

function fmt(n) { return n != null ? Number(n).toLocaleString() : "—"; }
function fmtBytes(b) {
  if (!b) return "0 B";
  if (b < 1024) return b + " B";
  if (b < 1024*1024) return (b/1024).toFixed(1) + " KB";
  return (b/1024/1024).toFixed(2) + " MB";
}
function severityColor(s) {
  return s==="HIGH" ? "#ef4444" : s==="MEDIUM" ? "#f59e0b" : "#10b981";
}
