// nav.js — NTDAP v4.0 shared navigation + utilities + auth

const API_BASE = "http://localhost:5000";

function _getUser() {
  try { return JSON.parse(localStorage.getItem("ntdap_user") || "{}"); } catch { return {}; }
}

function renderNav(activePage) {
  const user = _getUser();
  const isLoggedIn = !!localStorage.getItem("ntdap_token");
  const isAdmin = user.role === "admin";

  const resultPages = [
    { id: "overview",  label: "📋 Overview",  href: "result_overview.html" },
    { id: "traffic",   label: "🌐 Traffic",   href: "result_traffic.html" },
    { id: "security",  label: "🛡️ Security",  href: "result_security.html" },
    { id: "charts",    label: "📈 Charts",    href: "result_charts.html" },
    { id: "packets",   label: "📦 Packets",   href: "result_packets.html" },
    { id: "ai",        label: "✨ AI Analyst", href: "result_ai.html" },
  ];
  const isResultPage = resultPages.some(p => p.id === activePage);

  const tabs = isResultPage
    ? resultPages.map(p => `<a href="${p.href}" class="tab-link ${p.id===activePage?'active':''}">${p.label}</a>`).join("")
    : `<a href="index.html"  class="tab-link ${activePage==='home'   ?'active':''}">Home</a>
       <a href="upload.html" class="tab-link ${activePage==='upload' ?'active':''}">Upload</a>
       ${isAdmin ? `<a href="admin.html" class="tab-link ${activePage==='admin'?'active':''}">⚡ Admin</a>` : ""}`;

  const userMenu = isLoggedIn
    ? `<div class="nav-user-wrap">
        <a href="profile.html" class="nav-profile-btn ${activePage==='profile'?'active':''}">
          <span class="nav-avatar">${(user.username||"?")[0].toUpperCase()}</span>
          <span class="nav-username">${user.username||"User"}</span>
          ${isAdmin?'<span class="nav-admin-badge">Admin</span>':""}
        </a>
        <button class="nav-logout-btn" onclick="doLogout()" title="Sign Out">⏻</button>
       </div>`
    : `<a href="login.html" class="nav-new">Sign In →</a>`;

  return `<nav class="topnav">
    <div class="nav-brand">
      <a href="index.html" class="nav-logo-link">
        <div class="nav-logo">🔬</div>
        <span class="nav-title">NT<span>DAP</span></span>
      </a>
    </div>
    <div class="nav-tabs">${tabs}</div>
    <div class="nav-right">
      ${isResultPage?`<a href="upload.html" class="nav-new">+ New</a>`:""}
      ${userMenu}
    </div>
  </nav>`;
}

(function injectNavStyles() {
  if (document.getElementById("__ntdap_nav_styles")) return;
  const s = document.createElement("style"); s.id = "__ntdap_nav_styles";
  s.textContent = `
    .nav-right{display:flex;align-items:center;gap:10px}
    .nav-user-wrap{
    display:flex;
    align-items:center;
    gap:12px;
    min-width:fit-content;
}
    .nav-profile-btn{
    display:flex;
    align-items:center;
    gap:10px;
    background:var(--surface2);
    border:1px solid var(--border);
    border-radius:10px;
    padding:6px 14px 6px 8px;
    text-decoration:none;
    color:var(--text);
    font-size:13px;
    font-weight:600;
    transition:all .2s;
    white-space:nowrap;
}
    .nav-profile-btn:hover,.nav-profile-btn.active{border-color:var(--accent);color:var(--accent)}
    .nav-avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,var(--accent2),var(--accent));display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:#fff;flex-shrink:0}
    .nav-username{max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .nav-admin-badge{background:rgba(124,58,237,.25);border:1px solid rgba(124,58,237,.4);color:#a78bfa;border-radius:5px;padding:1px 6px;font-size:10px;font-weight:700}
    .nav-logout-btn{background:var(--surface2);border:1px solid var(--border);color:var(--muted);border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all .2s}
    .nav-logout-btn:hover{border-color:var(--danger);color:var(--danger)}
  `;
  document.head.appendChild(s);
})();

function doLogout() {
  const token = localStorage.getItem("ntdap_token");
  if (token) fetch(`${API_BASE}/auth/logout`,{method:"POST",headers:{"Authorization":`Bearer ${token}`}}).catch(()=>{});
  localStorage.removeItem("ntdap_token");
  localStorage.removeItem("ntdap_user");
  sessionStorage.removeItem("ntdap_result");
  window.location.href = "login.html";
}

function requireLogin(redirect=true) {
  if (!localStorage.getItem("ntdap_token")) {
    if (redirect) window.location.href = "login.html";
    return false;
  }
  return true;
}

function requireAdmin() {
  if (!requireLogin()) return false;
  if (_getUser().role !== "admin") { window.location.href = "upload.html"; return false; }
  return true;
}

function fmt(n)      { return n!=null?Number(n).toLocaleString():"—"; }
function fmtBytes(b) {
  if(!b||b===0)return"0 B";if(b<1024)return b+" B";
  if(b<1048576)return(b/1024).toFixed(1)+" KB";
  if(b<1073741824)return(b/1048576).toFixed(2)+" MB";
  return(b/1073741824).toFixed(2)+" GB";
}
function severityColor(s){const m={NORMAL:"#10b981",LOW:"#00d4ff",MEDIUM:"#f59e0b",HIGH:"#ef4444",CRITICAL:"#ff3b3b"};return m[s]||"#8b949e";}
function severityBadge(s){return`<span class="sev-indicator sev-${s||'NORMAL'}">${s||'NORMAL'}</span>`;}
function protoBadge(proto){const cls=["HTTP","HTTPS","TCP","UDP","DNS","ICMP","ARP"].includes(proto)?`proto-${proto}`:"proto-OTHER";return`<span class="proto ${cls}">${proto||"—"}</span>`;}
function statCard(label,value,cls="",sub=""){return`<div class="stat-card ${cls}"><div class="stat-label">${label}</div><div class="stat-value">${value}</div>${sub?`<div class="stat-sub">${sub}</div>`:""}</div>`;}
function navRow(ph,pl,nh,nl){return`<div style="display:flex;gap:12px;justify-content:space-between;margin-top:36px;border-top:1px solid var(--border);padding-top:24px"><a href="${ph}" style="border:1px solid var(--border);color:var(--text);padding:10px 22px;border-radius:9px;font-weight:600;font-size:13px;text-decoration:none;transition:border-color .2s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">${pl}</a><a href="${nh}" style="background:var(--accent);color:#000;padding:10px 26px;border-radius:9px;font-weight:700;font-size:13px;text-decoration:none">${nl}</a></div>`;}
function sectionHead(label){return`<div class="section-title"><span class="dot"></span>${label}</div>`;}

function getResult() {
  if(!requireLogin(true))return null;
  const raw=sessionStorage.getItem("ntdap_result");
  if(!raw){document.body.innerHTML=`<div style="text-align:center;padding:120px 20px;font-family:'Space Grotesk',sans-serif;color:#8b949e;background:#030712;min-height:100vh"><div style="font-size:56px;margin-bottom:20px">📭</div><h2 style="color:#e6edf3;font-size:22px;margin-bottom:10px;font-weight:700">No Analysis Found</h2><p style="margin-bottom:24px">Please upload and analyse a PCAP file first.</p><a href="upload.html" style="background:#00d4ff;color:#000;padding:12px 28px;border-radius:10px;font-weight:700;text-decoration:none;font-size:14px">Upload a PCAP →</a></div>`;return null;}
  try{return JSON.parse(raw);}catch{return null;}
}
