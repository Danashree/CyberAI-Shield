function buildLayout(activePage) {
    const user    = getUser() || { name: 'User', role: 'analyst', avatar: 'U' };
    const initial = user.avatar || (user.name ? user.name[0].toUpperCase() : 'U');

    const navItems = [
        { id: 'dashboard', icon: '⊞', label: 'Dashboard',        href: 'dashboard.html' },
        { id: 'threats',   icon: '⚡', label: 'Threat Intel',     href: 'threats.html' },
        { id: 'alerts',    icon: '🔔', label: 'Alerts Center',    href: 'alerts.html' },
        { id: 'reports',   icon: '📄', label: 'Incident Reports', href: 'reports.html' },
        { id: 'socbot',    icon: '🤖', label: 'SOC Chatbot',      href: 'socbot.html' },
        // In navItems array, add these two entries:
        { id: 'analytics',   icon: '📊', label: 'Analytics',   href: 'analytics.html' },
        { id: 'remediation', icon: '🛠️', label: 'Remediation',  href: 'remediation.html' },
    ];    

    const topTabs = [
        { id: 'dashboard', label: 'Dashboard', href: 'dashboard.html' },
        { id: 'threats',   label: 'Threats',   href: 'threats.html' },
        { id: 'alerts',    label: 'Alerts',    href: 'alerts.html' },
        { id: 'reports',   label: 'Reports',   href: 'reports.html' },
        { id: 'socbot',    label: 'SOC Bot',   href: 'socbot.html' },
    ];

    const sidebarHTML = `
    <div class="sidebar">
      <div class="sidebar-logo">
        <div class="logo-icon">🛡️</div>
        <div>
          <div class="logo-text">CyberAI <span>Shield</span></div>
          <div class="logo-sub">V2.4 Enterprise</div>
        </div>
      </div>
      <div class="sidebar-section-label">Main Menu</div>
      ${navItems.map(n => `
        <a class="nav-item ${activePage === n.id ? 'active' : ''}" href="${n.href}">
          <span class="nav-icon">${n.icon}</span>
          ${n.label}
          ${n.id === 'alerts' ? `<span class="nav-badge" id="alerts-badge" style="display:none">0</span>` : ''}
        </a>
      `).join('')}
      <div class="sidebar-section-label" style="margin-top:6px">Tools</div>
      <a class="nav-item" href="#" onclick="openUpload();return false;">
        <span class="nav-icon">☁️</span> Upload Logs
      </a>
      <div class="sidebar-section-label" style="margin-top:6px">Config</div>
      <a class="nav-item ${activePage === 'settings' ? 'active' : ''}" href="settings.html">
        <span class="nav-icon">⚙️</span> Settings
      </a>
      <div class="sidebar-bottom">
        <div class="plan-badge">
          <div class="plan-name">Premium Plan</div>
          <div class="plan-status">V2.4.0 Active</div>
          <button class="btn-manage">MANAGE</button>
        </div>
        <div class="user-row">
          <div class="user-avatar" style="cursor:pointer"
               onclick="window.location.href='settings.html'">${initial}</div>
          <div>
            <div class="user-name">${user.name}</div>
            <div class="user-role">${user.role}</div>
          </div>
          <span style="margin-left:auto;cursor:pointer;color:var(--text-mute);font-size:16px"
                onclick="logout()" title="Logout">⏻</span>
        </div>
      </div>
    </div>`;

    const topbarHTML = `
    <div class="topbar">
      <div class="topbar-tabs">
        ${topTabs.map(t => `
          <a class="topbar-tab ${activePage === t.id ? 'active' : ''}" href="${t.href}">${t.label}</a>
        `).join('')}
      </div>
      <div class="topbar-right">
        <div class="search-box">
          <span style="font-size:12px;color:var(--text-mute)">🔍</span>
          <input type="text" placeholder="Search threats..."
                 onkeydown="if(event.key==='Enter')window.location.href='threats.html'">
        </div>
        <div class="icon-btn" onclick="window.location.href='alerts.html'">
          🔔<span class="notif-dot" id="topbar-notif-count" style="display:none">0</span>
        </div>
        <div class="user-avatar" style="cursor:pointer"
             onclick="window.location.href='settings.html'"
             title="${user.name} (${user.role})">${initial}</div>
        <div style="display:flex;flex-direction:column;line-height:1.2">
          <span style="font-size:12px;color:var(--text-pri);font-weight:600">${user.name}</span>
          <span style="font-size:10px;color:var(--text-mute);font-family:var(--font-mono)">
            ${user.role.toUpperCase()}
          </span>
        </div>
      </div>
    </div>`;

    const statusHTML = `
    <div class="statusbar">
      <div class="status-dot">SYSTEM: OPERATIONAL</div>
      <div class="status-dot cyan">AI CORE: SYNCING</div>
      <div class="status-dot amber">ML: READY</div>
      <div class="statusbar-right" id="clock"></div>
    </div>`;

    document.body.insertAdjacentHTML('afterbegin', '<div class="starfield"></div>');
    const layout = document.getElementById('app-layout');
    if (layout) {
        layout.insertAdjacentHTML('afterbegin', sidebarHTML);
        const mainArea = layout.querySelector('.main-area');
        if (mainArea) {
            mainArea.insertAdjacentHTML('afterbegin', topbarHTML);
            mainArea.insertAdjacentHTML('beforeend', statusHTML);
        }
    }

    // Live clock
    function updateClock() {
        const cl = document.getElementById('clock');
        if (cl) {
            cl.textContent = `CYBERAI SHIELD V2.4 — ${new Date().toISOString().replace('T',' ').slice(0,19)} UTC`;
        }
    }
    updateClock();
    setInterval(updateClock, 1000);

    // Update badge after layout builds
    setTimeout(updateAlertBadge, 600);
    setInterval(updateAlertBadge, 30000);
}


async function updateAlertBadge() {
    try {
        const token = getToken();
        if (!token) return;

        const res = await fetch('http://localhost:8000/threats/?limit=100', {
            headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) return;

        const data = await res.json();

        // ✅ dismissed alerts localStorage-ல இருந்து get பண்றோம்
        const dismissedIds = new Set(
            JSON.parse(localStorage.getItem('cyberai_dismissed_alerts') || '[]')
        );

        // ✅ dismissed ஆனதை கழிச்சு count பண்றோம்
        const unread = (data.threats || []).filter(t =>
            t.status === 'active' && !dismissedIds.has(t.id)
        ).length;

        // Sidebar badge
        const badge = document.getElementById('alerts-badge');
        if (badge) {
            if (unread > 0) {
                badge.textContent   = unread;
                badge.style.display = 'inline-flex';
            } else {
                badge.style.display = 'none';
            }
        }

        // Topbar bell
        const notifCount = document.getElementById('topbar-notif-count');
        if (notifCount) {
            if (unread > 0) {
                notifCount.textContent   = unread;
                notifCount.style.display = 'flex';
            } else {
                notifCount.style.display = 'none';
            }
        }

    } catch(e) {
        // Silent fail — badge just won't update
    }
}


function openUpload() {
    document.getElementById('upload-modal')?.classList.remove('hidden');
}

function closeUpload() {
    document.getElementById('upload-modal')?.classList.add('hidden');
}