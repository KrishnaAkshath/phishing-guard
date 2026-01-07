import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

// Icons as components
const ShieldIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2ZM10 17L6 13L7.41 11.59L10 14.17L16.59 7.58L18 9L10 17Z" />
  </svg>
)

const DashboardIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" />
  </svg>
)

const SettingsIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z" />
  </svg>
)

const HistoryIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z" />
  </svg>
)

const ListIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
  </svg>
)

const BlockIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1C19.37 8.45 20 10.15 20 12c0 4.42-3.58 8-8 8z" />
  </svg>
)

const ChartIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M16 6l2.29 2.29-4.88 4.88-4-4L2 16.59 3.41 18l6-6 4 4 6.3-6.29L22 12V6z" />
  </svg>
)

const CheckIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
  </svg>
)

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [stats, setStats] = useState({ totalScans: 0, threatsBlocked: 0 })
  const [settings, setSettings] = useState({
    protection_level: 'medium',
    modules: {
      phishing_protection: true,
      password_guard: true,
      payment_protection: true,
      link_scanner: true
    },
    preferences: {
      real_time_alerts: true,
      auto_block_dangerous: true,
      notification_sound: false
    }
  })
  const [whitelist, setWhitelist] = useState([])
  const [blacklist, setBlacklist] = useState([])
  const [history, setHistory] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const [newDomain, setNewDomain] = useState('')

  useEffect(() => {
    checkConnection()
    loadData()
  }, [])

  const checkConnection = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`)
      const data = await res.json()
      setIsConnected(data.status === 'healthy')
    } catch {
      setIsConnected(false)
    }
  }

  const loadData = async () => {
    try {
      const statsRes = await fetch(`${API_BASE}/stats`)
      const statsData = await statsRes.json()
      setStats({
        totalScans: statsData.total_scans || 0,
        threatsBlocked: statsData.threats_detected || 0
      })
    } catch (e) {
      console.error('Failed to load data:', e)
    }
  }

  const toggleModule = (key) => {
    setSettings(prev => ({
      ...prev,
      modules: {
        ...prev.modules,
        [key]: !prev.modules[key]
      }
    }))
  }

  const togglePreference = (key) => {
    setSettings(prev => ({
      ...prev,
      preferences: {
        ...prev.preferences,
        [key]: !prev.preferences[key]
      }
    }))
  }

  const addToWhitelist = () => {
    if (newDomain && !whitelist.includes(newDomain)) {
      setWhitelist([...whitelist, newDomain])
      setNewDomain('')
    }
  }

  const addToBlacklist = () => {
    if (newDomain && !blacklist.includes(newDomain)) {
      setBlacklist([...blacklist, newDomain])
      setNewDomain('')
    }
  }

  const removeFromWhitelist = (domain) => {
    setWhitelist(whitelist.filter(d => d !== domain))
  }

  const removeFromBlacklist = (domain) => {
    setBlacklist(blacklist.filter(d => d !== domain))
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'settings':
        return <SettingsPage settings={settings} toggleModule={toggleModule} togglePreference={togglePreference} />
      case 'whitelist':
        return <WhitelistPage whitelist={whitelist} newDomain={newDomain} setNewDomain={setNewDomain} addToWhitelist={addToWhitelist} removeFromWhitelist={removeFromWhitelist} />
      case 'blacklist':
        return <BlacklistPage blacklist={blacklist} newDomain={newDomain} setNewDomain={setNewDomain} addToBlacklist={addToBlacklist} removeFromBlacklist={removeFromBlacklist} />
      case 'history':
        return <HistoryPage history={history} />
      case 'stats':
        return <StatsPage stats={stats} />
      default:
        return <DashboardPage stats={stats} settings={settings} isConnected={isConnected} />
    }
  }

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="logo-icon">
              <ShieldIcon />
            </div>
            <div className="logo-text">
              <span className="logo-name">Phishing Guard</span>
              <span className="logo-version">Dashboard v2.0</span>
            </div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Main</div>
            <a className={`nav-item ${currentPage === 'dashboard' ? 'active' : ''}`} onClick={() => setCurrentPage('dashboard')}>
              <DashboardIcon />
              <span>Dashboard</span>
            </a>
            <a className={`nav-item ${currentPage === 'stats' ? 'active' : ''}`} onClick={() => setCurrentPage('stats')}>
              <ChartIcon />
              <span>Statistics</span>
            </a>
            <a className={`nav-item ${currentPage === 'history' ? 'active' : ''}`} onClick={() => setCurrentPage('history')}>
              <HistoryIcon />
              <span>Scan History</span>
            </a>
          </div>

          <div className="nav-section">
            <div className="nav-section-title">Protection</div>
            <a className={`nav-item ${currentPage === 'whitelist' ? 'active' : ''}`} onClick={() => setCurrentPage('whitelist')}>
              <ListIcon />
              <span>Whitelist</span>
              {whitelist.length > 0 && <span className="nav-badge" style={{ background: 'var(--success)' }}>{whitelist.length}</span>}
            </a>
            <a className={`nav-item ${currentPage === 'blacklist' ? 'active' : ''}`} onClick={() => setCurrentPage('blacklist')}>
              <BlockIcon />
              <span>Blacklist</span>
              {blacklist.length > 0 && <span className="nav-badge">{blacklist.length}</span>}
            </a>
            <a className={`nav-item ${currentPage === 'settings' ? 'active' : ''}`} onClick={() => setCurrentPage('settings')}>
              <SettingsIcon />
              <span>Settings</span>
            </a>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="user-card">
            <div className="user-avatar">PG</div>
            <div className="user-info">
              <div className="user-name">Local User</div>
              <div className="user-plan">Pro Edition</div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {renderPage()}
      </main>
    </div>
  )
}

// Dashboard Page
function DashboardPage({ stats, settings, isConnected }) {
  const activeModules = Object.values(settings.modules).filter(Boolean).length

  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">Monitor your protection status and activity</p>
      </header>

      {/* Protection Status */}
      <div className="protection-hero">
        <div className="protection-ring">
          <svg viewBox="0 0 120 120">
            <circle className="ring-bg" cx="60" cy="60" r="54" />
            <circle className="ring-progress" cx="60" cy="60" r="54" style={{ strokeDashoffset: 0 }} />
          </svg>
          <div className="protection-icon">
            <CheckIcon />
          </div>
        </div>
        <div className="protection-info">
          <div className="protection-status">Protection Active</div>
          <p className="protection-message">
            All {activeModules} protection modules are running. Your browsing is secure.
          </p>
          <div className="protection-modules">
            <span className={`module-badge ${settings.modules.phishing_protection ? '' : 'inactive'}`}>🛡️ Phishing</span>
            <span className={`module-badge ${settings.modules.password_guard ? '' : 'inactive'}`}>🔐 Password</span>
            <span className={`module-badge ${settings.modules.payment_protection ? '' : 'inactive'}`}>💳 Payment</span>
            <span className={`module-badge ${settings.modules.link_scanner ? '' : 'inactive'}`}>🔗 Links</span>
          </div>
        </div>
        <div className="protection-action">
          <div style={{
            padding: '12px 20px',
            background: isConnected ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            borderRadius: '12px',
            border: `1px solid ${isConnected ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
            display: 'flex',
            alignItems: 'center',
            gap: '10px'
          }}>
            <div style={{
              width: '10px',
              height: '10px',
              borderRadius: '50%',
              background: isConnected ? '#22c55e' : '#ef4444',
              animation: 'pulse 2s infinite'
            }}></div>
            <span style={{ color: isConnected ? '#22c55e' : '#ef4444', fontWeight: 600 }}>
              {isConnected ? 'API Connected' : 'API Offline'}
            </span>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">
            <svg viewBox="0 0 24 24"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z" /></svg>
          </div>
          <div className="stat-value">{stats.totalScans.toLocaleString()}</div>
          <div className="stat-label">Total Scans</div>
          <div className="stat-change positive">↑ Active monitoring</div>
        </div>

        <div className="stat-card danger">
          <div className="stat-icon">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15h2v-2h-2v2zm0-4h2V7h-2v6z" /></svg>
          </div>
          <div className="stat-value">{stats.threatsBlocked.toLocaleString()}</div>
          <div className="stat-label">Threats Blocked</div>
          <div className="stat-change negative">⚡ Real-time protection</div>
        </div>

        <div className="stat-card success">
          <div className="stat-icon">
            <svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" /></svg>
          </div>
          <div className="stat-value">{activeModules}/4</div>
          <div className="stat-label">Active Modules</div>
          <div className="stat-change positive">✓ All systems go</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <svg viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z" /></svg>
          </div>
          <div className="stat-value">100%</div>
          <div className="stat-label">Uptime</div>
          <div className="stat-change positive">● Always on</div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Quick Actions</h3>
        </div>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <button className="btn btn-primary">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4C7.58 4 4.01 7.58 4.01 12C4.01 16.42 7.58 20 12 20C15.73 20 18.84 17.45 19.73 14H17.65C16.83 16.33 14.61 18 12 18C8.69 18 6 15.31 6 12C6 8.69 8.69 6 12 6C13.66 6 15.14 6.69 16.22 7.78L13 11H20V4L17.65 6.35Z" /></svg>
            Scan Current Tab
          </button>
          <button className="btn btn-secondary">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" /></svg>
            Add to Whitelist
          </button>
          <button className="btn btn-secondary">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1C19.37 8.45 20 10.15 20 12c0 4.42-3.58 8-8 8z" /></svg>
            Report Phishing
          </button>
        </div>
      </div>
    </>
  )
}

// Settings Page
function SettingsPage({ settings, toggleModule, togglePreference }) {
  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Settings</h1>
        <p className="page-subtitle">Configure your protection preferences</p>
      </header>

      <div className="settings-section">
        <h3 className="settings-title">Protection Modules</h3>
        <div className="settings-card">
          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">🛡️</div>
              <div className="settings-item-text">
                <h4>Phishing Protection</h4>
                <p>Detect and block phishing websites</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.modules.phishing_protection} onChange={() => toggleModule('phishing_protection')} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">🔐</div>
              <div className="settings-item-text">
                <h4>Password Guard</h4>
                <p>Protect password entry on untrusted sites</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.modules.password_guard} onChange={() => toggleModule('password_guard')} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">💳</div>
              <div className="settings-item-text">
                <h4>Payment Protection</h4>
                <p>Enhanced security for payment forms</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.modules.payment_protection} onChange={() => toggleModule('payment_protection')} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">🔗</div>
              <div className="settings-item-text">
                <h4>Link Scanner</h4>
                <p>Scan links before you click them</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.modules.link_scanner} onChange={() => toggleModule('link_scanner')} />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </div>
      </div>

      <div className="settings-section">
        <h3 className="settings-title">Preferences</h3>
        <div className="settings-card">
          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">🔔</div>
              <div className="settings-item-text">
                <h4>Real-time Alerts</h4>
                <p>Show notifications when threats are detected</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.preferences.real_time_alerts} onChange={() => togglePreference('real_time_alerts')} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">🚫</div>
              <div className="settings-item-text">
                <h4>Auto-block Dangerous Sites</h4>
                <p>Automatically block sites with high risk scores</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.preferences.auto_block_dangerous} onChange={() => togglePreference('auto_block_dangerous')} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="settings-item">
            <div className="settings-item-info">
              <div className="settings-item-icon">🔊</div>
              <div className="settings-item-text">
                <h4>Notification Sound</h4>
                <p>Play sound when threats are blocked</p>
              </div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={settings.preferences.notification_sound} onChange={() => togglePreference('notification_sound')} />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </div>
      </div>
    </>
  )
}

// Whitelist Page
function WhitelistPage({ whitelist, newDomain, setNewDomain, addToWhitelist, removeFromWhitelist }) {
  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Whitelist</h1>
        <p className="page-subtitle">Trusted domains that bypass security checks</p>
      </header>

      <div className="card" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', gap: '12px' }}>
          <input
            type="text"
            className="form-input"
            placeholder="Enter domain (e.g., example.com)"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addToWhitelist()}
            style={{ flex: 1 }}
          />
          <button className="btn btn-primary" onClick={addToWhitelist}>Add Domain</button>
        </div>
      </div>

      <div className="card">
        {whitelist.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>✓</div>
            <p>No whitelisted domains yet</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {whitelist.map((domain, i) => (
                  <tr key={i}>
                    <td><code style={{ color: 'var(--success)' }}>{domain}</code></td>
                    <td>Just now</td>
                    <td>
                      <button className="btn btn-sm btn-danger" onClick={() => removeFromWhitelist(domain)}>Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

// Blacklist Page
function BlacklistPage({ blacklist, newDomain, setNewDomain, addToBlacklist, removeFromBlacklist }) {
  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Blacklist</h1>
        <p className="page-subtitle">Blocked domains that are always flagged as dangerous</p>
      </header>

      <div className="card" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', gap: '12px' }}>
          <input
            type="text"
            className="form-input"
            placeholder="Enter domain to block (e.g., malicious-site.com)"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addToBlacklist()}
            style={{ flex: 1 }}
          />
          <button className="btn btn-danger" onClick={addToBlacklist}>Block Domain</button>
        </div>
      </div>

      <div className="card">
        {blacklist.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>🚫</div>
            <p>No blocked domains yet</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {blacklist.map((domain, i) => (
                  <tr key={i}>
                    <td><code style={{ color: 'var(--danger)' }}>{domain}</code></td>
                    <td>Just now</td>
                    <td>
                      <button className="btn btn-sm btn-secondary" onClick={() => removeFromBlacklist(domain)}>Unblock</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

// History Page
function HistoryPage({ history }) {
  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Scan History</h1>
        <p className="page-subtitle">Recent website scans and their results</p>
      </header>

      <div className="card">
        {history.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>📊</div>
            <p>No scan history yet. Browse the web with the extension active to see results here.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Website</th>
                  <th>Status</th>
                  <th>Risk Score</th>
                  <th>Scanned</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item, i) => (
                  <tr key={i}>
                    <td>{item.domain}</td>
                    <td><span className={`badge badge-${item.risk_level}`}>{item.risk_level}</span></td>
                    <td>{item.risk_score}%</td>
                    <td>{item.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

// Stats Page
function StatsPage({ stats }) {
  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Statistics</h1>
        <p className="page-subtitle">Detailed analytics about your protection</p>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.totalScans.toLocaleString()}</div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card danger">
          <div className="stat-value">{stats.threatsBlocked.toLocaleString()}</div>
          <div className="stat-label">Threats Blocked</div>
        </div>
        <div className="stat-card success">
          <div className="stat-value">{stats.totalScans > 0 ? Math.round(((stats.totalScans - stats.threatsBlocked) / stats.totalScans) * 100) : 100}%</div>
          <div className="stat-label">Safe Browsing Rate</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">24/7</div>
          <div className="stat-label">Protection Uptime</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Protection Summary</h3>
        </div>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.8 }}>
          Phishing Guard has been actively protecting your browsing experience.
          With <strong style={{ color: 'var(--text-primary)' }}>{stats.totalScans.toLocaleString()}</strong> total scans performed,
          the system has successfully blocked <strong style={{ color: 'var(--danger)' }}>{stats.threatsBlocked.toLocaleString()}</strong> potential threats.
          Your current protection effectiveness is excellent.
        </p>
      </div>
    </>
  )
}

export default App
