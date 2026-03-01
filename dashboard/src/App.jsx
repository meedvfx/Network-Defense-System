import React, { useState, useEffect, useCallback } from 'react'
import {
    Shield, AlertTriangle, Activity, Globe, BarChart3, Bell, Settings,
    Radio, Target, TrendingUp, Zap, Eye, Clock, FileText,
    ChevronLeft, ChevronRight, Menu, X, Sun, Moon,
    Download, RefreshCw, Wifi, WifiOff, Database, Layers
} from 'lucide-react'
import {
    AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
    XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'
import { useTheme } from './contexts/ThemeContext'

const API_BASE = '/api'
const ATTACK_COLORS = ['#f87171', '#fbbf24', '#a78bfa', '#f472b6', '#22d3ee', '#34d399', '#4f8ef7']

async function fetchAPI(endpoint, fallback = null, options = {}) {
    try {
        const res = await fetch(`${API_BASE}${endpoint}`, options)
        if (!res.ok) return fallback
        return await res.json()
    } catch {
        return fallback
    }
}

// ========================================
// Shared helpers
// ========================================
const emptyOverview = {
    threat_score: 0,
    total_alerts: 0,
    alerts_by_severity: {},
    anomaly_rate: 0,
    total_flows_analyzed: 0,
}

const toPieDistribution = (distribution = []) =>
    distribution.map((item, index) => ({
        name: String(item.label || item.name || 'Unknown'),
        value: Number(item.count || item.value || 0),
        color: ATTACK_COLORS[index % ATTACK_COLORS.length],
    }))

const normalizeTrafficSeries = (series = []) =>
    (Array.isArray(series) ? series : []).map((point) => ({
        time: String(point?.time || '--:--'),
        normal: Number(point?.normal || 0),
        suspicious: Number(point?.suspicious || 0),
        attacks: Number(point?.attacks || 0),
    }))

const normalizeProtocolDistribution = (distribution = []) =>
    (Array.isArray(distribution) ? distribution : [])
        .map((item) => ({
            name: String(item?.name || item?.label || 'UNKNOWN'),
            count: Number(item?.count || item?.value || 0),
        }))
        .filter((item) => item.count >= 0)
        .sort((a, b) => b.count - a.count)

function getSevClass(severity) {
    if (!severity) return 'low'
    const s = String(severity).toLowerCase()
    if (s === 'critical') return 'critical'
    if (s === 'high') return 'high'
    if (s === 'medium') return 'medium'
    return 'low'
}

// ========================================
// ChartEmptyState
// ========================================
function ChartEmptyState({ message = 'Aucune donnée disponible.' }) {
    return (
        <div className="chart-empty">
            <BarChart3 size={32} />
            <span>{message}</span>
        </div>
    )
}

// ========================================
// ThreatScoreRing
// ========================================
function ThreatScoreRing({ score = 0 }) {
    const radius = 70
    const circumference = 2 * Math.PI * radius
    const offset = circumference - (score * circumference)

    const getColor = (s) => {
        if (s >= 0.8) return '#f87171'
        if (s >= 0.5) return '#fbbf24'
        if (s >= 0.3) return '#4f8ef7'
        return '#34d399'
    }

    const getLabel = (s) => {
        if (s >= 0.8) return 'CRITIQUE'
        if (s >= 0.5) return 'ÉLEVÉ'
        if (s >= 0.3) return 'MODÉRÉ'
        return 'NORMAL'
    }

    return (
        <div style={{ textAlign: 'center' }}>
            <div className="threat-ring">
                <svg viewBox="0 0 160 160">
                    <circle className="ring-bg" cx="80" cy="80" r={radius} />
                    <circle
                        className="ring-fill"
                        cx="80" cy="80" r={radius}
                        stroke={getColor(score)}
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        style={{ filter: `drop-shadow(0 0 8px ${getColor(score)}60)` }}
                    />
                </svg>
                <div className="threat-ring-value">
                    <div className="score" style={{ color: getColor(score) }}>
                        {Math.round(score * 100)}
                    </div>
                    <div className="label">Threat Score</div>
                </div>
            </div>
            <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 14px',
                borderRadius: 'var(--radius-pill)',
                background: `${getColor(score)}18`,
                border: `1px solid ${getColor(score)}30`,
                fontSize: '11px',
                fontWeight: '700',
                letterSpacing: '1px',
                color: getColor(score),
                marginTop: '8px',
            }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: getColor(score), display: 'inline-block' }} />
                {getLabel(score)}
            </div>
        </div>
    )
}

// ========================================
// StatCard
// ========================================
function StatCard({ label, value, icon: Icon, trend, trendDir, variant = '', delay = 0 }) {
    const iconColors = {
        danger:  '#f87171',
        warning: '#fbbf24',
        success: '#34d399',
        '':      '#4f8ef7',
    }
    const iconBgs = {
        danger:  'rgba(248,113,113,0.12)',
        warning: 'rgba(251,191,36,0.12)',
        success: 'rgba(52,211,153,0.12)',
        '':      'rgba(79,142,247,0.12)',
    }
    const color = iconColors[variant] || iconColors['']
    const bg    = iconBgs[variant]   || iconBgs['']

    return (
        <div className={`stat-card ${variant} fade-in`} style={{ animationDelay: `${delay}s` }}>
            <div className="stat-header">
                <span className="stat-label">{label}</span>
                <div className="stat-icon" style={{ background: bg }}>
                    <Icon size={18} color={color} />
                </div>
            </div>
            <div className="stat-value">{value}</div>
            {trend && <div className={`stat-trend ${trendDir || ''}`}>{trend}</div>}
        </div>
    )
}

// ========================================
// AlertList — enhanced
// ========================================
function AlertList({ alerts, maxHeight = 360 }) {
    const formatTime = (ts) => {
        const d = new Date(ts)
        const now = new Date()
        const diff = Math.floor((now - d) / 60000)
        if (diff < 1) return 'À l\'instant'
        if (diff < 60) return `${diff}m`
        return `${Math.floor(diff / 60)}h`
    }

    if (!alerts.length) {
        return <ChartEmptyState message="Aucune alerte récente." />
    }

    return (
        <div className="alert-list" style={{ maxHeight }}>
            {alerts.map((alert, i) => {
                const sev = getSevClass(alert.severity)
                return (
                    <div key={alert.id || i} className="alert-item slide-in" style={{ animationDelay: `${i * 0.04}s` }}>
                        <div className={`alert-sev-bar ${sev}`} />
                        <div className="alert-info">
                            <div className="alert-type">
                                {alert.attack_type || 'Normal'} &mdash; <span className="font-mono" style={{ fontSize: '12px' }}>{alert.src_ip}</span>
                            </div>
                            <div className="alert-meta">
                                <span className="sev-pill" style={{ display: 'inline-block' }}>{sev.toUpperCase()}</span>
                                &nbsp;{formatTime(alert.timestamp)} &bull; {alert.decision?.replace(/_/g, ' ')}
                            </div>
                        </div>
                        <div className={`alert-score-chip ${sev}`}>
                            {Math.round(alert.threat_score * 100)}%
                        </div>
                    </div>
                )
            })}
        </div>
    )
}

// ========================================
// TrafficChart
// ========================================
function TrafficChart({ data }) {
    const hasData = Array.isArray(data) && data.some((p) =>
        Number(p?.normal || 0) > 0 || Number(p?.suspicious || 0) > 0 || Number(p?.attacks || 0) > 0
    )

    if (!hasData) return <ChartEmptyState message="Aucun trafic sur la période sélectionnée." />

    return (
        <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={data} margin={{ top: 8, right: 10, left: -10, bottom: 0 }}>
                <defs>
                    <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#4f8ef7" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#4f8ef7" stopOpacity={0.01} />
                    </linearGradient>
                    <linearGradient id="gradAttack" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f87171" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="#f87171" stopOpacity={0.01} />
                    </linearGradient>
                    <linearGradient id="gradSusp" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#fbbf24" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#fbbf24" stopOpacity={0.01} />
                    </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="4 4" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                <Tooltip
                    contentStyle={{
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '12px',
                        fontSize: '12px',
                        color: 'var(--text-primary)',
                        boxShadow: 'var(--shadow-lg)',
                        padding: '10px 14px',
                    }}
                    cursor={{ stroke: 'var(--border-strong)', strokeWidth: 1 }}
                />
                <Area type="monotone" dataKey="normal"     stroke="#4f8ef7" fill="url(#gradNormal)" strokeWidth={2.5} name="Normal" dot={false} activeDot={{ r: 4 }} />
                <Area type="monotone" dataKey="suspicious" stroke="#fbbf24" fill="url(#gradSusp)"   strokeWidth={2}   strokeDasharray="5 4" name="Suspect" dot={false} activeDot={{ r: 4 }} />
                <Area type="monotone" dataKey="attacks"    stroke="#f87171" fill="url(#gradAttack)" strokeWidth={2.5} name="Attaques" dot={false} activeDot={{ r: 4 }} />
                <Legend iconType="circle" iconSize={8} />
            </AreaChart>
        </ResponsiveContainer>
    )
}

// ========================================
// AttackDistribution
// ========================================
function AttackDistribution({ data }) {
    const hasData = Array.isArray(data) && data.some((item) => Number(item?.value || 0) > 0)
    if (!hasData) return <ChartEmptyState message="Aucune attaque distribuée à afficher." />

    return (
        <ResponsiveContainer width="100%" height={280}>
            <PieChart>
                <Pie data={data} cx="50%" cy="45%" innerRadius={58} outerRadius={90} paddingAngle={3} dataKey="value" strokeWidth={0}>
                    {data.map((entry, i) => (
                        <Cell key={i} fill={entry.color} stroke="none" />
                    ))}
                </Pie>
                <Tooltip
                    contentStyle={{
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '12px',
                        fontSize: '12px',
                        boxShadow: 'var(--shadow-lg)',
                        padding: '10px 14px',
                    }}
                />
                <Legend verticalAlign="bottom" iconType="circle" iconSize={8} />
            </PieChart>
        </ResponsiveContainer>
    )
}

// ========================================
// AttackMap
// ========================================
const attackIcon = L.divIcon({
    className: '',
    html: '<div style="width:13px;height:13px;background:#f87171;border-radius:50%;box-shadow:0 0 10px #f87171,0 0 20px #f87171;border:2px solid rgba(255,255,255,0.7);"></div>',
    iconSize: [13, 13],
    iconAnchor: [6, 6]
})

function AttackMap({ markers }) {
    const { theme } = useTheme()
    const tileUrl = theme === 'dark'
        ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
        : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
    const validMarkers = markers.filter(m => m.lat != null && m.lng != null)
    return (
        <div className="map-container">
            <MapContainer key={theme} center={[20, 0]} zoom={2} scrollWheelZoom={false} style={{ height: '100%', width: '100%' }}>
                <TileLayer
                    url={tileUrl}
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com">CARTO</a>'
                />
                {validMarkers.map((m, i) => (
                    <Marker key={i} position={[m.lat, m.lng]} icon={attackIcon}>
                        <Popup>
                            <div style={{ padding: '4px 2px', minWidth: '160px' }}>
                                <div style={{ fontWeight: 700, color: '#f87171', marginBottom: '6px', fontSize: '13px' }}>{m.ip}</div>
                                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '2px' }}>
                                    📍 {m.city || '—'}, {m.country || '—'}
                                </div>
                                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                                    🔔 {m.alert_count} alerte{m.alert_count > 1 ? 's' : ''}
                                </div>
                            </div>
                        </Popup>
                    </Marker>
                ))}
            </MapContainer>
        </div>
    )
}

// ========================================
// Timeline
// ========================================
function Timeline({ alerts }) {
    const formatTime = (ts) => new Date(ts).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

    if (!alerts.length) return <ChartEmptyState message="Aucun événement récent." />

    return (
        <div className="timeline">
            {alerts.slice(0, 7).map((a, i) => {
                const sev = getSevClass(a.severity)
                return (
                    <div key={a.id || i} className="timeline-item">
                        <div className={`timeline-dot ${sev}`} />
                        <div className="timeline-time">{formatTime(a.timestamp)}</div>
                        <div className="timeline-content">
                            <span className={`sev-pill ${sev}`} style={{ marginRight: 6 }}>{sev.toUpperCase()}</span>
                            {a.attack_type || 'Normal'} &mdash; {a.src_ip}
                        </div>
                        <div className="timeline-sub">
                            Score: {Math.round(a.threat_score * 100)}% · {a.decision?.replace(/_/g, ' ')}
                        </div>
                    </div>
                )
            })}
        </div>
    )
}

// ========================================
// Sidebar
// ========================================
function Sidebar({ activeView, setActiveView, collapsed, setCollapsed, captureRunning, alertCount }) {
    const navItems = [
        { id: 'overview',   label: 'Vue d\'ensemble',     icon: BarChart3,  group: 'SURVEILLANCE' },
        { id: 'alerts',     label: 'Alertes',              icon: Bell,       group: 'SURVEILLANCE', badge: alertCount > 0 ? alertCount : null },
        { id: 'traffic',    label: 'Trafic réseau',        icon: Activity,   group: 'ANALYSE' },
        { id: 'map',        label: 'Carte des attaques',   icon: Globe,      group: 'ANALYSE' },
        { id: 'reporting',  label: 'Reporting IA',         icon: FileText,   group: 'RAPPORTS' },
        { id: 'settings',   label: 'Paramètres',           icon: Settings,   group: 'SYSTÈME' },
    ]

    const groups = [...new Set(navItems.map(i => i.group))]

    return (
        <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
            {/* Collapse button */}
            <button className="sidebar-collapse-btn" onClick={() => setCollapsed(!collapsed)} title={collapsed ? 'Déplier' : 'Replier'}>
                {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
            </button>

            {/* Logo */}
            <div className="sidebar-logo">
                <div className="logo-icon">
                    <Shield size={20} color="white" />
                </div>
                <div className="logo-text">
                    <h1>NDS</h1>
                    <span>Network Defense</span>
                </div>
            </div>

            {/* Nav */}
            <nav className="nav-section">
                {groups.map(group => (
                    <React.Fragment key={group}>
                        <div className="nav-group-label">{group}</div>
                        {navItems.filter(i => i.group === group).map(item => (
                            <button
                                key={item.id}
                                className={`nav-item ${activeView === item.id ? 'active' : ''}`}
                                onClick={() => setActiveView(item.id)}
                                title={collapsed ? item.label : ''}
                            >
                                <span className="nav-item-icon"><item.icon size={18} /></span>
                                <span className="nav-item-label">{item.label}</span>
                                {item.badge && <span className="nav-badge">{item.badge > 99 ? '99+' : item.badge}</span>}
                            </button>
                        ))}
                    </React.Fragment>
                ))}
            </nav>

            {/* Footer / Capture status */}
            <div className="sidebar-footer">
                <div className={`capture-status ${captureRunning ? '' : 'inactive'}`} title={captureRunning ? 'Capture active' : 'Capture arrêtée'}>
                    <div className="capture-dot" />
                    <span className="capture-label">{captureRunning ? 'Capture active' : 'Capture arrêtée'}</span>
                </div>
            </div>
        </aside>
    )
}

// ========================================
// Dashboard Overview
// ========================================
function DashboardOverview() {
    const [overview, setOverview]             = useState(emptyOverview)
    const [alerts, setAlerts]                 = useState([])
    const [traffic, setTraffic]               = useState([])
    const [distribution, setDistribution]     = useState([])
    const [markers, setMarkers]               = useState([])
    const [captureRunning, setCaptureRunning] = useState(false)
    const [captureMessage, setCaptureMessage] = useState('')
    const [captureInterfaces, setCaptureInterfaces] = useState([])
    const [selectedInterface, setSelectedInterface] = useState('auto')
    const [captureStats, setCaptureStats]     = useState({ packets_captured: 0, active_flows: 0, completed_flows: 0 })

    useEffect(() => {
        let mounted = true
        const load = async () => {
            const [overviewData, recentAlerts, trafficData, attackData, mapData, captureStatus, interfacesData] = await Promise.all([
                fetchAPI('/dashboard/overview', emptyOverview),
                fetchAPI('/dashboard/recent-alerts', []),
                fetchAPI('/dashboard/traffic-timeseries', { series: [] }),
                fetchAPI('/dashboard/attack-distribution', { distribution: [] }),
                fetchAPI('/geo/attack-map', { markers: [] }),
                fetchAPI('/detection/capture/status', { is_running: false }),
                fetchAPI('/detection/capture/interfaces', { configured_interface: 'auto', available_interfaces: [] }),
            ])
            if (!mounted) return
            setOverview(overviewData || emptyOverview)
            setAlerts(Array.isArray(recentAlerts) ? recentAlerts : [])
            setTraffic(normalizeTrafficSeries(trafficData?.series || []))
            setDistribution(toPieDistribution(attackData?.distribution || []))
            setMarkers(mapData?.markers || [])
            setCaptureRunning(Boolean(captureStatus?.is_running))
            setCaptureStats(captureStatus || { packets_captured: 0, active_flows: 0, completed_flows: 0 })
            setCaptureInterfaces(interfacesData?.available_interfaces || [])
            setSelectedInterface(prev => prev && prev !== 'auto' ? prev : (interfacesData?.configured_interface || 'auto'))
            if (captureStatus?.last_error) setCaptureMessage(`Erreur: ${captureStatus.last_error}`)
        }
        load()
        const interval = setInterval(load, 5000)
        return () => { mounted = false; clearInterval(interval) }
    }, [])

    const controlCapture = async (action) => {
        const response = await fetchAPI(`/detection/capture/${action}`, null, { method: 'POST' })
        if (response?.message) setCaptureMessage(response.message)
        if (response?.details?.last_error) setCaptureMessage(`Erreur: ${response.details.last_error}`)
        const status = await fetchAPI('/detection/capture/status', { is_running: false })
        setCaptureRunning(Boolean(status?.is_running))
        setCaptureStats(status || { packets_captured: 0, active_flows: 0, completed_flows: 0 })
        if (status?.last_error) setCaptureMessage(`Erreur: ${status.last_error}`)
    }

    const applyInterface = async () => {
        const response = await fetchAPI('/detection/capture/interface', null, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: selectedInterface || 'auto' }),
        })
        if (response?.message) setCaptureMessage(response.message)
    }

    const threatScore     = Number(overview?.threat_score || 0)
    const criticalCount   = Number(overview?.alerts_by_severity?.critical || 0)
    const flowsAnalyzed   = Number(overview?.total_flows_analyzed || 0) || Number(captureStats?.packets_captured || 0)
    const anomalyRate     = Math.round((overview?.anomaly_rate || 0) * 100)

    return (
        <>
            {/* Page Header */}
            <div className="page-header">
                <div className="page-title-block">
                    <h2>Vue d'ensemble</h2>
                    <div className="subtitle">
                        <Radio size={13} /> Surveillance réseau en temps réel
                    </div>
                </div>
                <div className="header-actions">
                    <div className={`status-badge ${captureRunning ? '' : 'danger'}`}>
                        <span className="status-dot" />
                        {captureRunning ? 'Capture active' : 'Capture arrêtée'}
                    </div>
                </div>
            </div>

            {/* Capture Controls */}
            <div className="capture-controls">
                <Wifi size={16} color="var(--accent-primary)" />
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>Interface :</span>
                <select
                    className="form-select"
                    value={selectedInterface}
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    disabled={captureRunning}
                >
                    <option value="auto">auto</option>
                    {captureInterfaces.map((iface) => (
                        <option key={iface} value={iface}>{iface}</option>
                    ))}
                </select>
                <button className="btn btn-ghost" onClick={applyInterface} disabled={captureRunning}>
                    Appliquer
                </button>
                <div className="capture-divider" />
                <button className="btn btn-success" onClick={() => controlCapture('start')} disabled={captureRunning}>
                    <Wifi size={14} /> Démarrer
                </button>
                <button className="btn btn-danger" onClick={() => controlCapture('stop')} disabled={!captureRunning}>
                    <WifiOff size={14} /> Arrêter
                </button>
                {captureRunning && (
                    <>
                        <div className="capture-divider" />
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            <strong style={{ color: 'var(--text-primary)' }}>{captureStats?.packets_captured || 0}</strong> paquets &bull;&nbsp;
                            <strong style={{ color: 'var(--text-primary)' }}>{captureStats?.active_flows || 0}</strong> flows actifs
                        </span>
                    </>
                )}
            </div>

            {captureMessage && (
                <div className="info-message info" style={{ marginBottom: 'var(--grid-gap)' }}>
                    <Radio size={14} /> {captureMessage}
                </div>
            )}

            {/* Stat Cards */}
            <div className="stats-grid">
                <StatCard label="Menaces critiques" value={String(criticalCount)} icon={AlertTriangle}
                    trend={`Total alertes: ${overview?.total_alerts || 0}`} trendDir="up" variant="danger" delay={0} />
                <StatCard label="Flux analysés" value={String(flowsAnalyzed)} icon={Activity}
                    trend={`Flows actifs: ${captureStats?.active_flows || 0}`} variant="" delay={0.05} />
                <StatCard label="Taux d'anomalie" value={`${anomalyRate}%`} icon={Eye}
                    trend="Anomalies détectées" variant="warning" delay={0.1} />
                <StatCard label="Threat Score" value={`${Math.round(threatScore * 100)}%`} icon={Shield}
                    trend="Score global du réseau" variant="success" delay={0.15} />
            </div>

            {/* Traffic + Threat Ring */}
            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><Activity size={14} /></div>
                            Trafic réseau (24h)
                        </div>
                        <span className="panel-badge success">Temps réel</span>
                    </div>
                    <TrafficChart data={traffic} />
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><Target size={14} /></div>
                            Indice de menace
                        </div>
                    </div>
                    <ThreatScoreRing score={threatScore} />
                </div>
            </div>

            {/* Alerts + Timeline */}
            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><Bell size={14} /></div>
                            Alertes récentes
                        </div>
                        <span className={`panel-badge ${criticalCount > 0 ? 'danger' : ''}`}>{alerts.length} alertes</span>
                    </div>
                    <AlertList alerts={alerts} />
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><Clock size={14} /></div>
                            Timeline d'événements
                        </div>
                    </div>
                    <Timeline alerts={alerts} />
                </div>
            </div>

            {/* Map + Distribution */}
            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><Globe size={14} /></div>
                            Carte des attaques
                        </div>
                        <span className="panel-badge">{markers.length} sources</span>
                    </div>
                    <AttackMap markers={markers} />
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><BarChart3 size={14} /></div>
                            Distribution des attaques
                        </div>
                    </div>
                    <AttackDistribution data={distribution} />
                </div>
            </div>
        </>
    )
}

// ========================================
// Alerts View
// ========================================
function AlertsView() {
    const [alerts, setAlerts] = useState([])

    useEffect(() => {
        let mounted = true
        const load = async () => {
            const data = await fetchAPI('/alerts/?limit=100', [])
            if (mounted) setAlerts(Array.isArray(data) ? data : [])
        }
        load()
        const interval = setInterval(load, 5000)
        return () => { mounted = false; clearInterval(interval) }
    }, [])

    const counts = {
        critical: alerts.filter(a => getSevClass(a.severity) === 'critical').length,
        high:     alerts.filter(a => getSevClass(a.severity) === 'high').length,
        medium:   alerts.filter(a => getSevClass(a.severity) === 'medium').length,
        low:      alerts.filter(a => getSevClass(a.severity) === 'low').length,
    }

    return (
        <>
            <div className="page-header">
                <div className="page-title-block">
                    <h2>Alertes de sécurité</h2>
                    <div className="subtitle">Gestion et suivi des événements détectés</div>
                </div>
                <div className="header-actions">
                    <span className="panel-badge danger">{counts.critical} critiques</span>
                    <span className="panel-badge" style={{ background: 'rgba(251,191,36,0.12)', color: 'var(--accent-orange)' }}>{counts.high} élevées</span>
                    <span className="panel-badge">{alerts.length} total</span>
                </div>
            </div>

            {/* Summary mini-cards */}
            <div className="stats-grid" style={{ marginBottom: 'var(--grid-gap)' }}>
                {[
                    { label: 'Critiques',  value: counts.critical, variant: 'danger',  icon: AlertTriangle },
                    { label: 'Élevées',    value: counts.high,     variant: 'warning', icon: AlertTriangle },
                    { label: 'Moyennes',   value: counts.medium,   variant: '',        icon: Eye },
                    { label: 'Faibles',    value: counts.low,      variant: 'success', icon: Shield },
                ].map(c => (
                    <StatCard key={c.label} label={c.label} value={String(c.value)} icon={c.icon} variant={c.variant} />
                ))}
            </div>

            <div className="panel">
                <div className="panel-header">
                    <div className="panel-title">
                        <div className="panel-title-icon"><Bell size={14} /></div>
                        Toutes les alertes
                    </div>
                    <span className="panel-badge">{alerts.length} alertes</span>
                </div>
                <AlertList alerts={alerts} maxHeight={600} />
            </div>
        </>
    )
}

// ========================================
// Traffic View
// ========================================
function TrafficView() {
    const [traffic, setTraffic]           = useState([])
    const [distribution, setDistribution] = useState([])
    const [protocols, setProtocols]       = useState([])

    useEffect(() => {
        let mounted = true
        const load = async () => {
            const [trafficData, attackData, protocolData] = await Promise.all([
                fetchAPI('/dashboard/traffic-timeseries', { series: [] }),
                fetchAPI('/dashboard/attack-distribution', { distribution: [] }),
                fetchAPI('/dashboard/protocol-distribution', { distribution: [] }),
            ])
            if (!mounted) return
            setTraffic(normalizeTrafficSeries(trafficData?.series || []))
            setDistribution(toPieDistribution(attackData?.distribution || []))
            setProtocols(normalizeProtocolDistribution(protocolData?.distribution || []))
        }
        load()
        const interval = setInterval(load, 5000)
        return () => { mounted = false; clearInterval(interval) }
    }, [])

    return (
        <>
            <div className="page-header">
                <div className="page-title-block">
                    <h2>Trafic réseau</h2>
                    <div className="subtitle">Analyse détaillée du trafic capturé</div>
                </div>
            </div>

            <div className="panel" style={{ marginBottom: 'var(--section-gap)' }}>
                <div className="panel-header">
                    <div className="panel-title">
                        <div className="panel-title-icon"><Activity size={14} /></div>
                        Volume de trafic (24h)
                    </div>
                    <span className="panel-badge success">Temps réel</span>
                </div>
                <TrafficChart data={traffic} />
            </div>

            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><TrendingUp size={14} /></div>
                            Répartition par protocole
                        </div>
                    </div>
                    {Array.isArray(protocols) && protocols.some((p) => Number(p?.count || 0) > 0) ? (
                        <ResponsiveContainer width="100%" height={250}>
                            <BarChart data={protocols} margin={{ top: 5, right: 10, left: -15, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="4 4" vertical={false} />
                                <XAxis dataKey="name" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                                <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                                <Tooltip
                                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', boxShadow: 'var(--shadow-lg)', padding: '10px 14px' }}
                                    cursor={{ fill: 'var(--chart-grid)' }}
                                />
                                <Bar dataKey="count" radius={[5, 5, 0, 0]} name="Flux" maxBarSize={48}>
                                    {protocols.map((_, i) => (
                                        <Cell key={i} fill={ATTACK_COLORS[i % ATTACK_COLORS.length]} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    ) : (
                        <ChartEmptyState message="Aucune répartition protocolaire disponible." />
                    )}
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <div className="panel-title">
                            <div className="panel-title-icon"><BarChart3 size={14} /></div>
                            Distribution des attaques
                        </div>
                    </div>
                    <AttackDistribution data={distribution} />
                </div>
            </div>
        </>
    )
}

// ========================================
// Map View
// ========================================
function MapView() {
    const [markers, setMarkers] = useState([])

    useEffect(() => {
        let mounted = true
        const load = async () => {
            const data = await fetchAPI('/geo/attack-map', { markers: [] })
            if (mounted) setMarkers(data?.markers || [])
        }
        load()
        const interval = setInterval(load, 5000)
        return () => { mounted = false; clearInterval(interval) }
    }, [])

    return (
        <>
            <div className="page-header">
                <div className="page-title-block">
                    <h2>Carte des attaques</h2>
                    <div className="subtitle">Géolocalisation des sources malveillantes</div>
                </div>
                <div className="header-actions">
                    <span className="panel-badge danger">{markers.length} sources identifiées</span>
                </div>
            </div>
            <div className="panel">
                <div className="panel-header">
                    <div className="panel-title">
                        <div className="panel-title-icon"><Globe size={14} /></div>
                        Carte mondiale des menaces
                    </div>
                    <span className="panel-badge">{markers.length} marqueurs</span>
                </div>
                <AttackMap markers={markers} />

                {markers.length > 0 && (
                    <div style={{ marginTop: '20px' }}>
                        <div style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                            Top sources d'attaques
                        </div>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>IP</th>
                                    <th>Pays</th>
                                    <th>Ville</th>
                                    <th>Alertes</th>
                                </tr>
                            </thead>
                            <tbody>
                                {markers.slice(0, 10).map((m, i) => (
                                    <tr key={i}>
                                        <td style={{ color: 'var(--accent-red)' }}>{m.ip}</td>
                                        <td>{m.country || '—'}</td>
                                        <td>{m.city || '—'}</td>
                                        <td>
                                            <span className="sev-pill critical">{m.alert_count}</span>
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

// ========================================
// Reporting View — enhanced
// ========================================
function ReportingView() {
    const [period, setPeriod]           = useState(24)
    const [detailLevel, setDetailLevel] = useState('Technical')
    const [loading, setLoading]         = useState(false)
    const [report, setReport]           = useState(null)
    const [error, setError]             = useState(null)

    const handleGenerate = async () => {
        setLoading(true); setError(null); setReport(null)
        try {
            const res = await fetch(`${API_BASE}/reporting/generate?period_hours=${period}&detail_level=${detailLevel}&export_format=json`, { method: 'POST' })
            if (!res.ok) throw new Error("Erreur de l'API")
            setReport(await res.json())
        } catch (err) {
            setError(err.message || 'Échec de la génération du rapport.')
        } finally {
            setLoading(false)
        }
    }

    const downloadFormat = async (format) => {
        try {
            const res = await fetch(`${API_BASE}/reporting/generate?period_hours=${period}&detail_level=${detailLevel}&export_format=${format}`, { method: 'POST' })
            if (!res.ok) throw new Error(`Erreur téléchargement ${format}`)
            const ts = new Date().toISOString().slice(0, 19).replace('T', '_')
            if (format === 'pdf') {
                const blob = await res.blob()
                const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `NDS_Report_${ts}.pdf` })
                a.click()
            } else {
                const data = await res.json()
                const content = format === 'markdown' ? data.markdown : JSON.stringify(data, null, 2)
                const type    = format === 'markdown' ? 'text/markdown' : 'application/json'
                const ext     = format === 'markdown' ? 'md' : 'json'
                const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([content], { type })), download: `NDS_Report_${ts}.${ext}` })
                a.click()
            }
        } catch (err) {
            alert(err.message || "Erreur lors de l'export.")
        }
    }

    const threatPct = report ? report.threat_index : null

    return (
        <>
            <div className="page-header">
                <div className="page-title-block">
                    <h2>Reporting IA</h2>
                    <div className="subtitle">Génération de rapports SOC par LLM</div>
                </div>
            </div>

            {/* Config panel */}
            <div className="panel" style={{ marginBottom: 'var(--grid-gap)' }}>
                <div className="panel-header">
                    <div className="panel-title">
                        <div className="panel-title-icon"><FileText size={14} /></div>
                        Configuration du rapport
                    </div>
                </div>
                <div className="report-controls">
                    <div className="form-group">
                        <label className="form-label">Période</label>
                        <select className="form-select" value={period} onChange={(e) => setPeriod(Number(e.target.value))}>
                            <option value={24}>Dernières 24h</option>
                            <option value={168}>7 jours</option>
                            <option value={720}>30 jours</option>
                        </select>
                    </div>
                    <div className="form-group">
                        <label className="form-label">Niveau de détail</label>
                        <select className="form-select" value={detailLevel} onChange={(e) => setDetailLevel(e.target.value)}>
                            <option value="Technical">Technique / SOC</option>
                            <option value="Executive">Exécutif / Management</option>
                        </select>
                    </div>
                    <div className="form-group">
                        <label className="form-label">&nbsp;</label>
                        <button className="btn btn-primary" onClick={handleGenerate} disabled={loading}>
                            {loading ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Analyse LLM...</> : <><Zap size={14} /> Générer la synthèse</>}
                        </button>
                    </div>

                    {report && (
                        <div className="form-group">
                            <label className="form-label">Export</label>
                            <div style={{ display: 'flex', gap: 8 }}>
                                <button className="btn btn-ghost" onClick={() => downloadFormat('pdf')}>
                                    <Download size={13} /> PDF
                                </button>
                                <button className="btn btn-ghost" onClick={() => downloadFormat('markdown')}>
                                    <Download size={13} /> Markdown
                                </button>
                                <button className="btn btn-ghost" onClick={() => downloadFormat('json')}>
                                    <Download size={13} /> JSON
                                </button>
                            </div>
                        </div>
                    )}
                </div>
                {error && (
                    <div className="info-message error" style={{ marginTop: '14px' }}>
                        <AlertTriangle size={14} /> {error}
                    </div>
                )}
            </div>

            {/* Report content */}
            {report && (
                <>
                    {/* Metric cards */}
                    <div className="report-metric-row">
                        {[
                            { label: 'Threat Index', value: `${report.threat_index}/100` },
                            { label: 'Total alertes',  value: report.metrics?.total_alerts  ?? '—' },
                            { label: 'Flux analysés',  value: report.metrics?.total_flows   ?? '—' },
                            { label: 'Taux anomalie',  value: report.metrics?.anomaly_rate  != null ? `${Math.round(report.metrics.anomaly_rate * 100)}%` : '—' },
                        ].map(m => (
                            <div key={m.label} className="report-metric-card fade-in">
                                <div className="report-metric-label">{m.label}</div>
                                <div className="report-metric-value">{String(m.value)}</div>
                            </div>
                        ))}
                    </div>

                    {/* Executive Summary */}
                    <div className="executive-summary-card fade-in">
                        <h4><Zap size={14} /> Résumé Exécutif IA</h4>
                        <p>{report.llm_analysis?.executive_summary || 'Aucun résumé disponible.'}</p>
                    </div>

                    {/* Threat ring + detailed analysis */}
                    <div className="dashboard-grid" style={{ marginBottom: 'var(--grid-gap)' }}>
                        <div className="panel">
                            <div className="panel-header">
                                <div className="panel-title">
                                    <div className="panel-title-icon"><Target size={14} /></div>
                                    Analyse détaillée IA
                                </div>
                            </div>
                            {report.llm_analysis?.technical_analysis && (
                                <div className="report-section">
                                    <h4><Activity size={14} /> Analyse Technique</h4>
                                    <p style={{ fontSize: '14px', lineHeight: 1.7, color: 'var(--text-secondary)', whiteSpace: 'pre-line' }}>
                                        {report.llm_analysis.technical_analysis}
                                    </p>
                                </div>
                            )}
                            {report.llm_analysis?.attacker_behavior && (
                                <div className="report-section">
                                    <h4><Eye size={14} /> Comportement des Attaquants</h4>
                                    <p style={{ fontSize: '14px', lineHeight: 1.7, color: 'var(--text-secondary)', whiteSpace: 'pre-line' }}>
                                        {report.llm_analysis.attacker_behavior}
                                    </p>
                                </div>
                            )}
                        </div>

                        <div className="panel">
                            <div className="panel-header">
                                <div className="panel-title">
                                    <div className="panel-title-icon"><Target size={14} /></div>
                                    Threat Index
                                </div>
                            </div>
                            <ThreatScoreRing score={(report.threat_index || 0) / 100} />

                            {report.llm_analysis?.recommendations && (
                                <div className="report-section">
                                    <h4><AlertTriangle size={14} /> Recommandations</h4>
                                    {(Array.isArray(report.llm_analysis.recommendations)
                                        ? report.llm_analysis.recommendations
                                        : [report.llm_analysis.recommendations]
                                    ).map((r, i) => (
                                        <div key={i} className="recommendation-item">
                                            <div className="rec-number">{i + 1}</div>
                                            <div style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{r}</div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}
        </>
    )
}

// ========================================
// Settings View
// ========================================
function SettingsView() {
    const { theme, toggleTheme, density, setDensity, detailLevel, setDetailLevel, animations, setAnimations } = useTheme()
    const [activeSection, setActiveSection] = useState('apparence')

    const sections = [
        { id: 'apparence', label: 'Apparence',    icon: Sun },
        { id: 'affichage', label: 'Affichage',    icon: Layers },
        { id: 'systeme',   label: 'Système',      icon: Database },
    ]

    return (
        <>
            <div className="page-header">
                <div className="page-title-block">
                    <h2>Paramètres</h2>
                    <div className="subtitle">Configuration de l'interface NDS</div>
                </div>
            </div>

            <div className="settings-layout">
                {/* Settings nav */}
                <nav className="settings-nav">
                    {sections.map(s => (
                        <button
                            key={s.id}
                            className={`settings-nav-item ${activeSection === s.id ? 'active' : ''}`}
                            onClick={() => setActiveSection(s.id)}
                        >
                            <s.icon size={16} /> {s.label}
                        </button>
                    ))}
                </nav>

                {/* Settings panels */}
                <div className="settings-panel">
                    {activeSection === 'apparence' && (
                        <div className="settings-section fade-in">
                            <div className="settings-section-title">
                                <Sun size={18} /> Apparence & Thème
                            </div>

                            {/* Dark mode toggle */}
                            <div className="settings-row">
                                <div className="settings-info">
                                    <h4>Mode sombre</h4>
                                    <p>Basculer entre le thème clair et le thème sombre. La préférence est sauvegardée localement.</p>
                                </div>
                                <label className="toggle">
                                    <input type="checkbox" checked={theme === 'dark'} onChange={toggleTheme} />
                                    <div className="toggle-track">
                                        <div className="toggle-thumb" />
                                    </div>
                                </label>
                            </div>

                            {/* Theme preview */}
                            <div className="settings-row" style={{ alignItems: 'flex-start' }}>
                                <div className="settings-info">
                                    <h4>Thème actif</h4>
                                    <p>Sélectionnez votre thème préféré.</p>
                                </div>
                                <div className="radio-group">
                                    {[
                                        { value: 'dark',  label: '🌙 Sombre' },
                                        { value: 'light', label: '☀️ Clair' },
                                    ].map(opt => (
                                        <button
                                            key={opt.value}
                                            className={`radio-option ${theme === opt.value ? 'selected' : ''}`}
                                            onClick={() => { if (theme !== opt.value) toggleTheme() }}
                                        >
                                            {opt.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Animations */}
                            <div className="settings-row">
                                <div className="settings-info">
                                    <h4>Animations de l'interface</h4>
                                    <p>Activer les transitions et animations pour une expérience plus fluide.</p>
                                </div>
                                <label className="toggle">
                                    <input type="checkbox" checked={animations} onChange={(e) => setAnimations(e.target.checked)} />
                                    <div className="toggle-track">
                                        <div className="toggle-thumb" />
                                    </div>
                                </label>
                            </div>
                        </div>
                    )}

                    {activeSection === 'affichage' && (
                        <div className="settings-section fade-in">
                            <div className="settings-section-title">
                                <Layers size={18} /> Affichage & Densité
                            </div>

                            {/* Density */}
                            <div className="settings-row" style={{ alignItems: 'flex-start' }}>
                                <div className="settings-info">
                                    <h4>Densité d'affichage</h4>
                                    <p>Ajustez l'espacement des éléments selon vos préférences de confort visuel.</p>
                                </div>
                                <div className="radio-group">
                                    {[
                                        { value: 'compact', label: 'Compact' },
                                        { value: 'normal',  label: 'Normal' },
                                    ].map(opt => (
                                        <button
                                            key={opt.value}
                                            className={`radio-option ${density === opt.value ? 'selected' : ''}`}
                                            onClick={() => setDensity(opt.value)}
                                        >
                                            {opt.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Detail level */}
                            <div className="settings-row" style={{ alignItems: 'flex-start' }}>
                                <div className="settings-info">
                                    <h4>Niveau de détail du dashboard</h4>
                                    <p>Contrôlez la quantité d'informations affichées dans la vue d'ensemble.</p>
                                </div>
                                <div className="radio-group">
                                    {[
                                        { value: 'minimal', label: 'Minimal' },
                                        { value: 'full',    label: 'Complet' },
                                    ].map(opt => (
                                        <button
                                            key={opt.value}
                                            className={`radio-option ${detailLevel === opt.value ? 'selected' : ''}`}
                                            onClick={() => setDetailLevel(opt.value)}
                                        >
                                            {opt.label}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeSection === 'systeme' && (
                        <div className="settings-section fade-in">
                            <div className="settings-section-title">
                                <Database size={18} /> Informations système
                            </div>
                            <div className="settings-row">
                                <div className="settings-info">
                                    <h4>Version du dashboard</h4>
                                    <p>Interface NDS v2.0 — Enterprise SOC Edition</p>
                                </div>
                                <span className="panel-badge success">v2.0</span>
                            </div>
                            <div className="settings-row">
                                <div className="settings-info">
                                    <h4>Intervalle de rafraîchissement</h4>
                                    <p>Les données sont actualisées automatiquement toutes les 5 secondes.</p>
                                </div>
                                <span className="panel-badge">5s</span>
                            </div>
                            <div className="settings-row">
                                <div className="settings-info">
                                    <h4>Moteur IA</h4>
                                    <p>Hybrid Decision Engine — Modèles supervisé + non-supervisé</p>
                                </div>
                                <span className="panel-badge success">Actif</span>
                            </div>
                            <div className="settings-row">
                                <div className="settings-info">
                                    <h4>Réinitialiser les préférences</h4>
                                    <p>Restaure toutes les préférences d'affichage aux valeurs par défaut.</p>
                                </div>
                                <button className="btn btn-danger" onClick={() => {
                                    localStorage.clear()
                                    window.location.reload()
                                }}>
                                    Réinitialiser
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </>
    )
}

// ========================================
// App Root
// ========================================
export default function App() {
    const [activeView, setActiveView]   = useState('overview')
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
    const [mobileOpen, setMobileOpen]   = useState(false)
    const [captureRunning, setCaptureRunning] = useState(false)
    const [alertCount, setAlertCount]   = useState(0)
    const { theme, toggleTheme }        = useTheme()

    // Poll capture status + alert count for sidebar indicators
    useEffect(() => {
        const poll = async () => {
            const [status, alerts] = await Promise.all([
                fetchAPI('/detection/capture/status', { is_running: false }),
                fetchAPI('/alerts/?limit=100', []),
            ])
            setCaptureRunning(Boolean(status?.is_running))
            setAlertCount(Array.isArray(alerts)
                ? alerts.filter(a => getSevClass(a.severity) === 'critical').length
                : 0
            )
        }
        poll()
        const interval = setInterval(poll, 8000)
        return () => clearInterval(interval)
    }, [])

    const renderView = () => {
        switch (activeView) {
            case 'overview':  return <DashboardOverview />
            case 'alerts':    return <AlertsView />
            case 'traffic':   return <TrafficView />
            case 'map':       return <MapView />
            case 'reporting': return <ReportingView />
            case 'settings':  return <SettingsView />
            default:          return <DashboardOverview />
        }
    }

    return (
        <div className="app-layout">
            {/* Mobile overlay */}
            <div
                className={`sidebar-overlay ${mobileOpen ? 'visible' : ''}`}
                onClick={() => setMobileOpen(false)}
            />

            <Sidebar
                activeView={activeView}
                setActiveView={(v) => { setActiveView(v); setMobileOpen(false) }}
                collapsed={sidebarCollapsed}
                setCollapsed={setSidebarCollapsed}
                captureRunning={captureRunning}
                alertCount={alertCount}
            />

            <main className={`main-content ${sidebarCollapsed ? 'sidebar-collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
                {/* Top bar for mobile */}
                <div style={{
                    display: 'none',
                    padding: '12px 16px',
                    borderBottom: '1px solid var(--border-color)',
                    alignItems: 'center',
                    gap: '12px',
                    background: 'var(--bg-card)',
                    position: 'sticky',
                    top: 0,
                    zIndex: 100,
                }} className="mobile-topbar">
                    <button className="mobile-nav-btn" onClick={() => setMobileOpen(!mobileOpen)}>
                        {mobileOpen ? <X size={18} /> : <Menu size={18} />}
                    </button>
                    <span style={{ fontWeight: 700, background: 'var(--gradient-brand)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>NDS</span>
                    <div style={{ flex: 1 }} />
                    <button className="mobile-nav-btn" onClick={toggleTheme} title="Basculer le thème">
                        {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                    </button>
                </div>

                {/* Content area with theme toggle in top-right corner */}
                <div className="content-wrapper">
                    {/* Floating theme toggle */}
                    <button
                        onClick={toggleTheme}
                        title={theme === 'dark' ? 'Passer en mode clair' : 'Passer en mode sombre'}
                        style={{
                            position: 'fixed',
                            bottom: '24px',
                            right: '24px',
                            width: '44px',
                            height: '44px',
                            borderRadius: '50%',
                            background: 'var(--bg-card)',
                            border: '1px solid var(--border-color)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            cursor: 'pointer',
                            color: 'var(--text-secondary)',
                            boxShadow: 'var(--shadow-md)',
                            zIndex: 150,
                            transition: 'var(--transition-normal)',
                        }}
                        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent-primary)'; e.currentTarget.style.color = 'var(--accent-primary)' }}
                        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.color = 'var(--text-secondary)' }}
                    >
                        {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
                    </button>

                    {renderView()}
                </div>
            </main>
        </div>
    )
}

