import React, { useState, useEffect } from 'react'
import { Shield, AlertTriangle, Activity, Globe, BarChart3, Bell, Settings, Radio, Target, TrendingUp, Zap, Eye, Clock, FileText } from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'
const API_BASE = '/api'
const ATTACK_COLORS = ['#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#10b981', '#3b82f6']

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
    (Array.isArray(series) ? series : [])
        .map((point) => ({
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

function ChartEmptyState({ message = 'Aucune donnée disponible pour le moment.' }) {
    return (
        <div style={{
            height: '280px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-secondary)',
            fontSize: '13px',
            border: '1px dashed var(--border-color)',
            borderRadius: '10px',
            background: 'var(--bg-primary)',
        }}>
            {message}
        </div>
    )
}

// ========================================
// ThreatScoreRing Component
// ========================================
function ThreatScoreRing({ score = 0.72 }) {
    const radius = 70
    const circumference = 2 * Math.PI * radius
    const offset = circumference - (score * circumference)

    const getColor = (s) => {
        if (s >= 0.8) return '#ef4444'
        if (s >= 0.5) return '#f59e0b'
        if (s >= 0.3) return '#3b82f6'
        return '#10b981'
    }

    return (
        <div className="threat-ring">
            <svg viewBox="0 0 160 160">
                <circle className="ring-bg" cx="80" cy="80" r={radius} />
                <circle
                    className="ring-fill"
                    cx="80" cy="80" r={radius}
                    stroke={getColor(score)}
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    style={{ filter: `drop-shadow(0 0 8px ${getColor(score)}40)` }}
                />
            </svg>
            <div className="threat-ring-value">
                <div className="score" style={{ color: getColor(score) }}>
                    {Math.round(score * 100)}
                </div>
                <div className="label">Threat Score</div>
            </div>
        </div>
    )
}

// ========================================
// StatCard Component
// ========================================
function StatCard({ label, value, icon: Icon, trend, trendDir, variant = '' }) {
    return (
        <div className={`stat-card ${variant} fade-in`}>
            <div className="stat-header">
                <span className="stat-label">{label}</span>
                <div className="stat-icon" style={{ background: variant === 'danger' ? 'rgba(239,68,68,0.15)' : variant === 'success' ? 'rgba(16,185,129,0.15)' : variant === 'warning' ? 'rgba(245,158,11,0.15)' : 'rgba(59,130,246,0.15)' }}>
                    <Icon size={18} color={variant === 'danger' ? '#ef4444' : variant === 'success' ? '#10b981' : variant === 'warning' ? '#f59e0b' : '#3b82f6'} />
                </div>
            </div>
            <div className="stat-value">{value}</div>
            {trend && <div className={`stat-trend ${trendDir}`}>{trend}</div>}
        </div>
    )
}

// ========================================
// AlertList Component
// ========================================
function AlertList({ alerts }) {
    const formatTime = (ts) => {
        const d = new Date(ts)
        const now = new Date()
        const diff = Math.floor((now - d) / 60000)
        if (diff < 1) return 'À l\'instant'
        if (diff < 60) return `Il y a ${diff}m`
        return `Il y a ${Math.floor(diff / 60)}h`
    }

    return (
        <div className="alert-list">
            {alerts.map((alert, i) => (
                <div key={alert.id} className="alert-item slide-in" style={{ animationDelay: `${i * 0.05}s` }}>
                    <div className={`alert-severity ${alert.severity}`} />
                    <div className="alert-info">
                        <div className="alert-type">
                            {alert.attack_type || 'Normal'} — {alert.src_ip}
                        </div>
                        <div className="alert-meta">
                            {formatTime(alert.timestamp)} • {alert.decision.replace(/_/g, ' ')}
                        </div>
                    </div>
                    <div className="alert-score">{Math.round(alert.threat_score * 100)}%</div>
                </div>
            ))}
        </div>
    )
}

// ========================================
// TrafficChart Component
// ========================================
function TrafficChart({ data }) {
    const hasData = Array.isArray(data) && data.some((point) => (
        Number(point?.normal || 0) > 0 ||
        Number(point?.suspicious || 0) > 0 ||
        Number(point?.attacks || 0) > 0
    ))

    if (!hasData) {
        return <ChartEmptyState message="Aucun trafic détecté sur la période sélectionnée." />
    }

    return (
        <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={data}>
                <defs>
                    <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradAttack" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#ef4444" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', fontSize: '12px', color: 'var(--text-primary)' }}
                    labelStyle={{ color: 'var(--text-secondary)' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                />
                <Area type="monotone" dataKey="normal" stroke="#3b82f6" fill="url(#gradNormal)" strokeWidth={2} name="Normal" />
                <Area type="monotone" dataKey="suspicious" stroke="#f59e0b" fill="transparent" strokeWidth={2} strokeDasharray="5 5" name="Suspicious" />
                <Area type="monotone" dataKey="attacks" stroke="#ef4444" fill="url(#gradAttack)" strokeWidth={2} name="Attacks" />
                <Legend />
            </AreaChart>
        </ResponsiveContainer>
    )
}

// ========================================
// AttackDistribution Component
// ========================================
function AttackDistribution({ data }) {
    const hasData = Array.isArray(data) && data.some((item) => Number(item?.value || 0) > 0)

    if (!hasData) {
        return <ChartEmptyState message="Aucune attaque distribuée à afficher." />
    }

    return (
        <ResponsiveContainer width="100%" height={280}>
            <PieChart>
                <Pie
                    data={data}
                    cx="50%" cy="50%"
                    innerRadius={60} outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                >
                    {data.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                    ))}
                </Pie>
                <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', fontSize: '12px' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                />
                <Legend
                    verticalAlign="bottom"
                    iconType="circle"
                    formatter={(value) => <span style={{ color: '#94a3b8', fontSize: '12px' }}>{value}</span>}
                />
            </PieChart>
        </ResponsiveContainer>
    )
}

// ========================================
// AttackMap Component (Leaflet Integration)
// ========================================
const attackIcon = L.divIcon({
    className: 'custom-attack-icon',
    html: '<div style="width: 14px; height: 14px; background: #ef4444; border-radius: 50%; box-shadow: 0 0 10px #ef4444, 0 0 20px #ef4444; border: 2px solid white;"></div>',
    iconSize: [14, 14],
    iconAnchor: [7, 7]
})

function AttackMap({ markers }) {
    const validMarkers = markers.filter(m => m.lat != null && m.lng != null);

    return (
        <div className="map-container" style={{ position: 'relative', background: 'var(--bg-card)', height: '400px', width: '100%', borderRadius: '12px', overflow: 'hidden' }}>
            <MapContainer
                center={[20, 0]}
                zoom={2}
                scrollWheelZoom={false}
                style={{ height: '100%', width: '100%' }}
            >
                <TileLayer
                    url="https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png"
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
                />
                {validMarkers.map((m, i) => (
                    <Marker key={i} position={[m.lat, m.lng]} icon={attackIcon}>
                        <Popup>
                            <div style={{ padding: '4px', color: '#111' }}>
                                <strong style={{ color: '#ef4444', display: 'block', marginBottom: '4px' }}>{m.ip}</strong>
                                <div style={{ marginBottom: '2px' }}>Localisation: {m.city || 'Inconnue'}, {m.country || 'Inconnu'}</div>
                                <div>Alertes: <strong>{m.alert_count}</strong></div>
                            </div>
                        </Popup>
                    </Marker>
                ))}
            </MapContainer>
        </div>
    )
}

// ========================================
// Timeline Component
// ========================================
function Timeline({ alerts }) {
    const formatTime = (ts) => new Date(ts).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })

    return (
        <div className="timeline">
            {alerts.slice(0, 6).map((a, i) => (
                <div key={a.id} className={`timeline-item ${a.severity}`}>
                    <div className="timeline-time">{formatTime(a.timestamp)}</div>
                    <div className="timeline-content">
                        <strong>{a.attack_type || 'Normal'}</strong> depuis {a.src_ip}
                        <br />
                        <span style={{ color: '#64748b', fontSize: '11px' }}>
                            Score: {Math.round(a.threat_score * 100)}% — {a.decision.replace(/_/g, ' ')}
                        </span>
                    </div>
                </div>
            ))}
        </div>
    )
}

// ========================================
// Sidebar Component
// ========================================
function Sidebar({ activeView, setActiveView }) {
    const navItems = [
        { id: 'overview', label: 'Vue d\'ensemble', icon: BarChart3 },
        { id: 'alerts', label: 'Alertes', icon: Bell },
        { id: 'traffic', label: 'Trafic réseau', icon: Activity },
        { id: 'map', label: 'Carte des attaques', icon: Globe },
        { id: 'reporting', label: 'Reporting IA', icon: FileText },
        { id: 'settings', label: 'Paramètres', icon: Settings },
    ]

    return (
        <aside className="sidebar">
            <div className="sidebar-logo">
                <div className="logo-icon">🛡️</div>
                <div>
                    <h1>NDS</h1>
                    <span>Network Defense System</span>
                </div>
            </div>
            <nav className="nav-items">
                {navItems.map(item => (
                    <button
                        key={item.id}
                        className={`nav-item ${activeView === item.id ? 'active' : ''}`}
                        onClick={() => setActiveView(item.id)}
                    >
                        <item.icon className="nav-icon" size={20} />
                        {item.label}
                    </button>
                ))}
            </nav>
            <div style={{ borderTop: '1px solid rgba(59,130,246,0.15)', paddingTop: '16px', marginTop: '8px' }}>
                <div className="nav-item" style={{ cursor: 'default' }}>
                    <Radio size={16} color="#10b981" />
                    <span style={{ fontSize: '12px', color: '#10b981' }}>Capture réseau</span>
                </div>
            </div>
        </aside>
    )
}

// ========================================
// Dashboard Overview
// ========================================
function DashboardOverview() {
    const [overview, setOverview] = useState(emptyOverview)
    const [alerts, setAlerts] = useState([])
    const [traffic, setTraffic] = useState([])
    const [distribution, setDistribution] = useState([])
    const [markers, setMarkers] = useState([])
    const [captureRunning, setCaptureRunning] = useState(false)
    const [captureMessage, setCaptureMessage] = useState('')
    const [captureInterfaces, setCaptureInterfaces] = useState([])
    const [selectedInterface, setSelectedInterface] = useState('auto')
    const [captureStats, setCaptureStats] = useState({ packets_captured: 0, active_flows: 0, completed_flows: 0 })

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
            setSelectedInterface(prev => (
                prev && prev !== 'auto'
                    ? prev
                    : (interfacesData?.configured_interface || 'auto')
            ))
            if (captureStatus?.last_error) {
                setCaptureMessage(`Erreur capture: ${captureStatus.last_error}`)
            }
        }

        load()
        const interval = setInterval(load, 5000)
        return () => {
            mounted = false
            clearInterval(interval)
        }
    }, [])

    const controlCapture = async (action) => {
        const response = await fetchAPI(`/detection/capture/${action}`, null, { method: 'POST' })
        if (response?.message) {
            setCaptureMessage(response.message)
        }
        if (response?.details?.last_error) {
            setCaptureMessage(`Erreur capture: ${response.details.last_error}`)
        }
        const status = await fetchAPI('/detection/capture/status', { is_running: false })
        setCaptureRunning(Boolean(status?.is_running))
        setCaptureStats(status || { packets_captured: 0, active_flows: 0, completed_flows: 0 })
        if (status?.last_error) {
            setCaptureMessage(`Erreur capture: ${status.last_error}`)
        }
    }


    const applyInterface = async () => {
        const response = await fetchAPI('/detection/capture/interface', null, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: selectedInterface || 'auto' }),
        })
        if (response?.message) {
            setCaptureMessage(response.message)
        }
    }

    const threatScore = Number(overview?.threat_score || 0)
    const criticalCount = Number(overview?.alerts_by_severity?.critical || 0)
    const flowsAnalyzed = Number(overview?.total_flows_analyzed || 0) || Number(captureStats?.packets_captured || 0)

    return (
        <>
            <div className="page-header">
                <div>
                    <h2>Vue d'ensemble</h2>
                    <div className="subtitle">Surveillance réseau en temps réel</div>
                </div>
                <div className="header-actions">
                    <div className="status-badge">
                        <span className="status-dot" />
                        {captureRunning ? 'Capture active' : 'Capture arrêtée'}
                    </div>
                    <select
                        className="nav-item"
                        value={selectedInterface}
                        onChange={(e) => setSelectedInterface(e.target.value)}
                        disabled={captureRunning}
                    >
                        <option value="auto">auto</option>
                        {captureInterfaces.map((iface) => (
                            <option key={iface} value={iface}>{iface}</option>
                        ))}
                    </select>
                    <button className="nav-item" onClick={applyInterface} disabled={captureRunning}>Appliquer interface</button>
                    <button className="nav-item" onClick={() => controlCapture('start')}>Démarrer capture</button>
                    <button className="nav-item" onClick={() => controlCapture('stop')}>Arrêter capture</button>
                </div>
            </div>

            {captureMessage && (
                <div className="panel" style={{ marginBottom: '16px', padding: '12px 16px', color: 'var(--text-secondary)' }}>
                    {captureMessage}
                </div>
            )}

            <div className="stats-grid">
                <StatCard
                    label="Menaces actives"
                    value={String(criticalCount)}
                    icon={AlertTriangle}
                    trend={`Total alertes: ${overview?.total_alerts || 0}`}
                    trendDir="up"
                    variant="danger"
                />
                <StatCard
                    label="Flux analysés"
                    value={String(flowsAnalyzed)}
                    icon={Activity}
                    trend={`Flows actifs: ${captureStats?.active_flows || 0}`}
                    variant=""
                />
                <StatCard
                    label="Anomalies détectées"
                    value={`${Math.round((overview?.anomaly_rate || 0) * 100)}%`}
                    icon={Eye}
                    trend="Taux d'anomalie"
                    variant="warning"
                />
                <StatCard
                    label="Taux de détection"
                    value={`${Math.round(threatScore * 100)}%`}
                    icon={Shield}
                    trend="Threat score global"
                    variant="success"
                />
            </div>

            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><Activity size={16} /> Trafic réseau (24h)</h3>
                        <span className="panel-badge">Temps réel</span>
                    </div>
                    <TrafficChart data={traffic} />
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <h3><Target size={16} /> Threat Score</h3>
                    </div>
                    <ThreatScoreRing score={threatScore} />
                    <div style={{ textAlign: 'center', marginTop: '8px' }}>
                        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            {threatScore >= 0.7 ? '⚠️ Niveau élevé - Investigation requise' :
                                threatScore >= 0.4 ? '🔵 Niveau modéré - Surveillance renforcée' :
                                    '✅ Niveau normal - Aucune action requise'}
                        </div>
                    </div>
                </div>
            </div>

            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><Bell size={16} /> Alertes récentes</h3>
                        <span className="panel-badge">{alerts.length}</span>
                    </div>
                    <AlertList alerts={alerts} />
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <h3><Clock size={16} /> Timeline</h3>
                    </div>
                    <Timeline alerts={alerts} />
                </div>
            </div>

            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><Globe size={16} /> Carte des attaques</h3>
                        <span className="panel-badge">{markers.length} sources</span>
                    </div>
                    <AttackMap markers={markers} />
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <h3><BarChart3 size={16} /> Distribution des attaques</h3>
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
        return () => {
            mounted = false
            clearInterval(interval)
        }
    }, [])

    return (
        <>
            <div className="page-header">
                <div>
                    <h2>Alertes</h2>
                    <div className="subtitle">Gestion et suivi des alertes de sécurité</div>
                </div>
            </div>
            <div className="panel">
                <div className="panel-header">
                    <h3><Bell size={16} /> Toutes les alertes</h3>
                    <span className="panel-badge">{alerts.length} alertes</span>
                </div>
                <AlertList alerts={alerts} />
            </div>
        </>
    )
}

// ========================================
// Traffic View
// ========================================
function TrafficView() {
    const [traffic, setTraffic] = useState([])
    const [distribution, setDistribution] = useState([])
    const [protocols, setProtocols] = useState([])

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
        return () => {
            mounted = false
            clearInterval(interval)
        }
    }, [])

    return (
        <>
            <div className="page-header">
                <div>
                    <h2>Trafic réseau</h2>
                    <div className="subtitle">Analyse détaillée du trafic capturé</div>
                </div>
            </div>
            <div className="panel" style={{ marginBottom: '20px' }}>
                <div className="panel-header">
                    <h3><Activity size={16} /> Volume de trafic (24h)</h3>
                </div>
                <TrafficChart data={traffic} />
            </div>
            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><TrendingUp size={16} /> Top protocoles</h3>
                    </div>
                    {Array.isArray(protocols) && protocols.some((p) => Number(p?.count || 0) > 0) ? (
                        <ResponsiveContainer width="100%" height={250}>
                            <BarChart data={protocols}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip
                                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px' }}
                                    itemStyle={{ color: 'var(--text-primary)' }}
                                    labelStyle={{ color: 'var(--text-secondary)' }}
                                />
                                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : (
                        <ChartEmptyState message="Aucune répartition protocolaire disponible." />
                    )}
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <h3><BarChart3 size={16} /> Distribution des attaques</h3>
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
        return () => {
            mounted = false
            clearInterval(interval)
        }
    }, [])

    return (
        <>
            <div className="page-header">
                <div>
                    <h2>Carte des attaques</h2>
                    <div className="subtitle">Géolocalisation des sources malveillantes</div>
                </div>
            </div>
            <div className="panel">
                <div className="panel-header">
                    <h3><Globe size={16} /> Carte mondiale</h3>
                    <span className="panel-badge">{markers.length} sources</span>
                </div>
                <AttackMap markers={markers} />
            </div>
        </>
    )
}


// ========================================
// Reporting View
// ========================================
function ReportingView() {
    const [period, setPeriod] = useState(24);
    const [detailLevel, setDetailLevel] = useState("Technical");
    const [loading, setLoading] = useState(false);
    const [report, setReport] = useState(null);
    const [error, setError] = useState(null);

    const handleGenerate = async () => {
        setLoading(true);
        setError(null);
        setReport(null);
        try {
            const res = await fetch(`${API_BASE}/reporting/generate?period_hours=${period}&detail_level=${detailLevel}&export_format=json`, {
                method: 'POST'
            });
            if (!res.ok) throw new Error("Erreur de l'API");
            const data = await res.json();
            setReport(data);
        } catch (err) {
            setError(err.message || 'Échec de la génération du rapport.');
        } finally {
            setLoading(false);
        }
    };

    const downloadFormat = async (format) => {
        try {
            const res = await fetch(`${API_BASE}/reporting/generate?period_hours=${period}&detail_level=${detailLevel}&export_format=${format}`, {
                method: 'POST'
            });
            if (!res.ok) throw new Error(`Erreur téléchargement ${format}`);

            if (format === 'json') {
                const data = await res.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `NDS_Report_${new Date().toISOString()}.${format}`;
                a.click();
            } else if (format === 'markdown') {
                const data = await res.json();
                const blob = new Blob([data.markdown], { type: 'text/markdown' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `NDS_Report_${new Date().toISOString()}.${format === 'markdown' ? 'md' : format}`;
                a.click();
            } else if (format === 'pdf') {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `NDS_Report_${new Date().toISOString()}.${format}`;
                a.click();
            }
        } catch (err) {
            alert(err.message || "Erreur lors de l'export.");
        }
    };

    return (
        <>
            <div className="page-header">
                <div>
                    <h2>Reporting IA</h2>
                    <div className="subtitle">Générer des rapports descriptifs de sécurité SOC par LLM</div>
                </div>
            </div>

            <div className="panel" style={{ marginBottom: '20px' }}>
                <div className="panel-header">
                    <h3><FileText size={16} /> Configuration du Rapport</h3>
                </div>
                <div style={{ display: 'flex', gap: '15px', alignItems: 'flex-end', paddingBottom: '10px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
                        <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Période (heures)</label>
                        <select className="nav-item" style={{ width: '150px' }} value={period} onChange={(e) => setPeriod(e.target.value)}>
                            <option value={24}>Dernières 24 Heures</option>
                            <option value={168}>7 Jours (168h)</option>
                            <option value={720}>30 Jours (720h)</option>
                        </select>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
                        <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Niveau de détail</label>
                        <select className="nav-item" style={{ width: '150px' }} value={detailLevel} onChange={(e) => setDetailLevel(e.target.value)}>
                            <option value="Technical">Technique / SOC</option>
                            <option value="Executive">Exécutif / Managérial</option>
                        </select>
                    </div>
                    <button className="nav-item" onClick={handleGenerate} disabled={loading} style={{ background: 'rgba(59, 130, 246, 0.1)', border: '1px solid #3b82f6', color: '#3b82f6' }}>
                        {loading ? 'Analyse par le LLM...' : 'Générer Synthèse'}
                    </button>
                    {report && (
                        <div style={{ display: 'flex', gap: '5px' }}>
                            <button className="nav-item" onClick={() => downloadFormat('pdf')}>Export PDF</button>
                            <button className="nav-item" onClick={() => downloadFormat('markdown')}>Export MD</button>
                            <button className="nav-item" onClick={() => downloadFormat('json')}>Export JSON</button>
                        </div>
                    )}
                </div>
                {error && <div style={{ color: '#ef4444', fontSize: '13px', marginTop: '10px' }}>{error}</div>}
            </div>

            {report && (
                <div className="dashboard-grid">
                    <div className="panel">
                        <div className="panel-header">
                            <h3><Target size={16} /> Threat Index Période</h3>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center', height: '100%' }}>
                            <ThreatScoreRing score={report.threat_index / 100} />
                            <div>
                                <div style={{ fontSize: '24px', fontWeight: 'bold' }}>{report.threat_index}/100</div>
                                <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>Score algorithmique</div>
                            </div>
                        </div>
                    </div>

                    <div className="panel">
                        <div className="panel-header">
                            <h3><TrendingUp size={16} /> Résumé Exécutif IA</h3>
                        </div>
                        <div style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.6' }}>
                            {report.llm_analysis?.executive_summary || "Pas de résumé."}
                        </div>
                    </div>
                </div>
            )}

            {report && (
                <div className="panel" style={{ marginTop: '20px' }}>
                    <div className="panel-header">
                        <h3><Zap size={16} /> Analyse Détaillée IA</h3>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                        <div>
                            <h4 style={{ marginBottom: '10px', color: 'var(--text-primary)' }}>Analyse Technique</h4>
                            <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.6', whiteSpace: 'pre-line' }}>{report.llm_analysis?.technical_analysis}</p>
                        </div>
                        <div>
                            <h4 style={{ marginBottom: '10px', color: 'var(--text-primary)' }}>Comportement des Attaquants</h4>
                            <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.6', whiteSpace: 'pre-line' }}>{report.llm_analysis?.attacker_behavior}</p>
                        </div>
                    </div>
                    <div style={{ marginTop: '20px', background: 'rgba(239, 68, 68, 0.05)', padding: '15px', borderRadius: '8px', borderLeft: '3px solid #ef4444' }}>
                        <h4 style={{ marginBottom: '10px', color: 'var(--text-primary)' }}>Recommandations d'Action</h4>
                        <ul style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.6', paddingLeft: '20px' }}>
                            {Array.isArray(report.llm_analysis?.recommendations)
                                ? report.llm_analysis.recommendations.map((r, i) => <li key={i}>{r}</li>)
                                : <li>{report.llm_analysis?.recommendations}</li>}
                        </ul>
                    </div>
                </div>
            )}

        </>
    )
}

// ========================================
// App Principal
// ========================================
export default function App() {
    const [activeView, setActiveView] = useState('overview')

    const renderView = () => {
        switch (activeView) {
            case 'overview': return <DashboardOverview />
            case 'alerts': return <AlertsView />
            case 'traffic': return <TrafficView />
            case 'map': return <MapView />
            case 'reporting': return <ReportingView />
            case 'settings': return (
                <div className="page-header">
                    <div>
                        <h2>Paramètres</h2>
                        <div className="subtitle">Configuration du système NDS</div>
                    </div>
                </div>
            )
            default: return <DashboardOverview />
        }
    }

    return (
        <div className="app-layout">
            <Sidebar activeView={activeView} setActiveView={setActiveView} />
            <main className="main-content">
                {renderView()}
            </main>
        </div>
    )
}
