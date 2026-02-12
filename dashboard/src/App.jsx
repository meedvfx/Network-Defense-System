import React, { useState, useEffect } from 'react'
import { Shield, AlertTriangle, Activity, Globe, BarChart3, Bell, Settings, Radio, Target, TrendingUp, Zap, Eye, Clock } from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

// ========================================
// DEMO DATA (utilisé quand l'API n'est pas connectée)
// ========================================
const DEMO_ALERTS = [
    { id: '1', severity: 'critical', attack_type: 'DDoS', threat_score: 0.94, src_ip: '185.220.101.34', decision: 'confirmed_attack', timestamp: new Date(Date.now() - 120000).toISOString() },
    { id: '2', severity: 'high', attack_type: 'PortScan', threat_score: 0.78, src_ip: '45.33.32.156', decision: 'suspicious', timestamp: new Date(Date.now() - 300000).toISOString() },
    { id: '3', severity: 'critical', attack_type: 'BruteForce', threat_score: 0.91, src_ip: '103.99.0.34', decision: 'confirmed_attack', timestamp: new Date(Date.now() - 600000).toISOString() },
    { id: '4', severity: 'medium', attack_type: 'WebAttack-XSS', threat_score: 0.56, src_ip: '192.168.1.105', decision: 'suspicious', timestamp: new Date(Date.now() - 900000).toISOString() },
    { id: '5', severity: 'high', attack_type: 'Botnet', threat_score: 0.82, src_ip: '23.94.143.68', decision: 'confirmed_attack', timestamp: new Date(Date.now() - 1200000).toISOString() },
    { id: '6', severity: 'low', attack_type: null, threat_score: 0.12, src_ip: '10.0.0.45', decision: 'normal', timestamp: new Date(Date.now() - 1500000).toISOString() },
    { id: '7', severity: 'critical', attack_type: 'DoS-SlowHTTPTest', threat_score: 0.95, src_ip: '193.35.18.175', decision: 'confirmed_attack', timestamp: new Date(Date.now() - 1800000).toISOString() },
    { id: '8', severity: 'medium', attack_type: 'Unknown Anomaly', threat_score: 0.63, src_ip: '87.236.176.23', decision: 'unknown_anomaly', timestamp: new Date(Date.now() - 2100000).toISOString() },
]

const DEMO_TRAFFIC = Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, '0')}:00`,
    normal: Math.floor(800 + Math.random() * 400),
    suspicious: Math.floor(20 + Math.random() * 60),
    attacks: Math.floor(5 + Math.random() * 25),
}))

const DEMO_DISTRIBUTION = [
    { name: 'DDoS', value: 34, color: '#ef4444' },
    { name: 'PortScan', value: 22, color: '#f59e0b' },
    { name: 'BruteForce', value: 18, color: '#8b5cf6' },
    { name: 'DoS', value: 12, color: '#ec4899' },
    { name: 'Botnet', value: 8, color: '#06b6d4' },
    { name: 'Web Attack', value: 6, color: '#10b981' },
]

const DEMO_GEO_MARKERS = [
    { ip: '185.220.101.34', lat: 51.5, lng: -0.12, country: 'UK', city: 'London', alert_count: 12 },
    { ip: '103.99.0.34', lat: 1.35, lng: 103.82, country: 'Singapore', city: 'Singapore', alert_count: 8 },
    { ip: '23.94.143.68', lat: 39.95, lng: -75.16, country: 'US', city: 'Philadelphia', alert_count: 15 },
    { ip: '193.35.18.175', lat: 52.52, lng: 13.40, country: 'Germany', city: 'Berlin', alert_count: 6 },
    { ip: '45.33.32.156', lat: 37.77, lng: -122.42, country: 'US', city: 'San Francisco', alert_count: 9 },
    { ip: '87.236.176.23', lat: 55.75, lng: 37.62, country: 'Russia', city: 'Moscow', alert_count: 21 },
]

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
                    contentStyle={{ background: '#1a1f35', border: '1px solid rgba(59,130,246,0.2)', borderRadius: '10px', fontSize: '12px' }}
                    labelStyle={{ color: '#94a3b8' }}
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
                    contentStyle={{ background: '#1a1f35', border: '1px solid rgba(59,130,246,0.2)', borderRadius: '10px', fontSize: '12px' }}
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
// AttackMap Component (placeholder sans Leaflet réel pour la démo)
// ========================================
function AttackMap({ markers }) {
    return (
        <div className="map-container" style={{ position: 'relative', background: '#0d1117' }}>
            <div style={{
                position: 'absolute', inset: 0,
                display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center',
                background: 'linear-gradient(180deg, rgba(59,130,246,0.05) 0%, rgba(139,92,246,0.05) 100%)',
                gap: '16px',
            }}>
                <Globe size={48} style={{ color: '#3b82f6', opacity: 0.5 }} />
                <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '16px', fontWeight: 600, marginBottom: '4px' }}>
                        Carte des Attaques Mondiales
                    </div>
                    <div style={{ fontSize: '13px', color: '#64748b' }}>
                        {markers.length} sources détectées • Leaflet s'activera avec npm install
                    </div>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center', maxWidth: '500px' }}>
                    {markers.map((m, i) => (
                        <div key={i} style={{
                            padding: '6px 12px', background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)',
                            borderRadius: '8px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px'
                        }}>
                            <Target size={12} color="#ef4444" />
                            <span style={{ color: '#f1f5f9', fontWeight: 500 }}>{m.ip}</span>
                            <span style={{ color: '#64748b' }}>— {m.city}, {m.country}</span>
                            <span style={{ color: '#ef4444', fontWeight: 600 }}>({m.alert_count})</span>
                        </div>
                    ))}
                </div>
            </div>
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
        { id: 'models', label: 'Modèles AI', icon: Zap },
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
                    <span style={{ fontSize: '12px', color: '#10b981' }}>Capture active</span>
                </div>
            </div>
        </aside>
    )
}

// ========================================
// Dashboard Overview
// ========================================
function DashboardOverview() {
    const [threatScore, setThreatScore] = useState(0.72)

    // Oscillation dynamique du threat score
    useEffect(() => {
        const interval = setInterval(() => {
            setThreatScore(prev => {
                const delta = (Math.random() - 0.5) * 0.04
                return Math.max(0.1, Math.min(0.95, prev + delta))
            })
        }, 3000)
        return () => clearInterval(interval)
    }, [])

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
                        Système opérationnel
                    </div>
                </div>
            </div>

            <div className="stats-grid">
                <StatCard
                    label="Menaces actives"
                    value="23"
                    icon={AlertTriangle}
                    trend="↑ +12% vs hier"
                    trendDir="up"
                    variant="danger"
                />
                <StatCard
                    label="Flux analysés"
                    value="1,247,832"
                    icon={Activity}
                    trend="87,234 /heure"
                    variant=""
                />
                <StatCard
                    label="Anomalies détectées"
                    value="156"
                    icon={Eye}
                    trend="Taux: 0.012%"
                    variant="warning"
                />
                <StatCard
                    label="Taux de détection"
                    value="99.2%"
                    icon={Shield}
                    trend="F1-Score: 0.987"
                    trendDir="down"
                    variant="success"
                />
            </div>

            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><Activity size={16} /> Trafic réseau (24h)</h3>
                        <span className="panel-badge">Temps réel</span>
                    </div>
                    <TrafficChart data={DEMO_TRAFFIC} />
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <h3><Target size={16} /> Threat Score</h3>
                    </div>
                    <ThreatScoreRing score={threatScore} />
                    <div style={{ textAlign: 'center', marginTop: '8px' }}>
                        <div style={{ fontSize: '13px', color: '#94a3b8' }}>
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
                        <span className="panel-badge">{DEMO_ALERTS.length}</span>
                    </div>
                    <AlertList alerts={DEMO_ALERTS} />
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <h3><Clock size={16} /> Timeline</h3>
                    </div>
                    <Timeline alerts={DEMO_ALERTS} />
                </div>
            </div>

            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><Globe size={16} /> Carte des attaques</h3>
                        <span className="panel-badge">{DEMO_GEO_MARKERS.length} sources</span>
                    </div>
                    <AttackMap markers={DEMO_GEO_MARKERS} />
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <h3><BarChart3 size={16} /> Distribution des attaques</h3>
                    </div>
                    <AttackDistribution data={DEMO_DISTRIBUTION} />
                </div>
            </div>
        </>
    )
}

// ========================================
// Alerts View
// ========================================
function AlertsView() {
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
                    <span className="panel-badge">{DEMO_ALERTS.length} alertes</span>
                </div>
                <AlertList alerts={DEMO_ALERTS} />
            </div>
        </>
    )
}

// ========================================
// Traffic View
// ========================================
function TrafficView() {
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
                <TrafficChart data={DEMO_TRAFFIC} />
            </div>
            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><TrendingUp size={16} /> Top protocoles</h3>
                    </div>
                    <ResponsiveContainer width="100%" height={250}>
                        <BarChart data={[
                            { name: 'TCP', count: 45720 },
                            { name: 'UDP', count: 12340 },
                            { name: 'ICMP', count: 890 },
                            { name: 'HTTP', count: 34560 },
                            { name: 'HTTPS', count: 67890 },
                            { name: 'DNS', count: 8900 },
                        ]}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip contentStyle={{ background: '#1a1f35', border: '1px solid rgba(59,130,246,0.2)', borderRadius: '10px' }} />
                            <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <h3><BarChart3 size={16} /> Distribution des attaques</h3>
                    </div>
                    <AttackDistribution data={DEMO_DISTRIBUTION} />
                </div>
            </div>
        </>
    )
}

// ========================================
// Map View
// ========================================
function MapView() {
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
                    <span className="panel-badge">{DEMO_GEO_MARKERS.length} sources</span>
                </div>
                <AttackMap markers={DEMO_GEO_MARKERS} />
            </div>
        </>
    )
}

// ========================================
// Models View
// ========================================
function ModelsView() {
    return (
        <>
            <div className="page-header">
                <div>
                    <h2>Modèles AI</h2>
                    <div className="subtitle">Gestion des modèles de Deep Learning</div>
                </div>
            </div>
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                <StatCard label="Modèle supervisé" value="MLP v1.0" icon={Zap} trend="Accuracy: 99.2%" variant="success" />
                <StatCard label="Modèle non-supervisé" value="AE v1.0" icon={Eye} trend="Seuil: 0.0234" variant="" />
                <StatCard label="Feedbacks en attente" value="47" icon={TrendingUp} trend="Prochain retrain: 53 restants" variant="warning" />
            </div>
            <div className="dashboard-grid">
                <div className="panel">
                    <div className="panel-header">
                        <h3><Zap size={16} /> Architecture supervisée</h3>
                    </div>
                    <div style={{ padding: '20px', fontSize: '13px', lineHeight: '1.8', color: '#94a3b8' }}>
                        <strong style={{ color: '#f1f5f9' }}>MLP (Multi-Layer Perceptron)</strong><br />
                        • Input → Dense(256, ReLU) → BN → Dropout(0.3)<br />
                        • → Dense(128, ReLU) → BN → Dropout(0.3)<br />
                        • → Dense(64, ReLU) → BN → Dropout(0.2)<br />
                        • → Dense(n_classes, Softmax)<br /><br />
                        <strong style={{ color: '#f1f5f9' }}>Métriques (v1.0.0)</strong><br />
                        • Classes: DDoS, PortScan, BruteForce, DoS, Botnet, Web Attack, BENIGN<br />
                        • F1-Score moyen: 0.987<br />
                        • Entraîné sur CIC-IDS2017 + CIC-IDS2018
                    </div>
                </div>
                <div className="panel">
                    <div className="panel-header">
                        <h3><Eye size={16} /> Autoencoder non-supervisé</h3>
                    </div>
                    <div style={{ padding: '20px', fontSize: '13px', lineHeight: '1.8', color: '#94a3b8' }}>
                        <strong style={{ color: '#f1f5f9' }}>Dense Autoencoder</strong><br />
                        • Encoder: Input → 64 → 32 → 16 → 8 (latent)<br />
                        • Decoder: 8 → 16 → 32 → 64 → Output<br />
                        • Loss: MSE (Mean Squared Error)<br /><br />
                        <strong style={{ color: '#f1f5f9' }}>Détection d'anomalies</strong><br />
                        • Seuil dynamique: μ + 3σ<br />
                        • Calibré sur le percentile 99<br />
                        • Détecte les attaques 0-day et comportements déviants
                    </div>
                </div>
            </div>
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
            case 'models': return <ModelsView />
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
