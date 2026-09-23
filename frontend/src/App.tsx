import React, { useEffect, useState, useCallback } from 'react';
import { 
  Shield, 
  Server, 
  Database, 
  RefreshCw, 
  AlertTriangle, 
  XCircle, 
  Clock, 
  Lock,
  Layers
} from 'lucide-react';
import { fetchHealth } from './services/api';
import { HealthResponse } from './types/api';

export const App: React.FC = () => {
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const checkHealth = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchHealth();
      setHealthData(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to backend service');
      setHealthData(null);
    } finally {
      setLoading(false);
      setLastChecked(new Date());
    }
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      checkHealth();
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, checkHealth]);

  const isBackendHealthy = healthData?.status === 'ok';
  const isDbConnected = healthData?.database?.connected === true;

  return (
    <div className="container">
      {/* Top Navigation / Platform Banner */}
      <header style={{ marginBottom: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{
              width: '46px',
              height: '46px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.25), rgba(56, 189, 248, 0.1))',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--cyan-400)'
            }}>
              <Shield size={26} />
            </div>
            <div>
              <h1 style={{ fontSize: '1.45rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
                Attack Surface Intelligence & Risk Analysis Platform
              </h1>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                OSINT Reconnaissance • Multi-Source Correlation • Cryptographic Evidence • Explainable Risk
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span className="badge badge-neutral">
              Stage 0: Foundation
            </span>
            <button
              onClick={checkHealth}
              disabled={loading}
              className="btn btn-secondary"
              title="Refresh Health Status"
            >
              <RefreshCw size={15} className={loading ? 'spin' : ''} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              <span>{loading ? 'Checking...' : 'Refresh Status'}</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Status Grid */}
      <div className="grid-2" style={{ marginBottom: '2rem' }}>
        {/* Backend API Service Health Card */}
        <div className="glass-panel" style={{ padding: '1.75rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div style={{
                padding: '0.5rem',
                borderRadius: '8px',
                background: 'rgba(56, 189, 248, 0.1)',
                color: 'var(--cyan-400)'
              }}>
                <Server size={22} />
              </div>
              <div>
                <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>FastAPI Backend</h2>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>REST API Service</span>
              </div>
            </div>

            {error ? (
              <span className="badge badge-danger">
                <span className="pulse-dot pulse-danger" />
                Offline
              </span>
            ) : isBackendHealthy ? (
              <span className="badge badge-success">
                <span className="pulse-dot pulse-success" />
                Connected
              </span>
            ) : (
              <span className="badge badge-warning">
                <span className="pulse-dot pulse-warning" />
                Degraded
              </span>
            )}
          </div>

          {error ? (
            <div style={{
              background: 'rgba(251, 113, 133, 0.08)',
              border: '1px solid rgba(251, 113, 133, 0.25)',
              borderRadius: '8px',
              padding: '1rem',
              color: 'var(--rose-400)',
              fontSize: '0.875rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem', fontWeight: 600 }}>
                <XCircle size={16} /> Backend Unreachable
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{error}</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Service Name:</span>
                <span style={{ fontWeight: 500 }}>{healthData?.service}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Version / Environment:</span>
                <span className="font-mono" style={{ color: 'var(--cyan-400)' }}>
                  v{healthData?.version} ({healthData?.environment})
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Endpoint:</span>
                <span className="font-mono" style={{ color: 'var(--text-primary)' }}>GET /api/health</span>
              </div>
            </div>
          )}
        </div>

        {/* PostgreSQL Database Health Card */}
        <div className="glass-panel" style={{ padding: '1.75rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div style={{
                padding: '0.5rem',
                borderRadius: '8px',
                background: 'rgba(52, 211, 153, 0.1)',
                color: 'var(--emerald-400)'
              }}>
                <Database size={22} />
              </div>
              <div>
                <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>PostgreSQL Database</h2>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Docker Container Service</span>
              </div>
            </div>

            {isDbConnected ? (
              <span className="badge badge-success">
                <span className="pulse-dot pulse-success" />
                Active
              </span>
            ) : (
              <span className="badge badge-danger">
                <span className="pulse-dot pulse-danger" />
                Disconnected
              </span>
            )}
          </div>

          {!isDbConnected && healthData?.database?.error ? (
            <div style={{
              background: 'rgba(251, 113, 133, 0.08)',
              border: '1px solid rgba(251, 113, 133, 0.25)',
              borderRadius: '8px',
              padding: '1rem',
              color: 'var(--rose-400)',
              fontSize: '0.875rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem', fontWeight: 600 }}>
                <AlertTriangle size={16} /> Database Offline
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', wordBreak: 'break-all' }}>
                {healthData.database.error}
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Dialect / Driver:</span>
                <span className="font-mono" style={{ color: 'var(--emerald-400)' }}>
                  {healthData?.database?.dialect || 'postgresql (psycopg3)'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Query Latency:</span>
                <span className="font-mono" style={{ color: (healthData?.database?.latency_ms ?? 0) < 50 ? 'var(--emerald-400)' : 'var(--amber-400)' }}>
                  {healthData?.database?.latency_ms ? `${healthData.database.latency_ms} ms` : 'N/A'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Connection Probe:</span>
                <span className="font-mono" style={{ color: 'var(--text-primary)' }}>SELECT 1 (Success)</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Architecture & Pipeline Summary Panel */}
      <div className="glass-panel" style={{ padding: '1.75rem', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1.25rem' }}>
          <Layers size={20} style={{ color: 'var(--cyan-400)' }} />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Stage 0 Architecture Verification</h2>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          marginBottom: '1.5rem'
        }}>
          <div style={{
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center'
          }}>
            <div style={{ color: 'var(--cyan-400)', fontWeight: 600, marginBottom: '0.25rem' }}>Frontend</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>React + TS + Vite</div>
            <div style={{ marginTop: '0.5rem' }}>
              <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>Port 5173</span>
            </div>
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--cyan-400)',
            fontWeight: 700
          }}>
            ⇄ REST API / JSON ⇄
          </div>

          <div style={{
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center'
          }}>
            <div style={{ color: 'var(--cyan-400)', fontWeight: 600, marginBottom: '0.25rem' }}>Backend</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>FastAPI + SQLAlchemy</div>
            <div style={{ marginTop: '0.5rem' }}>
              <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>Port 8000</span>
            </div>
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--emerald-400)',
            fontWeight: 700
          }}>
            ⇄ SQLAlchemy Session ⇄
          </div>

          <div style={{
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center'
          }}>
            <div style={{ color: 'var(--emerald-400)', fontWeight: 600, marginBottom: '0.25rem' }}>Database</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>PostgreSQL 16 (Docker)</div>
            <div style={{ marginTop: '0.5rem' }}>
              <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>Port 5432</span>
            </div>
          </div>
        </div>

        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.8rem',
          color: 'var(--text-muted)',
          flexWrap: 'wrap',
          gap: '0.5rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={14} />
            <span>Last polled: {lastChecked ? lastChecked.toLocaleTimeString() : 'Never'}</span>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', color: 'var(--text-secondary)' }}>
            <input 
              type="checkbox" 
              checked={autoRefresh} 
              onChange={(e) => setAutoRefresh(e.target.checked)} 
            />
            Auto-refresh health (every 10s)
          </label>
        </div>
      </div>

      {/* Ethical & Security Policy Notice */}
      <footer style={{
        marginTop: '3rem',
        paddingTop: '1.5rem',
        borderTop: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
        color: 'var(--text-muted)',
        fontSize: '0.8rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Lock size={14} style={{ color: 'var(--cyan-400)' }} />
          <span>
            <strong>Ethical Assessment Notice:</strong> All reconnaissance and analysis modules must only target authorized domains and infrastructure.
          </span>
        </div>
        <div>
          <span>OSINT Intelligence Pipeline • Stage 0 Ready</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
