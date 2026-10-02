import React, { useState } from 'react';
import { Shield, Lock, User, Mail, ArrowRight } from 'lucide-react';
import { HealthResponse } from '../../types/api';

interface AuthViewProps {
  onLogin: (username: string, pass: string) => Promise<void>;
  onRegister: (email: string, username: string, pass: string, fullName: string) => Promise<void>;
  loading: boolean;
  error: string | null;
  healthData: HealthResponse | null;
}

export const AuthView: React.FC<AuthViewProps> = ({
  onLogin,
  onRegister,
  loading,
  error,
  healthData,
}) => {
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('analyst_jane');
  const [password, setPassword] = useState('Password123!');
  const [fullName, setFullName] = useState('Jane Analyst');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (authMode === 'login') {
      await onLogin(username, password);
    } else {
      await onRegister(email, username, password, fullName);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem 1rem',
      background: 'radial-gradient(ellipse at top, #0f172a 0%, #020617 100%)'
    }}>
      {/* Brand Header */}
      <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <div style={{
          width: '56px',
          height: '56px',
          borderRadius: '14px',
          background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.3), rgba(56, 189, 248, 0.1))',
          border: '1px solid rgba(56, 189, 248, 0.4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--cyan-400)',
          margin: '0 auto 1rem auto',
          boxShadow: '0 0 25px rgba(14, 165, 233, 0.2)'
        }}>
          <Shield size={32} />
        </div>
        <h1 style={{ fontSize: '1.65rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          OSINT Attack Surface Analyzer
        </h1>
        <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Cybersecurity Intelligence & Contextual Risk Platform
        </p>
      </div>

      {/* Auth Card */}
      <div className="glass-panel" style={{ width: '100%', maxWidth: '440px', padding: '2.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
          <Lock size={20} color="var(--cyan-400)" />
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>
            {authMode === 'login' ? 'Analyst Authentication' : 'Create Analyst Account'}
          </h2>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginBottom: '1.25rem' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {authMode === 'register' && (
            <>
              <div className="form-group">
                <label className="form-label">Full Name</label>
                <div style={{ position: 'relative' }}>
                  <User size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
                  <input
                    type="text"
                    required
                    className="form-input"
                    value={fullName}
                    onChange={e => setFullName(e.target.value)}
                    placeholder="Jane Analyst"
                    style={{ paddingLeft: '2.25rem' }}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Email Address</label>
                <div style={{ position: 'relative' }}>
                  <Mail size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
                  <input
                    type="email"
                    required
                    className="form-input"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="analyst@domain.com"
                    style={{ paddingLeft: '2.25rem' }}
                  />
                </div>
              </div>
            </>
          )}

          <div className="form-group">
            <label className="form-label">Username</label>
            <div style={{ position: 'relative' }}>
              <User size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                required
                className="form-input"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="analyst_jane"
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="password"
                required
                className="form-input"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '0.75rem', marginTop: '0.5rem', fontSize: '0.9rem', fontWeight: 600 }}
          >
            <span>{loading ? 'Authenticating...' : authMode === 'login' ? 'Sign In to Workspace' : 'Register Account'}</span>
            <ArrowRight size={16} />
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          {authMode === 'login' ? (
            <span>
              Need an analyst account?{' '}
              <button
                onClick={() => setAuthMode('register')}
                style={{ background: 'none', border: 'none', color: 'var(--cyan-400)', cursor: 'pointer', fontWeight: 600 }}
              >
                Register
              </button>
            </span>
          ) : (
            <span>
              Already registered?{' '}
              <button
                onClick={() => setAuthMode('login')}
                style={{ background: 'none', border: 'none', color: 'var(--cyan-400)', cursor: 'pointer', fontWeight: 600 }}
              >
                Sign In
              </button>
            </span>
          )}
        </div>
      </div>

      {/* System Status Footer */}
      <div style={{ marginTop: '2rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <span className={`badge ${healthData?.database?.connected ? 'badge-success' : 'badge-danger'}`}>
          <span className={`pulse-dot ${healthData?.database?.connected ? 'pulse-success' : 'pulse-danger'}`}></span>
          {healthData?.database?.connected ? `PostgreSQL Database Connected (${healthData.database.latency_ms}ms)` : 'Database Disconnected'}
        </span>
      </div>
    </div>
  );
};

export default AuthView;
