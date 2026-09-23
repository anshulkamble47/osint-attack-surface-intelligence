import React, { useEffect, useState, useCallback } from 'react';
import { 
  Shield, 
  Layers,
  Search,
  User,
  Globe,
  FileText,
  AlertCircle,
  Lock
} from 'lucide-react';
import { 
  fetchHealth, 
  loginUser, 
  registerUser, 
  createInvestigation, 
  listInvestigations, 
  runCTDiscovery,
  listInvestigationAssets 
} from './services/api';
import { 
  HealthResponse, 
  UserResponse, 
  InvestigationResponse, 
  CTDiscoveryResponse, 
  AssetSummary 
} from './types/api';

export const App: React.FC = () => {
  // System Health
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);

  // Authentication State
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('osint_jwt'));
  const [currentUser, setCurrentUser] = useState<UserResponse | null>(() => {
    const saved = localStorage.getItem('osint_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [authEmail, setAuthEmail] = useState('');
  const [authUsername, setAuthUsername] = useState('analyst_jane');
  const [authPassword, setAuthPassword] = useState('Password123!');
  const [authFullName, setAuthFullName] = useState('Jane Analyst');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);

  // Investigation State
  const [investigations, setInvestigations] = useState<InvestigationResponse[]>([]);
  const [selectedInv, setSelectedInv] = useState<InvestigationResponse | null>(null);
  const [invName, setInvName] = useState('Acme External Attack Surface');
  const [invDomain, setInvDomain] = useState('example.com');
  const [invOrg, setInvOrg] = useState('Acme Corporation');
  const [creatingInv, setCreatingInv] = useState(false);
  const [invError, setInvError] = useState<string | null>(null);

  // CT Discovery State
  const [runningCT, setRunningCT] = useState(false);
  const [ctResult, setCTResult] = useState<CTDiscoveryResponse | null>(null);
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [ctError, setCTError] = useState<string | null>(null);

  // Probe health
  const checkHealth = useCallback(async () => {
    try {
      const data = await fetchHealth();
      setHealthData(data);
    } catch {
      setHealthData(null);
    }
  }, []);

  // Fetch investigations
  const loadInvestigations = useCallback(async (authToken: string) => {
    try {
      const list = await listInvestigations(authToken);
      setInvestigations(list);
      if (list.length > 0 && !selectedInv) {
        setSelectedInv(list[0]);
      }
    } catch (err: any) {
      console.error('Failed to load investigations:', err);
    }
  }, [selectedInv]);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  useEffect(() => {
    if (token) {
      loadInvestigations(token);
    }
  }, [token, loadInvestigations]);

  // Load assets when selected investigation changes
  useEffect(() => {
    if (token && selectedInv) {
      listInvestigationAssets(token, selectedInv.id)
        .then(setAssets)
        .catch(console.error);
    }
  }, [token, selectedInv, ctResult]);

  // Handle Login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);
    try {
      const res = await loginUser(authUsername, authPassword);
      setToken(res.access_token);
      setCurrentUser(res.user);
      localStorage.setItem('osint_jwt', res.access_token);
      localStorage.setItem('osint_user', JSON.stringify(res.user));
      await loadInvestigations(res.access_token);
    } catch (err: any) {
      setAuthError(err.message || 'Login failed');
    } finally {
      setAuthLoading(false);
    }
  };

  // Handle Registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);
    try {
      await registerUser(authEmail, authUsername, authPassword, authFullName);
      // Auto login after register
      const loginRes = await loginUser(authUsername, authPassword);
      setToken(loginRes.access_token);
      setCurrentUser(loginRes.user);
      localStorage.setItem('osint_jwt', loginRes.access_token);
      localStorage.setItem('osint_user', JSON.stringify(loginRes.user));
      await loadInvestigations(loginRes.access_token);
    } catch (err: any) {
      setAuthError(err.message || 'Registration failed');
    } finally {
      setAuthLoading(false);
    }
  };

  // Handle Logout
  const handleLogout = () => {
    setToken(null);
    setCurrentUser(null);
    setSelectedInv(null);
    setCTResult(null);
    setAssets([]);
    localStorage.removeItem('osint_jwt');
    localStorage.removeItem('osint_user');
  };

  // Handle Create Investigation
  const handleCreateInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setCreatingInv(true);
    setInvError(null);
    try {
      const created = await createInvestigation(token, invName, invDomain, invOrg);
      setInvestigations(prev => [created, ...prev]);
      setSelectedInv(created);
      setCTResult(null);
      setInvName('');
      setInvDomain('');
      setInvOrg('');
    } catch (err: any) {
      setInvError(err.message || 'Failed to create investigation');
    } finally {
      setCreatingInv(false);
    }
  };

  // Handle Run CT Discovery
  const handleRunCT = async () => {
    if (!token || !selectedInv) return;
    setRunningCT(true);
    setCTError(null);
    try {
      const res = await runCTDiscovery(token, selectedInv.id);
      setCTResult(res);
      // Reload assets
      const updatedAssets = await listInvestigationAssets(token, selectedInv.id);
      setAssets(updatedAssets);
    } catch (err: any) {
      setCTError(err.message || 'Certificate Transparency discovery failed');
    } finally {
      setRunningCT(false);
    }
  };

  return (
    <div className="container">
      {/* Header */}
      <header style={{ marginBottom: '2rem' }}>
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
              <h1 style={{ fontSize: '1.35rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
                Attack Surface Intelligence & Risk Platform
              </h1>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Stage 3A: Investigation & Certificate Transparency Discovery
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {currentUser && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(30, 41, 59, 0.5)', padding: '0.35rem 0.75rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <User size={14} color="var(--cyan-400)" />
                <span style={{ fontSize: '0.85rem', fontWeight: 500 }}>{currentUser.username}</span>
                <span className="badge badge-neutral" style={{ fontSize: '0.7rem', padding: '0.15rem 0.45rem' }}>{currentUser.role}</span>
                <button onClick={handleLogout} className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}>Log out</button>
              </div>
            )}
            <span className={`badge ${healthData?.database?.connected ? 'badge-success' : 'badge-danger'}`}>
              <span className={`pulse-dot ${healthData?.database?.connected ? 'pulse-success' : 'pulse-danger'}`}></span>
              {healthData?.database?.connected ? `PostgreSQL Connected (${healthData.database.latency_ms}ms)` : 'PostgreSQL Disconnected'}
            </span>
          </div>
        </div>
      </header>

      {/* Auth Section if Not Logged In */}
      {!token ? (
        <div className="glass-panel" style={{ padding: '2rem', maxWidth: '480px', margin: '2rem auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
            <Lock size={20} color="var(--cyan-400)" />
            <h2 style={{ fontSize: '1.15rem', fontWeight: 600 }}>
              {authMode === 'login' ? 'Analyst Authentication' : 'Register Analyst Account'}
            </h2>
          </div>

          {authError && <div className="alert alert-error">{authError}</div>}

          <form onSubmit={authMode === 'login' ? handleLogin : handleRegister}>
            {authMode === 'register' && (
              <>
                <div className="form-group">
                  <label className="form-label">Email Address</label>
                  <input
                    type="email"
                    required
                    className="form-input"
                    value={authEmail}
                    onChange={e => setAuthEmail(e.target.value)}
                    placeholder="analyst@domain.com"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Full Name</label>
                  <input
                    type="text"
                    className="form-input"
                    value={authFullName}
                    onChange={e => setAuthFullName(e.target.value)}
                    placeholder="Jane Analyst"
                  />
                </div>
              </>
            )}

            <div className="form-group">
              <label className="form-label">Username / Email</label>
              <input
                type="text"
                required
                className="form-input"
                value={authUsername}
                onChange={e => setAuthUsername(e.target.value)}
                placeholder="analyst_jane"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                required
                className="form-input"
                value={authPassword}
                onChange={e => setAuthPassword(e.target.value)}
                placeholder="••••••••"
              />
            </div>

            <button type="submit" disabled={authLoading} className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }}>
              {authLoading ? 'Authenticating...' : authMode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <div style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            {authMode === 'login' ? (
              <span>Need an account? <button onClick={() => { setAuthMode('register'); setAuthError(null); }} style={{ background: 'none', border: 'none', color: 'var(--cyan-400)', cursor: 'pointer', textDecoration: 'underline' }}>Register</button></span>
            ) : (
              <span>Already registered? <button onClick={() => { setAuthMode('login'); setAuthError(null); }} style={{ background: 'none', border: 'none', color: 'var(--cyan-400)', cursor: 'pointer', textDecoration: 'underline' }}>Sign In</button></span>
            )}
          </div>
        </div>
      ) : (
        /* Authenticated Stage 3A Flow */
        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1.5rem', alignItems: 'start' }}>
          
          {/* Left Column: Investigation Management */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Create Investigation Card */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                <Globe size={18} color="var(--cyan-400)" />
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>New Investigation</h3>
              </div>

              {invError && <div className="alert alert-error" style={{ padding: '0.5rem', fontSize: '0.8rem' }}>{invError}</div>}

              <form onSubmit={handleCreateInvestigation}>
                <div className="form-group">
                  <label className="form-label">Target Domain</label>
                  <input
                    type="text"
                    required
                    className="form-input"
                    value={invDomain}
                    onChange={e => setInvDomain(e.target.value)}
                    placeholder="example.com"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Investigation Title</label>
                  <input
                    type="text"
                    required
                    className="form-input"
                    value={invName}
                    onChange={e => setInvName(e.target.value)}
                    placeholder="Q1 Audit"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Organization (Optional)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={invOrg}
                    onChange={e => setInvOrg(e.target.value)}
                    placeholder="Acme Corp"
                  />
                </div>

                <button type="submit" disabled={creatingInv} className="btn btn-primary" style={{ width: '100%' }}>
                  {creatingInv ? 'Validating...' : 'Create Assessment'}
                </button>
              </form>
            </div>

            {/* Investigations List */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                Active Investigations ({investigations.length})
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '280px', overflowY: 'auto' }}>
                {investigations.map(inv => (
                  <div
                    key={inv.id}
                    onClick={() => { setSelectedInv(inv); setCTResult(null); }}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      background: selectedInv?.id === inv.id ? 'rgba(14, 165, 233, 0.15)' : 'rgba(15, 23, 42, 0.4)',
                      border: `1px solid ${selectedInv?.id === inv.id ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{inv.target_domain}</span>
                      <span className="badge badge-neutral" style={{ fontSize: '0.65rem', padding: '0.1rem 0.35rem' }}>{inv.status}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{inv.reference_code}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column: CT Discovery & Discovered Assets */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {selectedInv ? (
              <>
                {/* Active Investigation Control Banner */}
                <div className="glass-panel" style={{ padding: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span className="badge badge-neutral font-mono">{selectedInv.reference_code}</span>
                        <span className="badge badge-success">{selectedInv.status}</span>
                      </div>
                      <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>{selectedInv.target_domain}</h2>
                      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{selectedInv.title}</p>
                    </div>

                    <button
                      onClick={handleRunCT}
                      disabled={runningCT}
                      className="btn btn-primary"
                      style={{ padding: '0.75rem 1.5rem' }}
                    >
                      <Search size={16} className={runningCT ? 'spin' : ''} style={{ animation: runningCT ? 'spin 1s linear infinite' : 'none' }} />
                      <span>{runningCT ? 'Scanning CT Logs...' : 'Discover CT Hostnames'}</span>
                    </button>
                  </div>

                  {ctError && <div className="alert alert-error" style={{ marginTop: '1rem' }}>{ctError}</div>}
                </div>

                {/* CT Discovery Notice Alert */}
                <div className="alert alert-info">
                  <AlertCircle size={18} />
                  <div>
                    <strong>Passive Discovery Notice:</strong> Hostnames extracted from Certificate Transparency logs are candidate assets. Reachability and DNS active validation will occur in Stage 3B.
                  </div>
                </div>

                {/* Discovered Candidate Hostnames Table */}
                <div className="glass-panel" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Layers size={18} color="var(--cyan-400)" />
                      <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Discovered Asset Candidates ({assets.length})</h3>
                    </div>
                    {ctResult && (
                      <span className="badge badge-neutral">
                        Source: {ctResult.source} • {ctResult.certificate_count} certs
                      </span>
                    )}
                  </div>

                  {assets.length === 0 ? (
                    <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No CT discovery executed yet for this investigation. Click <strong>"Discover CT Hostnames"</strong> above to retrieve public certificate logs.
                    </div>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Hostname / Asset</th>
                            <th>Type</th>
                            <th>Validation Status</th>
                            <th>Confidence</th>
                            <th>Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          {assets.map(asset => (
                            <tr key={asset.id}>
                              <td style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                                {asset.value}
                              </td>
                              <td>
                                <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                                  {asset.asset_type}
                                </span>
                              </td>
                              <td>
                                <span className="badge badge-warning" style={{ fontSize: '0.7rem' }}>
                                  Candidate (Unresolved)
                                </span>
                              </td>
                              <td style={{ color: 'var(--emerald-400)', fontWeight: 500 }}>
                                {(asset.confidence * 100).toFixed(0)}%
                              </td>
                              <td style={{ color: 'var(--text-secondary)' }}>
                                {asset.source}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Discovered Certificates Section (if CT discovery ran) */}
                {ctResult && ctResult.certificates.length > 0 && (
                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                      <FileText size={18} color="var(--cyan-400)" />
                      <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
                        Observed TLS Certificates ({ctResult.certificates.length})
                      </h3>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {ctResult.certificates.map(cert => (
                        <div
                          key={cert.fingerprint_sha256}
                          style={{
                            background: 'rgba(15, 23, 42, 0.5)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: '8px',
                            padding: '1rem',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.5rem' }}>
                            <div>
                              <span style={{ fontWeight: 600, color: 'var(--cyan-400)' }}>CN: {cert.subject_cn}</span>
                              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Issuer: {cert.issuer}</div>
                            </div>
                            <span className={`badge ${cert.is_expired ? 'badge-danger' : 'badge-success'}`} style={{ fontSize: '0.7rem' }}>
                              {cert.is_expired ? 'Expired' : 'Valid'}
                            </span>
                          </div>

                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                            Valid: {new Date(cert.valid_from).toLocaleDateString()} — {new Date(cert.valid_to).toLocaleDateString()}
                          </div>

                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                            {cert.san_list.map(san => (
                              <span
                                key={san}
                                className="badge badge-neutral font-mono"
                                style={{ fontSize: '0.7rem', padding: '0.15rem 0.45rem' }}
                              >
                                {san}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                Select an investigation from the left panel or create a new assessment to begin OSINT discovery.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
