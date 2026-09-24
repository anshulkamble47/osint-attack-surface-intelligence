import React, { useEffect, useState, useCallback } from 'react';
import { 
  Shield, 
  Layers,
  Search,
  User,
  Globe,
  FileText,
  Lock,
  Radio,
  Activity,
  CheckCircle2,
  XCircle,
  Server,
  Network,
} from 'lucide-react';

import { 
  fetchHealth, 
  loginUser, 
  registerUser, 
  createInvestigation, 
  listInvestigations, 
  runCTDiscovery,
  listInvestigationAssets,
  resolveInvestigation,
  listInvestigationDNSRecords,
  listInvestigationServices,
  enrichInvestigationIPs,
  listInvestigationIPAddresses,
  listInvestigationASNs,
} from './services/api';
import { 
  HealthResponse, 
  UserResponse, 
  InvestigationResponse, 
  CTDiscoveryResponse, 
  AssetSummary,
  DNSReachabilityResponse,
  DNSRecordSummary,
  ServiceExposureSummary,
  IPEnrichmentResponse,
  IPAddressSummary,
  ASNSummary,
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

  // Discovery State (Stage 3A & 3B)
  const [runningCT, setRunningCT] = useState(false);
  const [ctResult, setCTResult] = useState<CTDiscoveryResponse | null>(null);
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [ctError, setCTError] = useState<string | null>(null);

  // Stage 3B Resolution & Reachability State
  const [runningResolve, setRunningResolve] = useState(false);
  const [resolveResult, setResolveResult] = useState<DNSReachabilityResponse | null>(null);
  const [dnsRecords, setDnsRecords] = useState<DNSRecordSummary[]>([]);
  const [services, setServices] = useState<ServiceExposureSummary[]>([]);
  const [resolveError, setResolveError] = useState<string | null>(null);

  // Stage 4 IP / ASN / RDAP State
  const [runningIPEnrich, setRunningIPEnrich] = useState(false);
  const [ipEnrichResult, setIPEnrichResult] = useState<IPEnrichmentResponse | null>(null);
  const [ipAddresses, setIPAddresses] = useState<IPAddressSummary[]>([]);
  const [asns, setASNs] = useState<ASNSummary[]>([]);
  const [ipEnrichError, setIPEnrichError] = useState<string | null>(null);

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

  // Load assets, DNS records, services, IP addresses, and ASNs when selected investigation changes
  useEffect(() => {
    if (token && selectedInv) {
      listInvestigationAssets(token, selectedInv.id)
        .then(setAssets)
        .catch(console.error);
      listInvestigationDNSRecords(token, selectedInv.id)
        .then(setDnsRecords)
        .catch(console.error);
      listInvestigationServices(token, selectedInv.id)
        .then(setServices)
        .catch(console.error);
      listInvestigationIPAddresses(token, selectedInv.id)
        .then(setIPAddresses)
        .catch(console.error);
      listInvestigationASNs(token, selectedInv.id)
        .then(setASNs)
        .catch(console.error);
    }
  }, [token, selectedInv, ctResult, resolveResult, ipEnrichResult]);

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
    setResolveResult(null);
    setIPEnrichResult(null);
    setAssets([]);
    setDnsRecords([]);
    setServices([]);
    setIPAddresses([]);
    setASNs([]);
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
      setResolveResult(null);
      setIPEnrichResult(null);
      setIPAddresses([]);
      setASNs([]);
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
      const updatedAssets = await listInvestigationAssets(token, selectedInv.id);
      setAssets(updatedAssets);
    } catch (err: any) {
      setCTError(err.message || 'Certificate Transparency discovery failed');
    } finally {
      setRunningCT(false);
    }
  };

  // Handle Run DNS & Reachability Resolution (Stage 3B)
  const handleRunResolve = async () => {
    if (!token || !selectedInv) return;
    setRunningResolve(true);
    setResolveError(null);
    try {
      const res = await resolveInvestigation(token, selectedInv.id);
      setResolveResult(res);
      const [updatedAssets, updatedDns, updatedServices] = await Promise.all([
        listInvestigationAssets(token, selectedInv.id),
        listInvestigationDNSRecords(token, selectedInv.id),
        listInvestigationServices(token, selectedInv.id),
      ]);
      setAssets(updatedAssets);
      setDnsRecords(updatedDns);
      setServices(updatedServices);
    } catch (err: any) {
      setResolveError(err.message || 'Active DNS resolution & reachability probe failed');
    } finally {
      setRunningResolve(false);
    }
  };

  // Handle Run IP & ASN Intelligence Enrichment (Stage 4)
  const handleRunIPEnrich = async () => {
    if (!token || !selectedInv) return;
    setRunningIPEnrich(true);
    setIPEnrichError(null);
    try {
      const res = await enrichInvestigationIPs(token, selectedInv.id);
      setIPEnrichResult(res);
      const [updatedAssets, updatedIPs, updatedASNs] = await Promise.all([
        listInvestigationAssets(token, selectedInv.id),
        listInvestigationIPAddresses(token, selectedInv.id),
        listInvestigationASNs(token, selectedInv.id),
      ]);
      setAssets(updatedAssets);
      setIPAddresses(updatedIPs);
      setASNs(updatedASNs);
    } catch (err: any) {
      setIPEnrichError(err.message || 'IP, ASN, and RDAP enrichment failed');
    } finally {
      setRunningIPEnrich(false);
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
                Stage 3B: Active DNS Intelligence & Reachability Probing
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

          {/* Right Column: CT Discovery, Active Resolution & Discovered Assets */}
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

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                      <button
                        onClick={handleRunCT}
                        disabled={runningCT || runningResolve}
                        className="btn btn-secondary"
                        style={{ padding: '0.65rem 1.25rem' }}
                      >
                        <Search size={15} className={runningCT ? 'spin' : ''} style={{ animation: runningCT ? 'spin 1s linear infinite' : 'none' }} />
                        <span>{runningCT ? 'Scanning CT Logs...' : '1. Discover CT'}</span>
                      </button>

                      <button
                        onClick={handleRunResolve}
                        disabled={runningResolve || runningCT || runningIPEnrich || assets.length === 0}
                        className="btn btn-primary"
                        style={{ padding: '0.65rem 1.25rem' }}
                      >
                        <Radio size={15} className={runningResolve ? 'spin' : ''} style={{ animation: runningResolve ? 'spin 1s linear infinite' : 'none' }} />
                        <span>{runningResolve ? 'Probing DNS & HTTP...' : '2. Run DNS & Reachability'}</span>
                      </button>

                      <button
                        onClick={handleRunIPEnrich}
                        disabled={runningIPEnrich || runningResolve || runningCT || dnsRecords.length === 0}
                        className="btn btn-secondary"
                        style={{ padding: '0.65rem 1.25rem' }}
                      >
                        <Network size={15} className={runningIPEnrich ? 'spin' : ''} style={{ animation: runningIPEnrich ? 'spin 1s linear infinite' : 'none' }} />
                        <span>{runningIPEnrich ? 'Enriching IPs...' : '3. Run IP Intelligence'}</span>
                      </button>
                    </div>
                  </div>

                  {ctError && <div className="alert alert-error" style={{ marginTop: '1rem' }}>{ctError}</div>}
                  {resolveError && <div className="alert alert-error" style={{ marginTop: '1rem' }}>{resolveError}</div>}
                  {ipEnrichError && <div className="alert alert-error" style={{ marginTop: '1rem' }}>{ipEnrichError}</div>}
                </div>

                {/* DNS & Reachability Metrics Grid (if resolution executed) */}
                {resolveResult && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem' }}>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Processed</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700 }}>{resolveResult.candidates_processed}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(16, 185, 129, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--emerald-400)' }}>Resolved</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--emerald-400)' }}>{resolveResult.resolved}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(239, 68, 68, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--red-400)' }}>Unresolved</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--red-400)' }}>{resolveResult.not_resolved}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(56, 189, 248, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--cyan-400)' }}>Reachable</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--cyan-400)' }}>{resolveResult.reachable}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>DNS Records</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700 }}>{resolveResult.dns_records_discovered}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Services</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700 }}>{resolveResult.services_discovered}</div>
                    </div>
                  </div>
                )}

                {/* Stage 4 IP / ASN / RDAP Enrichment Metrics Grid */}
                {ipEnrichResult && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem' }}>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>IPs Processed</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700 }}>{ipEnrichResult.ips_processed}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(16, 185, 129, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--emerald-400)' }}>Public IPs</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--emerald-400)' }}>{ipEnrichResult.public_ips}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(245, 158, 11, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--amber-400)' }}>Skipped (Private)</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--amber-400)' }}>{ipEnrichResult.skipped_non_public}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(56, 189, 248, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--cyan-400)' }}>ASN Enriched</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--cyan-400)' }}>{ipEnrichResult.asn_success}</div>
                    </div>
                    <div className="glass-panel" style={{ padding: '0.85rem', textAlign: 'center', borderColor: 'rgba(168, 85, 247, 0.3)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--purple-400)' }}>RDAP Enriched</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--purple-400)' }}>{ipEnrichResult.rdap_success}</div>
                    </div>
                  </div>
                )}

                {/* Discovered Candidate Hostnames Table */}
                <div className="glass-panel" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Layers size={18} color="var(--cyan-400)" />
                      <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Discovered Assets ({assets.length})</h3>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      {ctResult && (
                        <span className="badge badge-neutral" style={{ fontSize: '0.75rem' }}>
                          CT: {ctResult.certificate_count} certs
                        </span>
                      )}
                      {dnsRecords.length > 0 && (
                        <span className="badge badge-success" style={{ fontSize: '0.75rem' }}>
                          DNS: {dnsRecords.length} records
                        </span>
                      )}
                      {services.length > 0 && (
                        <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>
                          HTTP/S: {services.length} services
                        </span>
                      )}
                    </div>
                  </div>

                  {assets.length === 0 ? (
                    <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No discovery executed yet for this investigation. Click <strong>"1. Discover CT"</strong> above to retrieve public certificate candidates.
                    </div>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Hostname / Asset</th>
                            <th>Type</th>
                            <th>DNS Status</th>
                            <th>Reachability</th>
                            <th>Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          {assets.map(asset => {
                            const candidateDetail = resolveResult?.results.find(r => r.hostname === asset.value);
                            const isResolving = asset.is_active || candidateDetail?.is_resolving;
                            const isReachable = candidateDetail?.is_reachable;

                            return (
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
                                  {isResolving ? (
                                    <span className="badge badge-success" style={{ fontSize: '0.7rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                                      <CheckCircle2 size={11} /> Resolving
                                    </span>
                                  ) : (
                                    <span className="badge badge-warning" style={{ fontSize: '0.7rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                                      <XCircle size={11} /> Unresolved Candidate
                                    </span>
                                  )}
                                </td>
                                <td>
                                  {isReachable ? (
                                    <span className="badge badge-info" style={{ fontSize: '0.7rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                                      <Activity size={11} /> Live HTTP/S
                                    </span>
                                  ) : isResolving ? (
                                    <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                                      No HTTP
                                    </span>
                                  ) : (
                                    <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                                  )}
                                </td>
                                <td style={{ color: 'var(--text-secondary)' }}>
                                  {asset.source}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Discovered DNS Records Section */}
                {dnsRecords.length > 0 && (
                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                      <Radio size={18} color="var(--cyan-400)" />
                      <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
                        Active DNS Resource Records ({dnsRecords.length})
                      </h3>
                    </div>

                    <div style={{ overflowX: 'auto', maxHeight: '280px' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Record Type</th>
                            <th>Value</th>
                            <th>TTL</th>
                            <th>Resolver</th>
                            <th>Collected At</th>
                          </tr>
                        </thead>
                        <tbody>
                          {dnsRecords.map(rec => (
                            <tr key={rec.id}>
                              <td>
                                <span className="badge badge-neutral font-mono" style={{ fontSize: '0.75rem', fontWeight: 700 }}>
                                  {rec.record_type}
                                </span>
                              </td>
                              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                                {rec.value}
                              </td>
                              <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                                {rec.ttl ? `${rec.ttl}s` : '—'}
                              </td>
                              <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                                {rec.resolver}
                              </td>
                              <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                                {new Date(rec.collected_at).toLocaleTimeString()}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Discovered Service Exposures Section */}
                {services.length > 0 && (
                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                      <Server size={18} color="var(--cyan-400)" />
                      <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
                        Live Service Exposures ({services.length})
                      </h3>
                    </div>

                    <div style={{ overflowX: 'auto', maxHeight: '280px' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Port / Protocol</th>
                            <th>Service</th>
                            <th>HTTP Status</th>
                            <th>Page Title</th>
                            <th>Observed</th>
                          </tr>
                        </thead>
                        <tbody>
                          {services.map(svc => (
                            <tr key={svc.id}>
                              <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                                {svc.port}/{svc.protocol}
                              </td>
                              <td>
                                <span className="badge badge-neutral" style={{ fontSize: '0.75rem' }}>
                                  {svc.service_name}
                                </span>
                              </td>
                              <td>
                                <span className={`badge ${svc.http_status && svc.http_status < 400 ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.75rem' }}>
                                  {svc.http_status ?? 'N/A'}
                                </span>
                              </td>
                              <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                {svc.page_title || '—'}
                              </td>
                              <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                                {new Date(svc.observed_at).toLocaleTimeString()}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Discovered IP Addresses & Network Intelligence Section (Stage 4) */}
                {ipAddresses.length > 0 && (
                  <div className="glass-panel" style={{ padding: '1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Globe size={18} color="var(--cyan-400)" />
                        <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
                          Discovered IP Addresses & Network Intelligence ({ipAddresses.length})
                        </h3>
                      </div>
                      {asns.length > 0 && (
                        <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>
                          {asns.length} Distinct Autonomous Systems
                        </span>
                      )}
                    </div>

                    <div style={{ overflowX: 'auto', maxHeight: '340px' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>IP Address</th>
                            <th>Type</th>
                            <th>ASN</th>
                            <th>Organization / Network</th>
                            <th>Allocated Prefix</th>
                            <th>Country</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ipAddresses.map(ip => (
                            <tr key={ip.id}>
                              <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                                {ip.ip_address}
                              </td>
                              <td>
                                <span className="badge badge-neutral font-mono" style={{ fontSize: '0.7rem' }}>
                                  IPv{ip.ip_version}
                                </span>
                              </td>
                              <td>
                                {ip.asn ? (
                                  <span className="badge badge-info font-mono" style={{ fontSize: '0.75rem' }}>
                                    AS{ip.asn.asn_number}
                                  </span>
                                ) : (
                                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                                )}
                              </td>
                              <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                {ip.organization || ip.asn?.name || '—'}
                              </td>
                              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                {ip.asn?.allocated_prefix || '—'}
                              </td>
                              <td>
                                {ip.country ? (
                                  <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                                    {ip.country}
                                  </span>
                                ) : (
                                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

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

