import React, { useEffect, useState, useCallback } from 'react';
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
  runFingerprinting,
  listInvestigationTechnologies,
  listInvestigationSecurityHeaders,
  listInvestigationTLSMetadata,
  correlateInvestigationVulnerabilities,
  listInvestigationVulnerabilities,
  getInvestigationGraph,
  generateInvestigationFindings,
  listInvestigationFindings,
  updateInvestigationFindingStatus,
  compareScanRuns,
  listInvestigationScans,
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
  FingerprintResponse,
  TechnologySummary,
  SecurityHeadersSummary,
  TLSMetadataSummary,
  CorrelateVulnerabilitiesResponse,
  VulnerabilityCorrelationDetail,
  GraphResponse,
  FindingResponse,
  ChangeRecordResponse,
  ComparisonSummaryResponse,
  ScanRunResponse,
} from './types/api';

import { Header } from './components/layout/Header';
import { Sidebar } from './components/layout/Sidebar';
import { AuthView } from './components/auth/AuthView';
import { OverviewDashboard, ActionResultInfo } from './components/overview/OverviewDashboard';
import { AssetInventory } from './components/assets/AssetInventory';
import { DnsInfrastructureView } from './components/infrastructure/DnsInfrastructureView';
import { ServicesTechView } from './components/services/ServicesTechView';
import { VulnerabilitiesView } from './components/vulnerabilities/VulnerabilitiesView';
import { AttackSurfaceGraphView } from './components/graph/AttackSurfaceGraphView';
import { FindingsRiskView } from './components/findings/FindingsRiskView';
import { MonitoringChangesView } from './components/monitoring/MonitoringChangesView';
import { ScanRunsView } from './components/scans/ScanRunsView';
import { Modal } from './components/common/Modal';

export const App: React.FC = () => {
  // System Health
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);

  // Authentication State
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('osint_jwt'));
  const [currentUser, setCurrentUser] = useState<UserResponse | null>(() => {
    const saved = localStorage.getItem('osint_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);

  // Navigation State
  const [activeTab, setActiveTab] = useState('overview');

  // Investigation Management State
  const [investigations, setInvestigations] = useState<InvestigationResponse[]>([]);
  const [selectedInv, setSelectedInv] = useState<InvestigationResponse | null>(null);
  const [isNewInvModalOpen, setIsNewInvModalOpen] = useState(false);
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

  // Stage 5 Technology & Security Fingerprint State
  const [runningFingerprint, setRunningFingerprint] = useState(false);
  const [fingerprintResult, setFingerprintResult] = useState<FingerprintResponse | null>(null);
  const [technologies, setTechnologies] = useState<TechnologySummary[]>([]);
  const [securityHeaders, setSecurityHeaders] = useState<SecurityHeadersSummary[]>([]);
  const [tlsMetadata, setTLSMetadata] = useState<TLSMetadataSummary[]>([]);
  const [fingerprintError, setFingerprintError] = useState<string | null>(null);

  // Stage 6 Vulnerability Intelligence & CVE Correlation State
  const [runningVulnCorrelate, setRunningVulnCorrelate] = useState(false);
  const [vulnResult, setVulnResult] = useState<CorrelateVulnerabilitiesResponse | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityCorrelationDetail[]>([]);
  const [vulnError, setVulnError] = useState<string | null>(null);

  // Stage 7 Attack Surface Graph & Correlation State
  const [runningGraph, setRunningGraph] = useState(false);
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [filterNodeType, setFilterNodeType] = useState<string>('ALL');
  const [filterRelType, setFilterRelType] = useState<string>('ALL');

  // Stage 8 Findings, Risk & Evidence Intelligence State
  const [runningFindings, setRunningFindings] = useState(false);
  const [findingsList, setFindingsList] = useState<FindingResponse[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [findingError, setFindingError] = useState<string | null>(null);

  // Stage 9 Monitoring & Change Detection State
  const [runningCompare, setRunningCompare] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<ComparisonSummaryResponse | null>(null);
  const [changesList, setChangesList] = useState<ChangeRecordResponse[]>([]);
  const [selectedBaselineScan, setSelectedBaselineScan] = useState<string>('');
  const [selectedCurrentScan, setSelectedCurrentScan] = useState<string>('');
  const [changeError, setChangeError] = useState<string | null>(null);
  const [selectedChangeRecord, setSelectedChangeRecord] = useState<ChangeRecordResponse | null>(null);

  // ScanRuns History State
  const [scanRuns, setScanRuns] = useState<ScanRunResponse[]>([]);

  // Health Probe
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

  // Load Graph Data
  const handleLoadGraph = useCallback(async () => {
    if (!token || !selectedInv) return;
    setRunningGraph(true);
    setGraphError(null);
    try {
      const nodeTypes = filterNodeType !== 'ALL' ? [filterNodeType.toLowerCase()] : undefined;
      const relTypes = filterRelType !== 'ALL' ? [filterRelType.toUpperCase()] : undefined;
      const res = await getInvestigationGraph(token, selectedInv.id, undefined, nodeTypes, relTypes);
      setGraphData(res);
    } catch (err: any) {
      setGraphError(err.message || 'Failed to load attack surface graph');
    } finally {
      setRunningGraph(false);
    }
  }, [token, selectedInv, filterNodeType, filterRelType]);

  // Load Findings Data
  const handleLoadFindings = useCallback(async () => {
    if (!token || !selectedInv) return;
    setFindingError(null);
    try {
      const res = await listInvestigationFindings(token, selectedInv.id);
      setFindingsList(res.findings);
      if (res.findings.length > 0 && !selectedFinding) {
        setSelectedFinding(res.findings[0]);
      }
    } catch (err: any) {
      console.error('Failed to load findings:', err);
      setFindingError(err.message || 'Failed to load findings');
    }
  }, [token, selectedInv, selectedFinding]);

  // Load ScanRuns Data
  const handleLoadScans = useCallback(async () => {
    if (!token || !selectedInv) return;
    try {
      const runs = await listInvestigationScans(token, selectedInv.id);
      setScanRuns(runs);
    } catch (err: any) {
      console.error('Failed to load scan runs:', err);
    }
  }, [token, selectedInv]);

  // Sync data whenever selected investigation changes
  useEffect(() => {
    if (token && selectedInv) {
      listInvestigationAssets(token, selectedInv.id).then(setAssets).catch(console.error);
      listInvestigationDNSRecords(token, selectedInv.id).then(setDnsRecords).catch(console.error);
      listInvestigationServices(token, selectedInv.id).then(setServices).catch(console.error);
      listInvestigationIPAddresses(token, selectedInv.id).then(setIPAddresses).catch(console.error);
      listInvestigationASNs(token, selectedInv.id).then(setASNs).catch(console.error);
      listInvestigationTechnologies(token, selectedInv.id).then(setTechnologies).catch(console.error);
      listInvestigationSecurityHeaders(token, selectedInv.id).then(setSecurityHeaders).catch(console.error);
      listInvestigationTLSMetadata(token, selectedInv.id).then(setTLSMetadata).catch(console.error);
      listInvestigationVulnerabilities(token, selectedInv.id).then(setVulnerabilities).catch(console.error);
      handleLoadGraph();
      handleLoadFindings();
      handleLoadScans();
    }
  }, [token, selectedInv, ctResult, resolveResult, ipEnrichResult, fingerprintResult, vulnResult, handleLoadGraph, handleLoadFindings, handleLoadScans]);

  // Handle Login
  const handleLogin = async (username: string, pass: string) => {
    setAuthLoading(true);
    setAuthError(null);
    try {
      const res = await loginUser(username, pass);
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

  // Handle Register
  const handleRegister = async (email: string, username: string, pass: string, fullName: string) => {
    setAuthLoading(true);
    setAuthError(null);
    try {
      await registerUser(email, username, pass, fullName);
      const loginRes = await loginUser(username, pass);
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
    setFingerprintResult(null);
    setAssets([]);
    setDnsRecords([]);
    setServices([]);
    setIPAddresses([]);
    setASNs([]);
    setTechnologies([]);
    setSecurityHeaders([]);
    setTLSMetadata([]);
    setVulnResult(null);
    setVulnerabilities([]);
    setGraphData(null);
    setFindingsList([]);
    setSelectedFinding(null);
    setChangesList([]);
    setComparisonResult(null);
    setScanRuns([]);
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
      setIsNewInvModalOpen(false);
      setCTResult(null);
      setResolveResult(null);
      setIPEnrichResult(null);
      setFingerprintResult(null);
      setVulnResult(null);
      setAssets([]);
      setDnsRecords([]);
      setServices([]);
      setIPAddresses([]);
      setASNs([]);
      setTechnologies([]);
      setSecurityHeaders([]);
      setTLSMetadata([]);
      setVulnerabilities([]);
      setGraphData(null);
      setFindingsList([]);
      setChangesList([]);
      setScanRuns([]);
    } catch (err: any) {
      setInvError(err.message || 'Failed to create assessment');
    } finally {
      setCreatingInv(false);
    }
  };

  // Pipeline Action Real-Time Status & Banner State
  const [actionStatus, setActionStatus] = useState<ActionResultInfo | null>(null);

  // Handle Run CT Discovery (Stage 3A)
  const handleRunCT = async () => {
    if (!token || !selectedInv) return;
    setRunningCT(true);
    setCTError(null);
    setActionStatus({
      type: 'running',
      stageNumber: 1,
      stageName: '1. Discover CT',
      message: `Scanning Certificate Transparency logs for ${selectedInv.target_domain}...`,
      timestamp: new Date(),
    });
    try {
      const res = await runCTDiscovery(token, selectedInv.id);
      setCTResult(res);
      const updatedAssets = await listInvestigationAssets(token, selectedInv.id);
      setAssets(updatedAssets);
      handleLoadScans();
      const providerLabel = res.provider_used || res.source || 'crt.sh';
      const successMsg = res.fallback_used
        ? `Certificate Transparency discovery completed using fallback provider (${providerLabel}): ${res.hostname_count} hostnames discovered, ${res.certificate_count} certificates stored.`
        : `Certificate Transparency discovery completed (${providerLabel}): ${res.hostname_count} hostnames discovered, ${res.certificate_count} certificates stored.`;
      setActionStatus({
        type: 'success',
        stageNumber: 1,
        stageName: '1. Discover CT',
        message: successMsg,
        detail: res.note,
        timestamp: new Date(),
      });
    } catch (err: any) {
      const msg = err.message || 'Certificate Transparency providers are temporarily unavailable. Please retry later.';
      setCTError(msg);
      setActionStatus({
        type: 'error',
        stageNumber: 1,
        stageName: '1. Discover CT',
        message: msg,
        detail: 'Certificate Transparency providers (primary and fallback) timed out or returned errors. Click Retry to attempt discovery again.',
        timestamp: new Date(),
      });
    } finally {
      setRunningCT(false);
    }
  };

  // Handle Run DNS & Reachability Resolution (Stage 3B)
  const handleRunResolve = async () => {
    if (!token || !selectedInv) return;
    setRunningResolve(true);
    setResolveError(null);
    setActionStatus({
      type: 'running',
      stageNumber: 2,
      stageName: '2. Resolve DNS',
      message: `Probing DNS records and HTTP reachability for discovered subdomains...`,
      timestamp: new Date(),
    });
    try {
      const res = await resolveInvestigation(token, selectedInv.id);
      setResolveResult(res);
      const [updatedAssets, updatedDns, updatedServices, updatedIPs] = await Promise.all([
        listInvestigationAssets(token, selectedInv.id),
        listInvestigationDNSRecords(token, selectedInv.id),
        listInvestigationServices(token, selectedInv.id),
        listInvestigationIPAddresses(token, selectedInv.id),
      ]);
      setAssets(updatedAssets);
      setDnsRecords(updatedDns);
      setServices(updatedServices);
      setIPAddresses(updatedIPs);
      handleLoadScans();
      setActionStatus({
        type: 'success',
        stageNumber: 2,
        stageName: '2. Resolve DNS',
        message: `DNS & Reachability probe completed: ${res.candidates_processed} hostnames probed, ${res.resolved} resolving, ${res.dns_records_discovered} DNS records found, ${res.services_discovered} services exposed.`,
        detail: res.note,
        timestamp: new Date(),
      });
    } catch (err: any) {
      const msg = err.message || 'Active DNS resolution & reachability probe failed';
      setResolveError(msg);
      setActionStatus({
        type: 'error',
        stageNumber: 2,
        stageName: '2. Resolve DNS',
        message: msg,
        timestamp: new Date(),
      });
    } finally {
      setRunningResolve(false);
    }
  };

  // Handle Run IP & ASN Intelligence Enrichment (Stage 4)
  const handleRunIPEnrich = async () => {
    if (!token || !selectedInv) return;
    setRunningIPEnrich(true);
    setIPEnrichError(null);
    setActionStatus({
      type: 'running',
      stageNumber: 3,
      stageName: '3. IP/ASN',
      message: `Enriching IP, ASN & RDAP...`,
      timestamp: new Date(),
    });
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
      handleLoadScans();
      setActionStatus({
        type: 'success',
        stageNumber: 3,
        stageName: '3. IP/ASN',
        message: `IP/ASN/RDAP enrichment completed: ${res.public_ips ?? res.ips_processed} IPs enriched, ${res.asn_success} ASNs observed.`,
        detail: res.note,
        timestamp: new Date(),
      });
    } catch (err: any) {
      const msg = err.message || 'IP, ASN, and RDAP enrichment failed';
      setIPEnrichError(msg);
      setActionStatus({
        type: 'error',
        stageNumber: 3,
        stageName: '3. IP/ASN',
        message: msg,
        timestamp: new Date(),
      });
    } finally {
      setRunningIPEnrich(false);
    }
  };

  // Handle Run Technology & Security Fingerprint (Stage 5)
  const handleRunFingerprint = async () => {
    if (!token || !selectedInv) return;
    setRunningFingerprint(true);
    setFingerprintError(null);
    setActionStatus({
      type: 'running',
      stageNumber: 4,
      stageName: '4. Tech/Headers',
      message: `Analyzing HTTP response headers, TLS metadata, server banners, and software technologies...`,
      timestamp: new Date(),
    });
    try {
      const res = await runFingerprinting(token, selectedInv.id);
      setFingerprintResult(res);
      const [updatedAssets, updatedTechs, updatedHeaders, updatedTLS, updatedServices] = await Promise.all([
        listInvestigationAssets(token, selectedInv.id),
        listInvestigationTechnologies(token, selectedInv.id),
        listInvestigationSecurityHeaders(token, selectedInv.id),
        listInvestigationTLSMetadata(token, selectedInv.id),
        listInvestigationServices(token, selectedInv.id),
      ]);
      setAssets(updatedAssets);
      setTechnologies(updatedTechs);
      setSecurityHeaders(updatedHeaders);
      setTLSMetadata(updatedTLS);
      setServices(updatedServices);
      handleLoadScans();
      setActionStatus({
        type: 'success',
        stageNumber: 4,
        stageName: '4. Tech/Headers',
        message: `Technology & Security Fingerprinting completed: ${res.services_processed} services probed, ${res.technologies_detected} technologies identified, ${res.security_headers_analyzed} security headers analyzed.`,
        detail: res.note,
        timestamp: new Date(),
      });
    } catch (err: any) {
      const msg = err.message || 'Technology & Security Fingerprinting failed';
      setFingerprintError(msg);
      setActionStatus({
        type: 'error',
        stageNumber: 4,
        stageName: '4. Tech/Headers',
        message: msg,
        timestamp: new Date(),
      });
    } finally {
      setRunningFingerprint(false);
    }
  };

  // Handle Run Vulnerability Intelligence & CVE Correlation (Stage 6)
  const handleRunVulnCorrelate = async () => {
    if (!token || !selectedInv) return;
    setRunningVulnCorrelate(true);
    setVulnError(null);
    setActionStatus({
      type: 'running',
      stageNumber: 5,
      stageName: '5. Correlate CVEs',
      message: `Correlating observed technologies against NVD CVE advisories and CISA Known Exploited Vulnerabilities...`,
      timestamp: new Date(),
    });
    try {
      const res = await correlateInvestigationVulnerabilities(token, selectedInv.id);
      setVulnResult(res);
      const updatedVulns = await listInvestigationVulnerabilities(token, selectedInv.id);
      setVulnerabilities(updatedVulns);
      handleLoadScans();
      setActionStatus({
        type: 'success',
        stageNumber: 5,
        stageName: '5. Correlate CVEs',
        message: `Vulnerability & CVE correlation completed: ${res.cves_correlated} CVE matches found across ${res.technologies_analyzed} technologies (${res.kev_listed_cves} CISA KEV cataloged).`,
        detail: res.note,
        timestamp: new Date(),
      });
    } catch (err: any) {
      const msg = err.message || 'Vulnerability intelligence & CVE correlation failed';
      setVulnError(msg);
      setActionStatus({
        type: 'error',
        stageNumber: 5,
        stageName: '5. Correlate CVEs',
        message: msg,
        timestamp: new Date(),
      });
    } finally {
      setRunningVulnCorrelate(false);
    }
  };

  // Handle Generate Findings (Stage 8)
  const handleGenerateFindings = async () => {
    if (!token || !selectedInv) return;
    setRunningFindings(true);
    setFindingError(null);
    setActionStatus({
      type: 'running',
      stageNumber: 6,
      stageName: '6. Generate Findings',
      message: `Evaluating contextual platform risk scores and generating evidence-backed findings...`,
      timestamp: new Date(),
    });
    try {
      const res = await generateInvestigationFindings(token, selectedInv.id);
      setFindingsList(res.findings);
      if (res.findings.length > 0) {
        setSelectedFinding(res.findings[0]);
      }
      handleLoadScans();
      setActionStatus({
        type: 'success',
        stageNumber: 6,
        stageName: '6. Generate Findings',
        message: `Security Findings Assessment completed: ${res.findings_generated} findings generated (${res.findings.length} total active findings).`,
        timestamp: new Date(),
      });
    } catch (err: any) {
      const msg = err.message || 'Failed to generate findings';
      setFindingError(msg);
      setActionStatus({
        type: 'error',
        stageNumber: 6,
        stageName: '6. Generate Findings',
        message: msg,
        timestamp: new Date(),
      });
    } finally {
      setRunningFindings(false);
    }
  };

  // Handle Update Finding Status (Stage 8)
  const handleUpdateFindingStatus = async (findingId: string, newStatus: string) => {
    if (!token || !selectedInv) return;
    try {
      const updated = await updateInvestigationFindingStatus(token, selectedInv.id, findingId, newStatus);
      setSelectedFinding(updated);
      setFindingsList(prev => prev.map(f => f.id === updated.id ? updated : f));
    } catch (err: any) {
      setFindingError(err.message || 'Failed to update finding status');
    }
  };

  // Handle Compare Scans (Stage 9)
  const handleCompareScans = async () => {
    if (!token || !selectedInv) return;
    setRunningCompare(true);
    setChangeError(null);
    try {
      const res = await compareScanRuns(
        token,
        selectedInv.id,
        selectedBaselineScan || undefined,
        selectedCurrentScan || undefined
      );
      setComparisonResult(res);
      setChangesList(res.changes);
      if (res.changes.length > 0) {
        setSelectedChangeRecord(res.changes[0]);
      }
    } catch (err: any) {
      setChangeError(err.message || 'Failed to compare scan runs');
    } finally {
      setRunningCompare(false);
    }
  };

  // If Not Authenticated, Render Auth View
  if (!token) {
    return (
      <AuthView
        onLogin={handleLogin}
        onRegister={handleRegister}
        loading={authLoading}
        error={authError}
        healthData={healthData}
      />
    );
  }

  // Count badges for sidebar
  const counts = {
    assets: assets.length,
    dns: dnsRecords.length,
    services: services.length + technologies.length,
    vulnerabilities: vulnerabilities.length,
    graph: graphData ? graphData.nodes.length : 0,
    findings: findingsList.length,
    monitoring: changesList.length,
    scans: scanRuns.length,
  };

  return (
    <div className="app-layout">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        investigations={investigations}
        selectedInv={selectedInv}
        onSelectInv={inv => {
          setSelectedInv(inv);
          setCTResult(null);
          setResolveResult(null);
          setIPEnrichResult(null);
          setFingerprintResult(null);
          setVulnResult(null);
          setGraphData(null);
          setFindingsList([]);
          setSelectedFinding(null);
          setChangesList([]);
          setComparisonResult(null);
        }}
        onOpenNewInvModal={() => setIsNewInvModalOpen(true)}
        counts={counts}
      />

      {/* Main Content Area */}
      <div className="main-content">
        <Header
          selectedInv={selectedInv}
          currentUser={currentUser}
          healthData={healthData}
          onLogout={handleLogout}
        />

        <div className="content-container">
          {selectedInv ? (
            <>
              {activeTab === 'overview' && (
                <OverviewDashboard
                  investigation={selectedInv}
                  assets={assets}
                  dnsRecords={dnsRecords}
                  services={services}
                  technologies={technologies}
                  vulnerabilities={vulnerabilities}
                  findings={findingsList}
                  changes={changesList}
                  onNavigateTab={setActiveTab}
                  onRunCT={handleRunCT}
                  onRunResolve={handleRunResolve}
                  onRunIPEnrich={handleRunIPEnrich}
                  onRunFingerprint={handleRunFingerprint}
                  onRunVulnCorrelate={handleRunVulnCorrelate}
                  onRunFindings={handleGenerateFindings}
                  runningCT={runningCT}
                  runningResolve={runningResolve}
                  runningIPEnrich={runningIPEnrich}
                  runningFingerprint={runningFingerprint}
                  runningVulnCorrelate={runningVulnCorrelate}
                  runningFindings={runningFindings}
                  actionStatus={actionStatus}
                  onDismissStatus={() => setActionStatus(null)}
                />
              )}

              {activeTab === 'assets' && (
                <AssetInventory
                  assets={assets}
                  onRunCT={handleRunCT}
                  loading={runningCT}
                  error={ctError}
                  targetDomain={selectedInv.target_domain}
                />
              )}

              {activeTab === 'dns' && (
                <DnsInfrastructureView
                  dnsRecords={dnsRecords}
                  ipAddresses={ipAddresses}
                  asns={asns}
                  onRunResolve={handleRunResolve}
                  onRunIPEnrich={handleRunIPEnrich}
                  runningResolve={runningResolve}
                  runningIPEnrich={runningIPEnrich}
                  resolveError={resolveError}
                  ipEnrichError={ipEnrichError}
                  targetDomain={selectedInv.target_domain}
                  actionStatus={actionStatus}
                  onDismissStatus={() => setActionStatus(null)}
                />
              )}

              {activeTab === 'services' && (
                <ServicesTechView
                  services={services}
                  technologies={technologies}
                  securityHeaders={securityHeaders}
                  tlsMetadata={tlsMetadata}
                  onRunFingerprint={handleRunFingerprint}
                  loading={runningFingerprint}
                  error={fingerprintError}
                  targetDomain={selectedInv.target_domain}
                />
              )}

              {activeTab === 'vulnerabilities' && (
                <VulnerabilitiesView
                  vulnerabilities={vulnerabilities}
                  onRunCorrelation={handleRunVulnCorrelate}
                  loading={runningVulnCorrelate}
                  error={vulnError}
                  targetDomain={selectedInv.target_domain}
                />
              )}

              {activeTab === 'graph' && (
                <AttackSurfaceGraphView
                  graphData={graphData}
                  onRefreshGraph={handleLoadGraph}
                  loading={runningGraph}
                  error={graphError}
                  selectedNodeType={filterNodeType}
                  onChangeNodeType={type => {
                    setFilterNodeType(type);
                  }}
                  selectedRelType={filterRelType}
                  onChangeRelType={rel => {
                    setFilterRelType(rel);
                  }}
                />
              )}

              {activeTab === 'findings' && (
                <FindingsRiskView
                  findings={findingsList}
                  onGenerateFindings={handleGenerateFindings}
                  onUpdateStatus={handleUpdateFindingStatus}
                  loading={runningFindings}
                  error={findingError}
                  selectedFinding={selectedFinding}
                  onSelectFinding={setSelectedFinding}
                  targetDomain={selectedInv.target_domain}
                />
              )}

              {activeTab === 'monitoring' && (
                <MonitoringChangesView
                  comparisonResult={comparisonResult}
                  changes={changesList}
                  onCompareScans={handleCompareScans}
                  loading={runningCompare}
                  error={changeError}
                  baselineScanId={selectedBaselineScan}
                  onChangeBaselineScanId={setSelectedBaselineScan}
                  currentScanId={selectedCurrentScan}
                  onChangeCurrentScanId={setSelectedCurrentScan}
                  selectedChange={selectedChangeRecord}
                  onSelectChange={setSelectedChangeRecord}
                />
              )}

              {activeTab === 'scans' && (
                <ScanRunsView
                  investigation={selectedInv}
                  scanRuns={scanRuns}
                  onRefreshScans={handleLoadScans}
                  onRunCT={handleRunCT}
                  onRunResolve={handleRunResolve}
                  onRunIPEnrich={handleRunIPEnrich}
                  onRunFingerprint={handleRunFingerprint}
                  onRunVulnCorrelate={handleRunVulnCorrelate}
                  onRunFindings={handleGenerateFindings}
                  runningCT={runningCT}
                  runningResolve={runningResolve}
                  runningIPEnrich={runningIPEnrich}
                  runningFingerprint={runningFingerprint}
                  runningVulnCorrelate={runningVulnCorrelate}
                  runningFindings={runningFindings}
                />
              )}
            </>
          ) : (
            <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              No active investigation selected. Create a new assessment using the sidebar button to begin.
            </div>
          )}
        </div>
      </div>

      {/* New Investigation Modal */}
      <Modal
        title="Create New Attack Surface Assessment"
        isOpen={isNewInvModalOpen}
        onClose={() => setIsNewInvModalOpen(false)}
        maxWidth="520px"
      >
        <form onSubmit={handleCreateInvestigation} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {invError && <div className="alert alert-danger">{invError}</div>}

          <div className="form-group">
            <label className="form-label">Target Domain / Root FQDN</label>
            <input
              type="text"
              required
              className="form-input"
              value={invDomain}
              onChange={e => setInvDomain(e.target.value)}
              placeholder="example.com"
            />
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Enter a valid Fully Qualified Domain Name (e.g. corp.example.com).
            </span>
          </div>

          <div className="form-group">
            <label className="form-label">Assessment Title</label>
            <input
              type="text"
              required
              className="form-input"
              value={invName}
              onChange={e => setInvName(e.target.value)}
              placeholder="Q1 External Surface Audit"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Client / Organization Name (Optional)</label>
            <input
              type="text"
              className="form-input"
              value={invOrg}
              onChange={e => setInvOrg(e.target.value)}
              placeholder="Acme Corporation"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button
              type="button"
              onClick={() => setIsNewInvModalOpen(false)}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creatingInv}
              className="btn btn-primary"
            >
              {creatingInv ? 'Creating...' : 'Initialize Assessment'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default App;
