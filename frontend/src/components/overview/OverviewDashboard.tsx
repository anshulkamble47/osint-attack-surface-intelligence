import React from 'react';
import {
  Globe,
  Network,
  Cpu,
  AlertTriangle,
  ShieldAlert,
  History,
  ArrowRight,
  Zap,
  Search,
  Radio,
  Flame,
  Globe2,
} from 'lucide-react';
import {
  InvestigationResponse,
  AssetSummary,
  DNSRecordSummary,
  ServiceExposureSummary,
  TechnologySummary,
  VulnerabilityCorrelationDetail,
  FindingResponse,
  ChangeRecordResponse,
} from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { CompactStatCard } from '../common/CompactStatCard';

export interface ActionResultInfo {
  type: 'success' | 'error' | 'running';
  stageNumber: number;
  stageName: string;
  message: string;
  detail?: string;
  timestamp: Date;
}

interface OverviewDashboardProps {
  investigation: InvestigationResponse;
  assets: AssetSummary[];
  dnsRecords: DNSRecordSummary[];
  services: ServiceExposureSummary[];
  technologies: TechnologySummary[];
  vulnerabilities: VulnerabilityCorrelationDetail[];
  findings: FindingResponse[];
  changes: ChangeRecordResponse[];
  onNavigateTab: (tab: string) => void;
  onRunCT: () => void;
  onRunResolve: () => void;
  onRunIPEnrich: () => void;
  onRunFingerprint: () => void;
  onRunVulnCorrelate: () => void;
  onRunFindings: () => void;
  runningCT: boolean;
  runningResolve: boolean;
  runningIPEnrich: boolean;
  runningFingerprint: boolean;
  runningVulnCorrelate: boolean;
  runningFindings: boolean;
  actionStatus: ActionResultInfo | null;
  onDismissStatus?: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  investigation,
  assets,
  dnsRecords,
  services,
  technologies,
  vulnerabilities,
  findings,
  changes,
  onNavigateTab,
  onRunCT,
  onRunResolve,
  onRunIPEnrich,
  onRunFingerprint,
  onRunVulnCorrelate,
  onRunFindings,
  runningCT,
  runningResolve,
  runningIPEnrich,
  runningFingerprint,
  runningVulnCorrelate,
  runningFindings,
  actionStatus,
  onDismissStatus,
}) => {
  const criticalFindings = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL');
  const highFindings = findings.filter(f => f.severity.toUpperCase() === 'HIGH');
  const resolvingSubdomains = assets.filter(a => a.asset_type === 'subdomain' && a.is_active);
  const kevVulns = vulnerabilities.filter(v => v.is_kev);

  const isAnyRunning = runningCT || runningResolve || runningIPEnrich || runningFingerprint || runningVulnCorrelate || runningFindings;

  const getStageRetryHandler = (stageNumber: number) => {
    switch (stageNumber) {
      case 1: return onRunCT;
      case 2: return onRunResolve;
      case 3: return onRunIPEnrich;
      case 4: return onRunFingerprint;
      case 5: return onRunVulnCorrelate;
      case 6: return onRunFindings;
      default: return undefined;
    }
  };

  const getStageTargetTab = (stageNumber: number) => {
    switch (stageNumber) {
      case 1: return 'assets';
      case 2: return 'dns';
      case 3: return 'dns';
      case 4: return 'services';
      case 5: return 'vulnerabilities';
      case 6: return 'findings';
      default: return 'overview';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Target & Investigation Overview Banner */}
      <div
        className="glass-panel"
        style={{
          padding: '1.25rem',
          borderLeft: '4px solid var(--cyan-400)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {investigation.title}
              </h2>
              <span className="badge badge-info font-mono" style={{ fontSize: '0.72rem' }}>
                {investigation.reference_code}
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Target: </span>
                <strong style={{ color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>{investigation.target_domain}</strong>
              </div>
              {investigation.scan_options?.organization && (
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Org: </span>
                  <strong style={{ color: 'var(--text-primary)' }}>{investigation.scan_options.organization}</strong>
                </div>
              )}
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Status: </span>
                <span className="badge badge-success" style={{ fontSize: '0.68rem' }}>
                  {investigation.status}
                </span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Created: </span>
                <span>{new Date(investigation.created_at).toLocaleDateString()}</span>
              </div>
            </div>
          </div>

          {/* Modular Pipeline Execution Station */}
          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
            <button
              className={`btn ${runningCT ? 'btn-primary' : 'btn-secondary'}`}
              onClick={onRunCT}
              disabled={isAnyRunning && !runningCT}
              title="Discover subdomains via Certificate Transparency"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', opacity: isAnyRunning && !runningCT ? 0.6 : 1 }}
            >
              <Search size={13} className={runningCT ? 'spin' : ''} />
              <span>{runningCT ? 'Scanning CT...' : '1. Discover CT'}</span>
            </button>

            <button
              className={`btn ${runningResolve ? 'btn-primary' : 'btn-secondary'}`}
              onClick={onRunResolve}
              disabled={(isAnyRunning && !runningResolve) || assets.length === 0}
              title="Probe DNS records and web reachability"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', opacity: isAnyRunning && !runningResolve ? 0.6 : 1 }}
            >
              <Radio size={13} className={runningResolve ? 'spin' : ''} />
              <span>{runningResolve ? 'Probing DNS...' : '2. Resolve DNS'}</span>
            </button>

            <button
              className={`btn ${runningIPEnrich ? 'btn-primary' : 'btn-secondary'}`}
              onClick={onRunIPEnrich}
              disabled={(isAnyRunning && !runningIPEnrich) || assets.length === 0}
              title="Enrich IP geolocation, ASN, and RDAP"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', opacity: isAnyRunning && !runningIPEnrich ? 0.6 : 1 }}
            >
              <Globe2 size={13} className={runningIPEnrich ? 'spin' : ''} />
              <span>{runningIPEnrich ? 'Enriching...' : '3. IP/ASN'}</span>
            </button>

            <button
              className={`btn ${runningFingerprint ? 'btn-primary' : 'btn-secondary'}`}
              onClick={onRunFingerprint}
              disabled={(isAnyRunning && !runningFingerprint) || assets.length === 0}
              title="Fingerprint HTTP security headers & technologies"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', opacity: isAnyRunning && !runningFingerprint ? 0.6 : 1 }}
            >
              <Cpu size={13} className={runningFingerprint ? 'spin' : ''} />
              <span>{runningFingerprint ? 'Fingerprinting...' : '4. Tech/Headers'}</span>
            </button>

            <button
              className={`btn ${runningVulnCorrelate ? 'btn-primary' : 'btn-secondary'}`}
              onClick={onRunVulnCorrelate}
              disabled={isAnyRunning && !runningVulnCorrelate}
              title="Correlate detected technologies with NVD and CISA KEV"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', opacity: isAnyRunning && !runningVulnCorrelate ? 0.6 : 1 }}
            >
              <Flame size={13} className={runningVulnCorrelate ? 'spin' : ''} />
              <span>{runningVulnCorrelate ? 'Correlating...' : '5. Correlate CVEs'}</span>
            </button>

            <button
              className="btn btn-primary"
              onClick={onRunFindings}
              disabled={isAnyRunning && !runningFindings}
              title="Evaluate risk model and generate security findings"
              style={{
                padding: '0.4rem 0.75rem',
                fontSize: '0.78rem',
                background: runningFindings ? '#be123c' : 'linear-gradient(135deg, #e11d48, #f43f5e)',
                border: 'none',
                opacity: isAnyRunning && !runningFindings ? 0.6 : 1
              }}
            >
              <Zap size={13} className={runningFindings ? 'spin' : ''} />
              <span>{runningFindings ? 'Assessing Risk...' : '6. Generate Findings'}</span>
            </button>
          </div>
        </div>

        {/* Real-Time Action Feedback & Pipeline Notification Banner */}
        {actionStatus && (
          <div
            style={{
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              fontSize: '0.82rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '0.65rem',
              background: actionStatus.type === 'error'
                ? 'rgba(239, 68, 68, 0.12)'
                : actionStatus.type === 'running'
                ? 'rgba(56, 189, 248, 0.12)'
                : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${
                actionStatus.type === 'error'
                  ? 'rgba(239, 68, 68, 0.35)'
                  : actionStatus.type === 'running'
                  ? 'rgba(56, 189, 248, 0.35)'
                  : 'rgba(16, 185, 129, 0.35)'
              }`,
              color: actionStatus.type === 'error'
                ? 'var(--rose-400)'
                : actionStatus.type === 'running'
                ? 'var(--cyan-400)'
                : 'var(--emerald-400)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span
                className="badge"
                style={{
                  fontSize: '0.68rem',
                  fontWeight: 700,
                  background: actionStatus.type === 'error'
                    ? 'rgba(239, 68, 68, 0.25)'
                    : actionStatus.type === 'running'
                    ? 'rgba(56, 189, 248, 0.25)'
                    : 'rgba(16, 185, 129, 0.25)',
                  border: 'none',
                }}
              >
                {actionStatus.stageName}
              </span>
              <div>
                <strong>{actionStatus.message}</strong>
                {actionStatus.detail && (
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                    {actionStatus.detail}
                  </div>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              {actionStatus.type === 'success' && (
                <button
                  className="btn btn-secondary"
                  onClick={() => onNavigateTab(getStageTargetTab(actionStatus.stageNumber))}
                  style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                >
                  View Details &rarr;
                </button>
              )}
              {actionStatus.type === 'error' && getStageRetryHandler(actionStatus.stageNumber) && (
                <button
                  className="btn btn-primary"
                  onClick={getStageRetryHandler(actionStatus.stageNumber)}
                  style={{ padding: '0.2rem 0.55rem', fontSize: '0.72rem' }}
                >
                  Retry Action
                </button>
              )}
              {onDismissStatus && actionStatus.type !== 'running' && (
                <button
                  onClick={onDismissStatus}
                  className="btn btn-secondary"
                  style={{ padding: '0.2rem 0.45rem', fontSize: '0.72rem' }}
                  title="Dismiss"
                >
                  &times;
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Intelligence Stat Cards Grid */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Globe}
          label="Discovered Assets"
          value={assets.length}
          subtext={`${resolvingSubdomains.length} active resolving subdomains`}
          color="cyan"
          onClick={() => onNavigateTab('assets')}
        />

        <CompactStatCard
          icon={Network}
          label="DNS & Records"
          value={dnsRecords.length}
          subtext="Observed DNS records & routing"
          color="emerald"
          onClick={() => onNavigateTab('dns')}
        />

        <CompactStatCard
          icon={Cpu}
          label="Services & Tech"
          value={services.length}
          subtext={`${technologies.length} software technologies detected`}
          color="amber"
          onClick={() => onNavigateTab('services')}
        />

        <CompactStatCard
          icon={AlertTriangle}
          label="Correlated CVEs"
          value={vulnerabilities.length}
          subtext={kevVulns.length > 0 ? `${kevVulns.length} in CISA KEV` : 'No known exploited CVEs'}
          color={kevVulns.length > 0 ? 'rose' : 'purple'}
          onClick={() => onNavigateTab('vulnerabilities')}
        />

        <CompactStatCard
          icon={ShieldAlert}
          label="Security Findings"
          value={findings.length}
          subtext={`${criticalFindings.length} Critical, ${highFindings.length} High`}
          color={criticalFindings.length > 0 ? 'rose' : findings.length > 0 ? 'amber' : 'emerald'}
          onClick={() => onNavigateTab('findings')}
        />

        <CompactStatCard
          icon={History}
          label="Surface Changes"
          value={changes.length}
          subtext="Diff across completed ScanRuns"
          color="neutral"
          onClick={() => onNavigateTab('monitoring')}
        />
      </div>

      {/* Split Section: Top Findings vs Recent Changes */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1rem', width: '100%' }}>
        {/* Top Findings Panel */}
        <div className="glass-panel" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <ShieldAlert size={16} color="var(--rose-400)" />
              <h3 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Critical & High Risk Findings ({criticalFindings.length + highFindings.length})
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('findings')}
              style={{ background: 'transparent', border: 'none', color: 'var(--cyan-400)', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
            >
              View All <ArrowRight size={12} />
            </button>
          </div>

          {findings.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {findings
                .filter(f => ['CRITICAL', 'HIGH'].includes(f.severity.toUpperCase()))
                .slice(0, 5)
                .map(f => (
                  <div
                    key={f.id}
                    onClick={() => onNavigateTab('findings')}
                    style={{
                      padding: '0.55rem 0.75rem',
                      borderRadius: '8px',
                      background: 'rgba(15, 23, 42, 0.45)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '0.65rem',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem', overflow: 'hidden' }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                        {f.title}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        {f.asset?.value || investigation.target_domain} • {f.finding_type}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexShrink: 0 }}>
                      <RiskScoreBadge score={f.context_score} category={f.risk_category} />
                      <SeverityBadge severity={f.severity} size="sm" />
                    </div>
                  </div>
                ))}
              {criticalFindings.length === 0 && highFindings.length === 0 && (
                <div style={{ padding: '1.25rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  No Critical or High severity findings observed.
                </div>
              )}
            </div>
          ) : (
            <div style={{ padding: '1.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              No findings generated yet. Click <strong>6. Generate Findings</strong> above to evaluate risk.
            </div>
          )}
        </div>

        {/* Recent Surface Changes Panel */}
        <div className="glass-panel" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <History size={16} color="#c084fc" />
              <h3 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Recent Attack Surface Changes ({changes.length})
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('monitoring')}
              style={{ background: 'transparent', border: 'none', color: 'var(--cyan-400)', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
            >
              View All <ArrowRight size={12} />
            </button>
          </div>

          {changes.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {changes.slice(0, 5).map(c => {
                const typeStyle =
                  c.change_type === 'ADDED'
                    ? { bg: 'rgba(52, 211, 153, 0.15)', color: 'var(--emerald-400)', label: '+ ADDED' }
                    : c.change_type === 'REMOVED'
                    ? { bg: 'rgba(251, 113, 133, 0.15)', color: 'var(--rose-400)', label: '- REMOVED' }
                    : { bg: 'rgba(251, 191, 36, 0.15)', color: 'var(--amber-400)', label: '~ MODIFIED' };

                return (
                  <div
                    key={c.id}
                    onClick={() => onNavigateTab('monitoring')}
                    style={{
                      padding: '0.55rem 0.75rem',
                      borderRadius: '8px',
                      background: 'rgba(15, 23, 42, 0.45)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '0.65rem',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem', overflow: 'hidden' }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-primary)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                        {c.description || c.entity_key}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {c.category} • {c.entity_key}
                      </div>
                    </div>
                    <span
                      className="badge"
                      style={{
                        background: typeStyle.bg,
                        color: typeStyle.color,
                        fontSize: '0.62rem',
                        fontWeight: 700,
                        flexShrink: 0,
                      }}
                    >
                      {typeStyle.label}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ padding: '1.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              No scan differences computed yet. Use <strong>8. Monitoring & Changes</strong> to establish baseline.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OverviewDashboard;
