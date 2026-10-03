import React, { useState } from 'react';
import {
  ShieldAlert,
  Zap,
  Filter,
  Search,
  Flame,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Layers
} from 'lucide-react';
import { FindingResponse } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { StatusBadge } from '../common/StatusBadge';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';

interface FindingsRiskViewProps {
  findings: FindingResponse[];
  onGenerateFindings: () => void;
  onUpdateStatus: (findingId: string, newStatus: string) => void;
  loading: boolean;
  error: string | null;
  selectedFinding: FindingResponse | null;
  onSelectFinding: (finding: FindingResponse) => void;
  targetDomain: string;
}

export const FindingsRiskView: React.FC<FindingsRiskViewProps> = ({
  findings,
  onGenerateFindings,
  onUpdateStatus,
  loading,
  error,
  selectedFinding,
  onSelectFinding,
  targetDomain,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');

  const filteredFindings = findings.filter(f => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
    if (typeFilter !== 'ALL' && f.finding_type !== typeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(term);
      const matchRef = f.reference_code.toLowerCase().includes(term);
      const matchAsset = f.asset?.value.toLowerCase().includes(term);
      const matchTech = f.technology?.name.toLowerCase().includes(term);
      if (!matchTitle && !matchRef && !matchAsset && !matchTech) return false;
    }
    return true;
  });

  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumLowCount = findings.filter(f => f.severity === 'MEDIUM' || f.severity === 'LOW').length;
  const kevCount = findings.filter(f => f.is_kev).length;
  const openCount = findings.filter(f => f.status === 'open').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & Generate Action */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.85rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
              <div style={{
                background: 'rgba(244, 63, 94, 0.15)',
                color: 'var(--rose-400)',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <ShieldAlert size={18} />
              </div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Findings & Contextual Risk Assessment</h2>
              <span className="badge badge-danger" style={{ fontSize: '0.68rem' }}>Risk Model</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
              Evidence-backed security findings synthesized across vulnerabilities, exposed services, weak headers, and TLS configurations with explainable contextual risk scores (0–100).
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <button
              onClick={onGenerateFindings}
              disabled={loading}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #e11d48, #f43f5e)', border: 'none', padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
            >
              <Zap size={14} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Evaluating Risk Model...' : 'Generate Findings & Risk'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '0.75rem', padding: '0.5rem 0.75rem', fontSize: '0.8rem' }}>
            {error}
          </div>
        )}
      </div>

      {/* Compact Metrics Strip */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Layers}
          label="Total Findings"
          value={findings.length}
          subtext={`Target ${targetDomain}`}
          color="neutral"
        />
        <CompactStatCard
          icon={AlertTriangle}
          label="Critical Severity"
          value={criticalCount}
          subtext="Immediate action needed"
          color="rose"
        />
        <CompactStatCard
          icon={AlertTriangle}
          label="High Severity"
          value={highCount}
          subtext="Elevated risk exposure"
          color="amber"
        />
        <CompactStatCard
          icon={Lock}
          label="Medium / Low"
          value={mediumLowCount}
          subtext="Moderate exposure"
          color="cyan"
        />
        <CompactStatCard
          icon={Flame}
          label="CISA KEV Listed"
          value={kevCount}
          subtext="Actively exploited"
          color="rose"
        />
        <CompactStatCard
          icon={CheckCircle2}
          label="Open Findings"
          value={openCount}
          subtext="Pending resolution"
          color="emerald"
        />
      </div>

      {/* Search & Filters */}
      <div className="glass-panel" style={{ padding: '0.65rem 1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.6rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flex: 1, minWidth: '240px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '260px' }}>
              <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search findings, assets, tech..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '2rem', padding: '0.35rem 0.6rem 0.35rem 2rem', fontSize: '0.78rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                className="form-input"
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Informational</option>
              </select>
            </div>

            <select
              className="form-input"
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
            >
              <option value="ALL">All Finding Types</option>
              <option value="VULNERABILITY">Vulnerability</option>
              <option value="SECURITY_HEADER">Security Header</option>
              <option value="TLS_SECURITY">TLS Security</option>
              <option value="SERVICE_EXPOSURE">Service Exposure</option>
            </select>

            <select
              className="form-input"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
            >
              <option value="ALL">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
              <option value="suppressed">Suppressed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Workspace Split Layout */}
      {findings.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1.1fr)', gap: '1rem', alignItems: 'start' }}>

          {/* Left: Findings List */}
          <div className="glass-panel" style={{ padding: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                Synthesized Security Findings ({filteredFindings.length})
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Click finding to inspect contextual risk model
              </span>
            </div>

            <div style={{ maxHeight: '540px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
              {filteredFindings.map(finding => {
                const isSelected = selectedFinding?.id === finding.id;

                return (
                  <div
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(244, 63, 94, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                      border: `1px solid ${isSelected ? 'var(--rose-500)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', minWidth: 0, flexWrap: 'wrap' }}>
                        <SeverityBadge severity={finding.severity} />
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {finding.reference_code}
                        </span>
                        {finding.category === 'vulnerability' && (
                          (finding.correlation_status === 'REQUIRES_VERIFICATION' || (!finding.is_version_supported && !finding.technology?.version)) ? (
                            <span
                              className="badge badge-warning"
                              style={{
                                fontSize: '0.6rem',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.2rem',
                                fontWeight: 600,
                                padding: '0.05rem 0.3rem',
                              }}
                            >
                              <AlertTriangle size={9} /> REQUIRES VERIFICATION
                            </span>
                          ) : (
                            <span
                              className="badge badge-info"
                              style={{
                                fontSize: '0.6rem',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.2rem',
                                fontWeight: 600,
                                padding: '0.05rem 0.3rem',
                              }}
                            >
                              <CheckCircle2 size={9} /> VERSION MATCH
                            </span>
                          )
                        )}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        {finding.is_kev && (
                          <span
                            className="badge badge-danger"
                            style={{
                              fontSize: '0.62rem',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.2rem',
                              fontWeight: 700,
                              padding: '0.08rem 0.3rem'
                            }}
                          >
                            <Flame size={10} /> CISA KEV
                          </span>
                        )}
                        <RiskScoreBadge score={finding.context_score} category={finding.risk_category} />
                      </div>
                    </div>

                    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {finding.title}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{finding.asset?.value || 'Target Asset'}</span>
                      <StatusBadge status={finding.status} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected Finding Inspector Panel */}
          <div className="glass-panel" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.65rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <ShieldAlert size={16} color="var(--rose-400)" />
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Finding Risk & Evidence Inspector
                </h4>
              </div>

              {selectedFinding && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Status:</span>
                  <select
                    className="form-input"
                    value={selectedFinding.status}
                    onChange={e => onUpdateStatus(selectedFinding.id, e.target.value)}
                    style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', width: 'auto' }}
                  >
                    <option value="open">Open</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="resolved">Resolved</option>
                    <option value="suppressed">Suppressed</option>
                  </select>
                </div>
              )}
            </div>

            {selectedFinding ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {selectedFinding.reference_code}
                    </span>
                    <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                      {selectedFinding.finding_type}
                    </span>
                    <StatusBadge status={selectedFinding.status} />
                  </div>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {selectedFinding.title}
                  </h3>
                </div>

                {/* Side-by-Side Contextual Risk vs CVSS Base Score */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem' }}>
                  <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: '8px', padding: '0.75rem' }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--rose-400)', fontWeight: 700, letterSpacing: '0.04em' }}>
                      PLATFORM CONTEXTUAL RISK
                    </div>
                    <div style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--rose-400)', marginTop: '0.15rem' }}>
                      {selectedFinding.context_score} / 100
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
                      Category: <strong style={{ color: 'var(--rose-400)' }}>{selectedFinding.risk_category}</strong>
                    </div>
                  </div>

                  <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0.75rem' }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--cyan-400)', fontWeight: 700, letterSpacing: '0.04em' }}>
                      NVD CVSS BASE SCORE
                    </div>
                    <div style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--cyan-400)', marginTop: '0.15rem' }}>
                      {selectedFinding.cvss_score !== null && selectedFinding.cvss_score !== undefined ? `${selectedFinding.cvss_score} / 10.0` : 'N/A'}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
                      Severity: <strong>{selectedFinding.severity}</strong>
                    </div>
                  </div>
                </div>

                {/* Vulnerability Correlation & Verification State */}
                {selectedFinding.category === 'vulnerability' ? (
                  (() => {
                    const isRequiresVerification =
                      selectedFinding.correlation_status === 'REQUIRES_VERIFICATION' ||
                      (!selectedFinding.is_version_supported && !selectedFinding.technology?.version);

                    const matchBasis =
                      selectedFinding.match_basis ||
                      selectedFinding.risk_factors?.match_basis ||
                      (isRequiresVerification
                        ? `Observed technology '${selectedFinding.technology?.name || 'Unknown'}' without concrete version. Verification required.`
                        : `Observed technology '${selectedFinding.technology?.name || 'Unknown'}' version '${selectedFinding.technology?.version || ''}' matches advisory.`);

                    return (
                      <div
                        style={{
                          background: isRequiresVerification ? 'rgba(245, 158, 11, 0.08)' : 'rgba(56, 189, 248, 0.08)',
                          border: `1px solid ${isRequiresVerification ? 'rgba(245, 158, 11, 0.3)' : 'rgba(56, 189, 248, 0.3)'}`,
                          borderRadius: '8px',
                          padding: '0.85rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.45rem',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                            {isRequiresVerification ? (
                              <AlertTriangle size={15} color="#fbbf24" />
                            ) : (
                              <CheckCircle2 size={15} color="var(--cyan-400)" />
                            )}
                            <span
                              style={{
                                fontSize: '0.74rem',
                                fontWeight: 700,
                                color: isRequiresVerification ? '#fbbf24' : 'var(--cyan-400)',
                                letterSpacing: '0.03em',
                              }}
                            >
                              CORRELATION STATUS: {isRequiresVerification ? 'REQUIRES_VERIFICATION' : 'VERSION-SUPPORTED MATCH'}
                            </span>
                          </div>
                          <span
                            className={`badge ${isRequiresVerification ? 'badge-warning' : 'badge-info'}`}
                            style={{ fontSize: '0.62rem', fontWeight: 700, padding: '0.1rem 0.4rem' }}
                          >
                            {isRequiresVerification ? 'REQUIRES_VERIFICATION' : 'VERSION MATCH'}
                          </span>
                        </div>

                        <p
                          style={{
                            fontSize: '0.78rem',
                            color: 'var(--text-primary)',
                            lineHeight: 1.45,
                            margin: 0,
                            padding: '0.45rem 0.6rem',
                            background: 'rgba(0, 0, 0, 0.25)',
                            borderRadius: '5px',
                            borderLeft: `3px solid ${isRequiresVerification ? '#fbbf24' : 'var(--cyan-400)'}`,
                          }}
                        >
                          {isRequiresVerification
                            ? 'Technology was observed, but a concrete affected version was not established. This finding is a potential correlation and requires verification.'
                            : 'Observed technology version satisfies published advisory criteria. Dynamic verification or active validation is recommended to confirm exploitability.'}
                        </p>

                        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.1rem' }}>
                          <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Match Evidence Basis: </span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{matchBasis}</span>
                        </div>

                        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                          * Passive correlation only — does NOT constitute proof that the target is actively exploited.
                        </div>
                      </div>
                    );
                  })()
                ) : (
                  <div
                    style={{
                      background: 'rgba(16, 185, 129, 0.08)',
                      border: '1px solid rgba(16, 185, 129, 0.3)',
                      borderRadius: '8px',
                      padding: '0.75rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <CheckCircle2 size={14} color="var(--emerald-400)" />
                        <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--emerald-400)', letterSpacing: '0.03em' }}>
                          CORRELATION STATUS: DIRECT OBSERVATION
                        </span>
                      </div>
                      <span className="badge badge-success" style={{ fontSize: '0.62rem', fontWeight: 700, padding: '0.1rem 0.4rem' }}>
                        CONFIRMED OBSERVATION
                      </span>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                      <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Evidence Basis: </span>
                      <span>{selectedFinding.match_basis || selectedFinding.risk_factors?.match_basis || 'Direct service configuration observed over network interface.'}</span>
                    </div>
                  </div>
                )}

                {/* Explainable Risk Scoring Breakdown */}
                {selectedFinding.risk_factors && (
                  <div style={{ background: 'rgba(0, 0, 0, 0.35)', borderRadius: '8px', padding: '0.75rem', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Zap size={12} color="var(--rose-400)" />
                      <span>Contextual Risk Factors & Weight Formula:</span>
                    </div>
                    <table className="data-table" style={{ fontSize: '0.72rem' }}>
                      <tbody>
                        <tr>
                          <td style={{ color: 'var(--text-muted)' }}>Base Factor:</td>
                          <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{selectedFinding.risk_factors.base_factor} pts</td>
                        </tr>
                        {selectedFinding.risk_factors.cisa_kev_adjustment > 0 && (
                          <tr>
                            <td style={{ color: 'var(--rose-400)', fontWeight: 600 }}>CISA KEV Weight:</td>
                            <td style={{ color: 'var(--rose-400)', fontWeight: 600 }}>
                              +{selectedFinding.risk_factors.cisa_kev_adjustment} pts ({selectedFinding.risk_factors.cisa_kev_reason})
                            </td>
                          </tr>
                        )}
                        {selectedFinding.risk_factors.exposure_adjustment > 0 && (
                          <tr>
                            <td style={{ color: '#fb923c', fontWeight: 600 }}>Exposure Weight:</td>
                            <td style={{ color: '#fb923c', fontWeight: 600 }}>
                              +{selectedFinding.risk_factors.exposure_adjustment} pts ({selectedFinding.risk_factors.exposure_reason})
                            </td>
                          </tr>
                        )}
                        {selectedFinding.risk_factors.confidence_adjustment !== 0 && (
                          <tr>
                            <td style={{ color: 'var(--cyan-400)' }}>Confidence Adjustment:</td>
                            <td style={{ color: 'var(--cyan-400)' }}>
                              {selectedFinding.risk_factors.confidence_adjustment > 0 ? `+${selectedFinding.risk_factors.confidence_adjustment}` : selectedFinding.risk_factors.confidence_adjustment} pts ({selectedFinding.risk_factors.confidence_reason})
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Finding Description */}
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.2rem' }}>
                    FINDING DESCRIPTION
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.45, background: 'rgba(0,0,0,0.25)', padding: '0.65rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', margin: 0 }}>
                    {selectedFinding.description}
                  </p>
                </div>

                {/* Recommended Remediation */}
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '0.75rem' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--emerald-400)', marginBottom: '0.2rem' }}>
                    RECOMMENDED REMEDIATION
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: 1.4, margin: 0 }}>
                    {selectedFinding.remediation || selectedFinding.recommendation || 'Apply vendor security patch and restrict network access to authoritative endpoints.'}
                  </p>
                </div>

                {/* Target Asset & Technology Details */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem', fontSize: '0.78rem' }}>
                  <div style={{ background: 'rgba(15, 23, 42, 0.4)', padding: '0.55rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Target Asset</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>
                      {selectedFinding.asset?.value || 'Target Root'}
                    </div>
                  </div>

                  {selectedFinding.technology && (
                    <div style={{ background: 'rgba(15, 23, 42, 0.4)', padding: '0.55rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Affected Technology</div>
                      <div style={{ fontWeight: 600, color: '#a78bfa', marginTop: '0.1rem' }}>
                        {selectedFinding.technology.name} {selectedFinding.technology.version || ''}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', padding: '3rem 1rem' }}>
                Select a finding from the list to view its risk scoring breakdown, evidence provenance, and remediation guidance.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <EmptyState
            title="No Findings Generated for this ScanRun"
            description="No qualifying vulnerability, configuration, TLS, header, or service findings were identified in this ScanRun. Click Generate Findings & Risk to synthesize findings across observed attack surface telemetry."
            icon={ShieldAlert}
            actionLabel="Generate Findings & Risk"
            onAction={onGenerateFindings}
          />
        </div>
      )}
    </div>
  );
};

export default FindingsRiskView;
