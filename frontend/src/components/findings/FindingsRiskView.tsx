import React, { useState } from 'react';
import {
  ShieldAlert,
  Zap,
  Filter,
  Search,
  Flame
} from 'lucide-react';
import { FindingResponse } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { StatusBadge } from '../common/StatusBadge';
import { EmptyState } from '../common/EmptyState';

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Generate Action */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(244, 63, 94, 0.15)',
                color: 'var(--rose-400)',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <ShieldAlert size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Findings & Contextual Risk Assessment</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Evidence-backed security findings synthesized across vulnerabilities, exposed services, weak security headers, and TLS configurations with explainable contextual risk scores (0-100).
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onGenerateFindings}
              disabled={loading}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #e11d48, #f43f5e)', border: 'none' }}
            >
              <Zap size={16} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Evaluating Risk Model...' : 'Generate Findings & Risk'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
            {error}
          </div>
        )}
      </div>

      {/* Summary Metrics Strip */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Correlated Findings</div>
          <div className="stat-value">{findings.length}</div>
          <div className="stat-subtext">Across target {targetDomain}</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(239, 68, 68, 0.3)' }}>
          <div className="stat-label" style={{ color: 'var(--red-400)' }}>Critical Severity</div>
          <div className="stat-value" style={{ color: 'var(--red-400)' }}>{criticalCount}</div>
          <div className="stat-subtext">Immediate attention required</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(249, 115, 22, 0.3)' }}>
          <div className="stat-label" style={{ color: '#fb923c' }}>High Severity</div>
          <div className="stat-value" style={{ color: '#fb923c' }}>{highCount}</div>
          <div className="stat-subtext">High risk exposure</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(250, 204, 21, 0.3)' }}>
          <div className="stat-label" style={{ color: '#facc15' }}>Medium / Low</div>
          <div className="stat-value" style={{ color: '#facc15' }}>{mediumLowCount}</div>
          <div className="stat-subtext">Moderate to low exposure</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(244, 63, 94, 0.3)' }}>
          <div className="stat-label" style={{ color: '#f43f5e' }}>CISA KEV Listed</div>
          <div className="stat-value" style={{ color: '#f43f5e' }}>{kevCount}</div>
          <div className="stat-subtext">Exploited in the wild</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Open Findings</div>
          <div className="stat-value" style={{ color: 'var(--cyan-400)' }}>{openCount}</div>
          <div className="stat-subtext">Pending resolution</div>
        </div>
      </div>

      {/* Search & Filters */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '240px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '300px' }}>
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search findings, assets, tech..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={15} color="var(--text-muted)" />
              <select
                className="form-input"
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
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
              style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
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
              style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
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
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1.1fr)', gap: '1.25rem', alignItems: 'start' }}>

          {/* Left: Findings List */}
          <div className="glass-panel" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                Correlated Security Findings ({filteredFindings.length})
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Click finding to inspect risk factors
              </span>
            </div>

            <div style={{ maxHeight: '560px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {filteredFindings.map(finding => {
                const isSelected = selectedFinding?.id === finding.id;

                return (
                  <div
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    style={{
                      padding: '0.85rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(244, 63, 94, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                      border: `1px solid ${isSelected ? 'var(--rose-500)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.45rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', minWidth: 0 }}>
                        <SeverityBadge severity={finding.severity} />
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {finding.reference_code}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        {finding.is_kev && (
                          <span
                            className="badge badge-danger"
                            style={{
                              fontSize: '0.65rem',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.2rem',
                              fontWeight: 700,
                              padding: '0.1rem 0.35rem'
                            }}
                          >
                            <Flame size={11} /> CISA KEV
                          </span>
                        )}
                        <RiskScoreBadge score={finding.context_score} category={finding.risk_category} />
                      </div>
                    </div>

                    <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {finding.title}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{finding.asset?.value || 'Target Asset'}</span>
                      <StatusBadge status={finding.status} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected Finding Inspector Panel */}
          <div className="glass-panel" style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={18} color="var(--rose-400)" />
                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Finding Inspector & Risk Model
                </h4>
              </div>

              {selectedFinding && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Lifecycle:</span>
                  <select
                    className="form-input"
                    value={selectedFinding.status}
                    onChange={e => onUpdateStatus(selectedFinding.id, e.target.value)}
                    style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', width: 'auto' }}
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
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {selectedFinding.reference_code}
                    </span>
                    <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                      {selectedFinding.finding_type}
                    </span>
                    <StatusBadge status={selectedFinding.status} />
                  </div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {selectedFinding.title}
                  </h3>
                </div>

                {/* Side-by-Side Contextual Risk vs CVSS Base Score */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: '8px', padding: '0.85rem' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--rose-400)', fontWeight: 700, letterSpacing: '0.04em' }}>
                      PLATFORM CONTEXTUAL RISK
                    </div>
                    <div style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--rose-400)', marginTop: '0.2rem' }}>
                      {selectedFinding.context_score} / 100
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                      Category: <strong style={{ color: 'var(--rose-400)' }}>{selectedFinding.risk_category}</strong>
                    </div>
                  </div>

                  <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0.85rem' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--cyan-400)', fontWeight: 700, letterSpacing: '0.04em' }}>
                      NVD CVSS BASE SCORE
                    </div>
                    <div style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--cyan-400)', marginTop: '0.2rem' }}>
                      {selectedFinding.cvss_score !== null && selectedFinding.cvss_score !== undefined ? `${selectedFinding.cvss_score} / 10.0` : 'N/A'}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                      Severity: <strong>{selectedFinding.severity}</strong>
                    </div>
                  </div>
                </div>

                {/* Explainable Risk Scoring Breakdown */}
                {selectedFinding.risk_factors && (
                  <div style={{ background: 'rgba(0, 0, 0, 0.35)', borderRadius: '8px', padding: '0.85rem', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      <Zap size={13} color="var(--rose-400)" />
                      <span>Contextual Risk Factors & Calculation Weights:</span>
                    </div>
                    <table className="data-table" style={{ fontSize: '0.75rem' }}>
                      <tbody>
                        <tr>
                          <td style={{ color: 'var(--text-muted)' }}>Base Score Factor:</td>
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
                            <td style={{ color: '#fb923c', fontWeight: 600 }}>Asset Exposure Weight:</td>
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
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>
                    FINDING DESCRIPTION
                  </div>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                    {selectedFinding.description}
                  </p>
                </div>

                {/* Recommended Remediation */}
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '0.85rem' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--emerald-400)', marginBottom: '0.25rem' }}>
                    RECOMMENDED REMEDIATION
                  </div>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.45 }}>
                    {selectedFinding.remediation || selectedFinding.recommendation || 'Apply vendor security patch and restrict network access to authoritative endpoints.'}
                  </p>
                </div>

                {/* Target Asset & Technology Details */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
                  <div style={{ background: 'rgba(15, 23, 42, 0.4)', padding: '0.65rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Target Asset</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.15rem' }}>
                      {selectedFinding.asset?.value || 'Target Root'}
                    </div>
                  </div>

                  {selectedFinding.technology && (
                    <div style={{ background: 'rgba(15, 23, 42, 0.4)', padding: '0.65rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Affected Technology</div>
                      <div style={{ fontWeight: 600, color: '#a78bfa', marginTop: '0.15rem' }}>
                        {selectedFinding.technology.name} {selectedFinding.technology.version || ''}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '3.5rem 1rem' }}>
                Select a finding from the list to view its risk scoring breakdown, evidence provenance, and remediation guidance.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <EmptyState
            title="No Security Findings Generated"
            description="No findings have been synthesized for this investigation yet. Run finding generation to evaluate attack surface observations through the contextual risk engine."
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
