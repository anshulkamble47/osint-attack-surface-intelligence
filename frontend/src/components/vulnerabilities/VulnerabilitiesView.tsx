import React, { useState } from 'react';
import {
  Flame,
  AlertTriangle,
  Search,
  Filter,
  ExternalLink
} from 'lucide-react';
import { VulnerabilityCorrelationDetail } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';
import { EmptyState } from '../common/EmptyState';
import { Modal } from '../common/Modal';

interface VulnerabilitiesViewProps {
  vulnerabilities: VulnerabilityCorrelationDetail[];
  onRunCorrelation: () => void;
  loading: boolean;
  error: string | null;
  targetDomain: string;
}

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({
  vulnerabilities,
  onRunCorrelation,
  loading,
  error,
  targetDomain,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [kevOnly, setKevOnly] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<VulnerabilityCorrelationDetail | null>(null);

  const filteredVulns = vulnerabilities.filter(v => {
    if (kevOnly && !v.is_kev) return false;
    if (severityFilter !== 'ALL' && v.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && v.correlation_status !== statusFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchCve = v.cve_id.toLowerCase().includes(term);
      const matchTech = v.technology_name.toLowerCase().includes(term);
      const matchBasis = v.match_basis ? v.match_basis.toLowerCase().includes(term) : false;
      if (!matchCve && !matchTech && !matchBasis) return false;
    }
    return true;
  });

  const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
  const kevCount = vulnerabilities.filter(v => v.is_kev).length;
  const verificationCount = vulnerabilities.filter(v => v.correlation_status === 'REQUIRES_VERIFICATION').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* View Header & Pipeline Action */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(239, 68, 68, 0.15)',
                color: 'var(--red-400)',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Flame size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Vulnerability Intelligence & CVE Correlation</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Correlates observed technologies, web servers, and software components against the National Vulnerability Database (NVD) and CISA Known Exploited Vulnerabilities (KEV) catalog.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onRunCorrelation}
              disabled={loading}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #e11d48, #f43f5e)', border: 'none' }}
            >
              <Flame size={16} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Correlating CVEs...' : 'Run CVE Correlation'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
            {error}
          </div>
        )}

        {/* Passive Intelligence Disclaimer */}
        <div style={{
          background: 'rgba(30, 41, 59, 0.6)',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: '8px',
          padding: '0.85rem 1rem',
          marginTop: '1.25rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.75rem',
          fontSize: '0.82rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.45
        }}>
          <AlertTriangle size={18} color="var(--amber-400)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong style={{ color: 'var(--text-primary)' }}>Passive Intelligence & Verification Semantics: </strong>
            Correlated CVEs represent potential vulnerabilities based on passive technology fingerprinting and CPE/version range matching.
            <strong> CVSS Base Severity is not equivalent to Contextual Risk</strong>, and items marked <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>REQUIRES_VERIFICATION</span> must not be assumed to be confirmed vulnerable without active validation.
          </div>
        </div>
      </div>

      {/* Metrics Strip */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Correlated CVEs</div>
          <div className="stat-value">{vulnerabilities.length}</div>
          <div className="stat-subtext">Across target {targetDomain}</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(239, 68, 68, 0.3)' }}>
          <div className="stat-label" style={{ color: 'var(--red-400)' }}>Critical Severity</div>
          <div className="stat-value" style={{ color: 'var(--red-400)' }}>{criticalCount}</div>
          <div className="stat-subtext">CVSS 9.0 - 10.0 Base Score</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(249, 115, 22, 0.3)' }}>
          <div className="stat-label" style={{ color: '#fb923c' }}>High Severity</div>
          <div className="stat-value" style={{ color: '#fb923c' }}>{highCount}</div>
          <div className="stat-subtext">CVSS 7.0 - 8.9 Base Score</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(250, 204, 21, 0.3)' }}>
          <div className="stat-label" style={{ color: '#facc15' }}>Medium Severity</div>
          <div className="stat-value" style={{ color: '#facc15' }}>{mediumCount}</div>
          <div className="stat-subtext">CVSS 4.0 - 6.9 Base Score</div>
        </div>

        <div className="stat-card" style={{ borderColor: 'rgba(244, 63, 94, 0.3)' }}>
          <div className="stat-label" style={{ color: '#f43f5e' }}>CISA KEV Listed</div>
          <div className="stat-value" style={{ color: '#f43f5e' }}>{kevCount}</div>
          <div className="stat-subtext">Active in-the-wild exploitation</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Requires Verification</div>
          <div className="stat-value">{verificationCount}</div>
          <div className="stat-subtext">Version unobserved / range match</div>
        </div>
      </div>

      {/* Filters and Search Bar */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '240px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '320px' }}>
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search CVE, Tech, Match basis..."
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
              </select>
            </div>

            <select
              className="form-input"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
            >
              <option value="ALL">All Correlation Statuses</option>
              <option value="POTENTIAL_MATCH">Potential Match</option>
              <option value="REQUIRES_VERIFICATION">Requires Verification</option>
              <option value="CONFIRMED_MATCH">Confirmed Match</option>
            </select>
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={e => setKevOnly(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <span style={{ color: kevOnly ? 'var(--red-400)' : 'var(--text-secondary)', fontWeight: kevOnly ? 600 : 400 }}>
              CISA KEV Listed Only ({kevCount})
            </span>
          </label>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      {filteredVulns.length > 0 ? (
        <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
              Correlated Vulnerability Intelligence Records ({filteredVulns.length})
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Click row to inspect full CVE intelligence & remediation
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Observed Technology</th>
                  <th>Observed Version</th>
                  <th>CVSS Base Severity</th>
                  <th>CISA KEV</th>
                  <th>Correlation Status</th>
                  <th>Match Basis</th>
                  <th>Source</th>
                  <th>Published</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.map((v, idx) => (
                  <tr
                    key={idx}
                    onClick={() => setSelectedVuln(v)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                          {v.cve_id}
                        </span>
                      </div>
                    </td>
                    <td style={{ fontWeight: 600 }}>{v.technology_name}</td>
                    <td>
                      {v.observed_version ? (
                        <span className="badge badge-success font-mono" style={{ fontSize: '0.75rem' }}>
                          {v.observed_version}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Version not observed</span>
                      )}
                    </td>
                    <td>
                      <SeverityBadge severity={v.severity || 'UNKNOWN'} cvssScore={v.cvss_score} />
                    </td>
                    <td>
                      {v.is_kev ? (
                        <span
                          className="badge badge-danger"
                          style={{
                            fontSize: '0.7rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                            fontWeight: 700
                          }}
                        >
                          <Flame size={12} /> KEV Listed
                          {v.kev_details?.ransomware_campaign === 'Known' && ' (Ransomware)'}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          v.correlation_status === 'POTENTIAL_MATCH' ? 'badge-warning' :
                          v.correlation_status === 'REQUIRES_VERIFICATION' ? 'badge-neutral' :
                          'badge-info'
                        }`}
                        style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)' }}
                      >
                        {v.correlation_status}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.match_basis || ''}>
                      {v.match_basis || '—'}
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                        {v.source}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {v.published_date ? new Date(v.published_date).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <EmptyState
            title={vulnerabilities.length === 0 ? "No Vulnerability Correlations Available" : "No Matching Vulnerabilities"}
            description={
              vulnerabilities.length === 0
                ? "No passive CVE correlations have been executed for this scan run yet. Run CVE correlation to cross-reference detected technologies with the NVD and CISA KEV catalog."
                : "No vulnerability records matched the current filter and search criteria."
            }
            icon={Flame}
            actionLabel={vulnerabilities.length === 0 ? "Run CVE Correlation" : undefined}
            onAction={vulnerabilities.length === 0 ? onRunCorrelation : undefined}
          />
        </div>
      )}

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <Modal
          title={`Vulnerability Intelligence: ${selectedVuln.cve_id}`}
          isOpen={!!selectedVuln}
          onClose={() => setSelectedVuln(null)}
          maxWidth="750px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Header info */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                  {selectedVuln.cve_id}
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                  Technology: <strong style={{ color: 'var(--text-primary)' }}>{selectedVuln.technology_name}</strong>
                  {selectedVuln.observed_version && ` (Observed: ${selectedVuln.observed_version})`}
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <SeverityBadge severity={selectedVuln.severity || 'UNKNOWN'} cvssScore={selectedVuln.cvss_score} />
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-secondary"
                  style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
                >
                  <ExternalLink size={13} />
                  <span>NVD Entry</span>
                </a>
              </div>
            </div>

            {/* CISA KEV Alert Box if applicable */}
            {selectedVuln.is_kev && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid var(--red-500)',
                borderRadius: '8px',
                padding: '1rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--red-400)', fontWeight: 700, fontSize: '0.9rem' }}>
                  <Flame size={18} />
                  <span>CISA Known Exploited Vulnerability (KEV) Catalog</span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                  This vulnerability is confirmed to be actively exploited in the wild. Prioritize remediation and isolation of this asset.
                </p>
                {selectedVuln.kev_details && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Due Date: </span>
                      <span style={{ color: 'var(--red-400)', fontWeight: 600 }}>{selectedVuln.kev_details.due_date || 'Immediate'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Ransomware Campaign: </span>
                      <span style={{ color: 'var(--text-primary)' }}>{selectedVuln.kev_details.ransomware_campaign || 'Not Documented'}</span>
                    </div>
                    <div style={{ gridColumn: '1 / -1' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Required Action: </span>
                      <span style={{ color: 'var(--text-primary)' }}>{selectedVuln.kev_details.required_action || 'Apply official vendor patch/mitigation'}</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Correlation Semantics Strip */}
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.5rem' }}>
                CORRELATION & EVIDENCE METADATA
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Correlation Status: </span>
                  <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>{selectedVuln.correlation_status}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Intelligence Source: </span>
                  <span style={{ color: 'var(--text-primary)' }}>{selectedVuln.source}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>CVSS Base Vector: </span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{selectedVuln.cvss_vector || 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Published Date: </span>
                  <span style={{ color: 'var(--text-primary)' }}>{selectedVuln.published_date ? new Date(selectedVuln.published_date).toLocaleDateString() : 'N/A'}</span>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Match Basis: </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{selectedVuln.match_basis || 'Automated CPE substring and version range mapping'}</span>
                </div>
              </div>
            </div>

            {/* Description & Impact */}
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                Vulnerability Summary
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, background: 'rgba(0, 0, 0, 0.3)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                {selectedVuln.description || 'No detailed description available from intelligence provider.'}
              </p>
            </div>

            {/* Remediation guidance */}
            <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '1rem' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--emerald-400)', marginBottom: '0.3rem' }}>
                Recommended Remediation Strategy
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.45 }}>
                {`Verify if ${selectedVuln.technology_name} ${selectedVuln.observed_version || ''} is exposed to untrusted networks. Update ${selectedVuln.technology_name} to the latest supported vendor release, or apply vendor-recommended configuration mitigations.`}
              </p>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
