import React, { useState } from 'react';
import {
  Flame,
  AlertTriangle,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  Info
} from 'lucide-react';
import { VulnerabilityCorrelationDetail } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';
import { EmptyState } from '../common/EmptyState';
import { Modal } from '../common/Modal';
import { CompactStatCard } from '../common/CompactStatCard';

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* View Header & Pipeline Action */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <div style={{
                background: 'rgba(239, 68, 68, 0.15)',
                color: 'var(--rose-400)',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Flame size={18} />
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Vulnerability Intelligence & CVE Correlation</h2>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
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
              <Flame size={14} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Correlating CVEs...' : '5. Correlate CVEs'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '0.75rem', marginBottom: 0 }}>
            {error}
          </div>
        )}

        {/* Passive Intelligence Disclaimer */}
        <div style={{
          background: 'rgba(30, 41, 59, 0.5)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          borderRadius: '8px',
          padding: '0.65rem 0.85rem',
          marginTop: '0.85rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.65rem',
          fontSize: '0.78rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.45
        }}>
          <AlertTriangle size={16} color="var(--amber-400)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong style={{ color: 'var(--text-primary)' }}>Passive Intelligence Semantics: </strong>
            Correlated CVEs represent potential vulnerabilities derived from passive technology fingerprinting and version range matching.
            <strong> CVSS Base Severity is not equivalent to Contextual Risk</strong>, and items marked <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>REQUIRES_VERIFICATION</span> must not be assumed vulnerable without active confirmation.
          </div>
        </div>
      </div>

      {/* Compact Metrics Strip */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Flame}
          label="Correlated CVEs"
          value={vulnerabilities.length}
          subtext={`Target: ${targetDomain}`}
          color="cyan"
        />

        <CompactStatCard
          icon={ShieldAlert}
          label="Critical Severity"
          value={criticalCount}
          subtext="CVSS 9.0 - 10.0"
          color={criticalCount > 0 ? 'rose' : 'neutral'}
        />

        <CompactStatCard
          icon={AlertTriangle}
          label="High Severity"
          value={highCount}
          subtext="CVSS 7.0 - 8.9"
          color={highCount > 0 ? 'amber' : 'neutral'}
        />

        <CompactStatCard
          icon={ShieldCheck}
          label="Medium / Low"
          value={mediumCount}
          subtext="CVSS 0.1 - 6.9"
          color="emerald"
        />

        <CompactStatCard
          icon={Flame}
          label="CISA KEV Listed"
          value={kevCount}
          subtext="Known in-the-wild exploits"
          color={kevCount > 0 ? 'rose' : 'purple'}
        />

        <CompactStatCard
          icon={Info}
          label="Requires Verification"
          value={verificationCount}
          subtext="Unversioned or range matches"
          color="neutral"
        />
      </div>

      {/* Filters and Search Bar */}
      <div className="glass-panel" style={{ padding: '0.75rem 1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flex: 1, minWidth: '220px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
              <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search CVE, Tech, basis..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ width: '100%', paddingLeft: '1.9rem', fontSize: '0.8rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Filter size={13} color="var(--text-muted)" />
              <select
                className="form-input"
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                style={{ fontSize: '0.78rem', padding: '0.3rem 0.6rem' }}
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
              style={{ fontSize: '0.78rem', padding: '0.3rem 0.6rem' }}
            >
              <option value="ALL">All Statuses</option>
              <option value="POTENTIAL_MATCH">Potential Match</option>
              <option value="REQUIRES_VERIFICATION">Requires Verification</option>
            </select>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--rose-400)', cursor: 'pointer', fontWeight: 600 }}>
              <input
                type="checkbox"
                checked={kevOnly}
                onChange={e => setKevOnly(e.target.checked)}
              />
              CISA KEV Only
            </label>
          </div>

          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Showing <strong>{filteredVulns.length}</strong> of {vulnerabilities.length} correlations
          </div>
        </div>
      </div>

      {/* Vulnerabilities Table or Explanatory Empty State */}
      {filteredVulns.length > 0 ? (
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto', maxHeight: '550px' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE Identifier</th>
                  <th>Affected Component</th>
                  <th>Observed Version</th>
                  <th>Base Severity</th>
                  <th>CISA KEV</th>
                  <th>Correlation State</th>
                  <th>Correlation Match Basis</th>
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
                      <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                        {v.cve_id}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{v.technology_name}</td>
                    <td>
                      {v.observed_version ? (
                        <span className="badge badge-success font-mono" style={{ fontSize: '0.7rem' }}>
                          {v.observed_version}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>Not observed</span>
                      )}
                    </td>
                    <td>
                      <SeverityBadge severity={v.severity || 'UNKNOWN'} cvssScore={v.cvss_score} size="sm" />
                    </td>
                    <td>
                      {v.is_kev ? (
                        <span
                          className="badge badge-danger"
                          style={{
                            fontSize: '0.65rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.2rem',
                            fontWeight: 700
                          }}
                        >
                          <Flame size={11} /> KEV
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>No</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          v.correlation_status === 'POTENTIAL_MATCH' ? 'badge-warning' :
                          v.correlation_status === 'REQUIRES_VERIFICATION' ? 'badge-neutral' :
                          'badge-info'
                        }`}
                        style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)' }}
                      >
                        {v.correlation_status}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.match_basis || ''}>
                      {v.match_basis || '—'}
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                        {v.source}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
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
                ? "No vulnerability correlations generated for this ScanRun. Passive CVE correlation evaluates observed software components (like Apache, nginx, or WordPress) against the NVD and CISA KEV catalog. If no software technologies with identifiable versions were disclosed by target endpoints, zero CVE correlations are expected."
                : "No vulnerability records matched the current filter and search criteria."
            }
            icon={Flame}
            actionLabel={vulnerabilities.length === 0 ? "5. Correlate CVEs" : undefined}
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
          maxWidth="720px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                  {selectedVuln.cve_id}
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                  Affecting: <strong style={{ color: 'var(--text-primary)' }}>{selectedVuln.technology_name}</strong> {selectedVuln.observed_version ? `(${selectedVuln.observed_version})` : ''} on {selectedVuln.asset_value}
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <SeverityBadge severity={selectedVuln.severity || 'UNKNOWN'} cvssScore={selectedVuln.cvss_score} />
                {selectedVuln.is_kev && (
                  <span className="badge badge-danger">
                    <Flame size={12} /> CISA KEV
                  </span>
                )}
              </div>
            </div>

            {/* Description */}
            <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.85rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                Vulnerability Advisory Description
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                {selectedVuln.description || 'No detailed advisory description available from NVD.'}
              </div>
            </div>

            {/* Match Basis & Evidence */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.4)', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Correlation Status</div>
                <div style={{ marginTop: '0.2rem', fontWeight: 600, color: 'var(--amber-400)', fontSize: '0.82rem' }}>
                  {selectedVuln.correlation_status}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.4)', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Match Confidence</div>
                <div style={{ marginTop: '0.2rem', fontWeight: 600, color: 'var(--cyan-400)', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
                  {Math.round(selectedVuln.match_confidence * 100)}%
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button className="btn btn-secondary" onClick={() => setSelectedVuln(null)}>
                Close
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

export default VulnerabilitiesView;
