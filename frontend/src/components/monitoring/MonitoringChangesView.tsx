import React, { useState } from 'react';
import {
  History,
  GitCompare,
  Filter,
  Search,
  Info,
  Hash
} from 'lucide-react';
import { ChangeRecordResponse, ComparisonSummaryResponse } from '../../types/api';
import { EmptyState } from '../common/EmptyState';

interface MonitoringChangesViewProps {
  comparisonResult: ComparisonSummaryResponse | null;
  changes: ChangeRecordResponse[];
  onCompareScans: () => void;
  loading: boolean;
  error: string | null;
  baselineScanId: string;
  onChangeBaselineScanId: (id: string) => void;
  currentScanId: string;
  onChangeCurrentScanId: (id: string) => void;
  selectedChange: ChangeRecordResponse | null;
  onSelectChange: (change: ChangeRecordResponse) => void;
}

export const MonitoringChangesView: React.FC<MonitoringChangesViewProps> = ({
  comparisonResult,
  changes,
  onCompareScans,
  loading,
  error,
  baselineScanId,
  onChangeBaselineScanId,
  currentScanId,
  onChangeCurrentScanId,
  selectedChange,
  onSelectChange,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const filteredChanges = changes.filter(c => {
    if (typeFilter !== 'ALL' && c.change_type !== typeFilter) return false;
    if (categoryFilter !== 'ALL' && c.category !== categoryFilter && c.field_name !== categoryFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchKey = c.entity_key ? c.entity_key.toLowerCase().includes(term) : false;
      const matchDesc = c.description ? c.description.toLowerCase().includes(term) : false;
      const matchCat = c.category ? c.category.toLowerCase().includes(term) : false;
      if (!matchKey && !matchDesc && !matchCat) return false;
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Diffing Pipeline Action */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(6, 182, 212, 0.15)',
                color: 'var(--cyan-400)',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <History size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Attack Surface Monitoring & Change Detection</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Deterministic, evidence-backed point-in-time diffing across subdomains, DNS records, public IPs, services, technologies, vulnerabilities, and certificates.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <input
                type="text"
                className="form-input"
                placeholder="Baseline Scan ID (optional)"
                value={baselineScanId}
                onChange={e => onChangeBaselineScanId(e.target.value)}
                style={{ width: '170px', padding: '0.4rem 0.6rem', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
              />
              <input
                type="text"
                className="form-input"
                placeholder="Current Scan ID (optional)"
                value={currentScanId}
                onChange={e => onChangeCurrentScanId(e.target.value)}
                style={{ width: '170px', padding: '0.4rem 0.6rem', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
              />
            </div>

            <button
              onClick={onCompareScans}
              disabled={loading}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #0284c7, #06b6d4)', border: 'none' }}
            >
              <GitCompare size={15} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Diffing Scans...' : 'Compare Scan Runs'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
            {error}
          </div>
        )}

        {/* Change Semantics Notice */}
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
          <Info size={18} color="var(--cyan-400)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong style={{ color: 'var(--text-primary)' }}>Deterministic Change Semantics: </strong>
            <strong style={{ color: 'var(--emerald-400)' }}>ADDED:</strong> Previously not observed, now observed. •
            <strong style={{ color: 'var(--rose-400)' }}> REMOVED:</strong> Previously observed in baseline scan, not observed in the current completed scan (absence from a passive scan does NOT prove remediation or physical deletion). •
            <strong style={{ color: '#facc15' }}> MODIFIED:</strong> Observed in both scans with tracked observable properties changed.
          </div>
        </div>
      </div>

      {/* Summary Metrics Strip */}
      {comparisonResult && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">Total Detected Changes</div>
            <div className="stat-value">{comparisonResult.total_changes}</div>
            <div className="stat-subtext">Across compared scan runs</div>
          </div>

          <div className="stat-card" style={{ borderColor: 'rgba(16, 185, 129, 0.3)' }}>
            <div className="stat-label" style={{ color: 'var(--emerald-400)' }}>Added (+)</div>
            <div className="stat-value" style={{ color: 'var(--emerald-400)' }}>+{comparisonResult.added_count}</div>
            <div className="stat-subtext">Newly observed attack surface</div>
          </div>

          <div className="stat-card" style={{ borderColor: 'rgba(244, 63, 94, 0.3)' }}>
            <div className="stat-label" style={{ color: 'var(--rose-400)' }}>Removed (-)</div>
            <div className="stat-value" style={{ color: 'var(--rose-400)' }}>-{comparisonResult.removed_count}</div>
            <div className="stat-subtext">No longer observed in current scan</div>
          </div>

          <div className="stat-card" style={{ borderColor: 'rgba(250, 204, 21, 0.3)' }}>
            <div className="stat-label" style={{ color: '#facc15' }}>Modified (~)</div>
            <div className="stat-value" style={{ color: '#facc15' }}>~{comparisonResult.modified_count}</div>
            <div className="stat-subtext">Tracked property mutations</div>
          </div>

          <div className="stat-card">
            <div className="stat-label">Scan Comparison Attribution</div>
            <div className="stat-value" style={{ color: 'var(--cyan-400)', fontSize: '1.15rem' }}>
              Run #{comparisonResult.baseline_scan_run_number || 1} → #{comparisonResult.current_scan_run_number || 2}
            </div>
            <div className="stat-subtext">Sequential baseline diff</div>
          </div>
        </div>
      )}

      {/* Filters & Search */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '240px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '300px' }}>
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search entity key, description..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={15} color="var(--text-muted)" />
              <select
                className="form-input"
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value)}
                style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
              >
                <option value="ALL">All Change Types</option>
                <option value="ADDED">Added (+)</option>
                <option value="REMOVED">Removed (-)</option>
                <option value="MODIFIED">Modified (~)</option>
              </select>
            </div>

            <select
              className="form-input"
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
            >
              <option value="ALL">All Categories</option>
              <option value="subdomain">Subdomain</option>
              <option value="dns_record">DNS Record</option>
              <option value="ip_observation">IP Observation</option>
              <option value="service_exposure">Service Exposure</option>
              <option value="technology">Technology</option>
              <option value="vulnerability">Vulnerability</option>
              <option value="certificate">Certificate</option>
              <option value="asset_relationship">Relationship</option>
              <option value="finding">Finding</option>
            </select>
          </div>
        </div>
      </div>

      {/* Changes Split Workspace */}
      {changes.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1.1fr)', gap: '1.25rem', alignItems: 'start' }}>

          {/* Left: Change Records List */}
          <div className="glass-panel" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                Observed Change Records ({filteredChanges.length})
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Click record to inspect state diff
              </span>
            </div>

            <div style={{ maxHeight: '560px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {filteredChanges.map(change => {
                const isSelected = selectedChange?.id === change.id;
                const typeBadge =
                  change.change_type === 'ADDED' ? { bg: 'rgba(16, 185, 129, 0.2)', border: 'rgba(16, 185, 129, 0.4)', color: 'var(--emerald-400)', label: '+ ADDED' } :
                  change.change_type === 'REMOVED' ? { bg: 'rgba(244, 63, 94, 0.2)', border: 'rgba(244, 63, 94, 0.4)', color: 'var(--rose-400)', label: '- REMOVED' } :
                  { bg: 'rgba(250, 204, 21, 0.2)', border: 'rgba(250, 204, 21, 0.4)', color: '#facc15', label: '~ MODIFIED' };

                return (
                  <div
                    key={change.id}
                    onClick={() => onSelectChange(change)}
                    style={{
                      padding: '0.85rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(6, 182, 212, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                      border: `1px solid ${isSelected ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.45rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span
                          className="badge"
                          style={{
                            fontSize: '0.65rem',
                            background: typeBadge.bg,
                            border: `1px solid ${typeBadge.border}`,
                            color: typeBadge.color,
                            fontWeight: 700,
                          }}
                        >
                          {typeBadge.label}
                        </span>
                        <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                          {change.category}
                        </span>
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        {new Date(change.detected_at).toLocaleTimeString()}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {change.description || change.entity_key}
                    </div>

                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {change.entity_key}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected Change Inspector */}
          <div className="glass-panel" style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.85rem' }}>
              <History size={18} color="var(--cyan-400)" />
              <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Change Record & Diff Inspector
              </h4>
            </div>

            {selectedChange ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>ENTITY KEY</div>
                  <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)', wordBreak: 'break-all', marginTop: '0.2rem' }}>
                    {selectedChange.entity_key}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>DESCRIPTION</div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.45, background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                    {selectedChange.description}
                  </p>
                </div>

                {/* Old vs New JSON Diff View */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--rose-400)', fontWeight: 700, marginBottom: '0.35rem' }}>
                      BASELINE STATE (OLD)
                    </div>
                    <pre
                      style={{
                        background: 'rgba(0, 0, 0, 0.45)',
                        border: '1px solid rgba(244, 63, 94, 0.25)',
                        padding: '0.75rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '240px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {selectedChange.old_value ? JSON.stringify(selectedChange.old_value, null, 2) : 'null (Newly Added)'}
                    </pre>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--emerald-400)', fontWeight: 700, marginBottom: '0.35rem' }}>
                      CURRENT STATE (NEW)
                    </div>
                    <pre
                      style={{
                        background: 'rgba(0, 0, 0, 0.45)',
                        border: '1px solid rgba(16, 185, 129, 0.25)',
                        padding: '0.75rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '240px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {selectedChange.new_value ? JSON.stringify(selectedChange.new_value, null, 2) : 'null (Unobserved in current completed scan)'}
                    </pre>
                  </div>
                </div>

                {/* Evidence Hash */}
                {selectedChange.evidence_hash && (
                  <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.75rem' }}>
                    <div style={{ color: 'var(--text-muted)', marginBottom: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Hash size={13} color="var(--cyan-400)" />
                      <span>Evidence Provenance Hash (SHA-256)</span>
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                      {selectedChange.evidence_hash}
                    </span>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '3.5rem 1rem' }}>
                Select a change record from the list to inspect state diffs and evidence hashes.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <EmptyState
            title="No Attack Surface Changes Detected"
            description="No changes have been computed yet between the selected scan runs. Click Compare Scan Runs to detect added, removed, or modified attack surface elements."
            icon={GitCompare}
            actionLabel="Compare Scan Runs"
            onAction={onCompareScans}
          />
        </div>
      )}
    </div>
  );
};
