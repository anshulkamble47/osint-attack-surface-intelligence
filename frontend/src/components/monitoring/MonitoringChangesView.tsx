import React, { useState } from 'react';
import {
  History,
  GitCompare,
  Filter,
  Search,
  Info,
  Hash,
  PlusCircle,
  MinusCircle,
  RefreshCw,
  Layers,
  Clock,
  Camera,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { ChangeRecordResponse, ComparisonSummaryResponse, SnapshotSummaryResponse } from '../../types/api';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';

interface MonitoringChangesViewProps {
  comparisonResult: ComparisonSummaryResponse | null;
  changes: ChangeRecordResponse[];
  snapshots: SnapshotSummaryResponse[];
  onCompareSnapshots: () => void;
  onCaptureSnapshot: () => void;
  loading: boolean;
  capturingSnapshot: boolean;
  error: string | null;
  baselineSnapshotId: string;
  onChangeBaselineSnapshotId: (id: string) => void;
  currentSnapshotId: string;
  onChangeCurrentSnapshotId: (id: string) => void;
  selectedChange: ChangeRecordResponse | null;
  onSelectChange: (change: ChangeRecordResponse) => void;
}

export const MonitoringChangesView: React.FC<MonitoringChangesViewProps> = ({
  comparisonResult,
  changes,
  snapshots,
  onCompareSnapshots,
  onCaptureSnapshot,
  loading,
  capturingSnapshot,
  error,
  baselineSnapshotId,
  onChangeBaselineSnapshotId,
  currentSnapshotId,
  onChangeCurrentSnapshotId,
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

  const isSingleBaseline = snapshots.length === 1 || (comparisonResult && comparisonResult.message && comparisonResult.message.includes('Baseline Established'));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & Snapshot Management Controls */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
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
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Attack Surface Monitoring & Change Detection</h2>
              <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>Assessment Snapshots</span>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0, maxWidth: '780px' }}>
              Deterministic point-in-time diffing between complete attack surface assessments. Individual module operations (CT discovery, DNS probe, IP enrichment, CVE correlation) are strictly isolated and only coherent complete snapshots are compared.
            </p>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <button
              onClick={onCaptureSnapshot}
              disabled={capturingSnapshot}
              className="btn btn-secondary"
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              title="Capture a point-in-time Complete Assessment Snapshot of the current attack surface"
            >
              <Camera size={15} className={capturingSnapshot ? 'spin' : ''} />
              <span>{capturingSnapshot ? 'Capturing Snapshot...' : 'Capture Snapshot'}</span>
            </button>

            <button
              onClick={onCompareSnapshots}
              disabled={loading || snapshots.length === 0}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #0284c7, #06b6d4)', border: 'none', padding: '0.45rem 0.95rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <GitCompare size={15} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Diffing Snapshots...' : 'Compare Snapshots'}</span>
            </button>
          </div>
        </div>

        {/* Snapshot Selector Strip */}
        <div style={{
          marginTop: '1rem',
          padding: '0.85rem 1rem',
          background: 'rgba(15, 23, 42, 0.65)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1rem',
          alignItems: 'center'
        }}>
          {/* Baseline Snapshot Selection */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Baseline Snapshot
            </label>
            <select
              className="form-input"
              value={baselineSnapshotId}
              onChange={e => onChangeBaselineSnapshotId(e.target.value)}
              style={{ width: '100%', padding: '0.4rem 0.65rem', fontSize: '0.8rem' }}
            >
              <option value="">Auto-Resolve Previous Completed Snapshot</option>
              {snapshots.map(s => (
                <option key={s.id} value={s.id}>
                  Assessment #{s.run_number} ({new Date(s.started_at).toLocaleString()}) — Complete Attack Surface
                </option>
              ))}
            </select>
          </div>

          {/* Current Snapshot Selection */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Current Snapshot
            </label>
            <select
              className="form-input"
              value={currentSnapshotId}
              onChange={e => onChangeCurrentSnapshotId(e.target.value)}
              style={{ width: '100%', padding: '0.4rem 0.65rem', fontSize: '0.8rem' }}
            >
              <option value="">Auto-Resolve Latest Completed Snapshot</option>
              {snapshots.map(s => (
                <option key={s.id} value={s.id}>
                  Assessment #{s.run_number} ({new Date(s.started_at).toLocaleString()}) — Complete Attack Surface
                </option>
              ))}
            </select>
          </div>

          {/* Snapshot Coverage Indicator */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Eligibility & Scope
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--emerald-400)' }}>
              <ShieldCheck size={16} />
              <span>{snapshots.length} Complete {snapshots.length === 1 ? 'Snapshot' : 'Snapshots'} Eligible for Diffing</span>
            </div>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '0.85rem', padding: '0.65rem 0.85rem', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* First Snapshot / Baseline Established Banner */}
        {isSingleBaseline && (
          <div style={{
            background: 'rgba(6, 182, 212, 0.12)',
            border: '1px solid rgba(6, 182, 212, 0.35)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
            marginTop: '0.85rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.75rem',
            fontSize: '0.82rem',
            color: 'var(--text-primary)',
            lineHeight: 1.5
          }}>
            <CheckCircle2 size={18} color="var(--cyan-400)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ color: 'var(--cyan-400)', fontSize: '0.88rem' }}>Baseline Established — No Prior Snapshot for Diffing</strong>
              <div style={{ color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                The current completed assessment establishes the baseline attack surface. Changes (Added, Removed, Modified) will appear after a subsequent completed assessment is executed and compared.
              </div>
            </div>
          </div>
        )}

        {/* Change Semantics Notice */}
        <div style={{
          background: 'rgba(30, 41, 59, 0.6)',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: '8px',
          padding: '0.65rem 0.85rem',
          marginTop: '0.85rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.6rem',
          fontSize: '0.78rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.45
        }}>
          <Info size={16} color="var(--cyan-400)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong style={{ color: 'var(--text-primary)' }}>Deterministic Differential Semantics: </strong>
            <strong style={{ color: 'var(--emerald-400)' }}>ADDED:</strong> Previously absent, newly observed in current snapshot. •
            <strong style={{ color: 'var(--rose-400)' }}> REMOVED:</strong> Observed in baseline snapshot, absent in current snapshot (passive absence does not prove physical deletion). •
            <strong style={{ color: '#facc15' }}> MODIFIED:</strong> Present in both snapshots with tracked observable properties changed.
          </div>
        </div>
      </div>

      {/* Compact Metrics Strip */}
      {comparisonResult ? (
        <div className="compact-stats-grid">
          <CompactStatCard
            icon={Layers}
            label="Total Changes"
            value={comparisonResult.total_changes}
            subtext="Across compared snapshots"
            color="neutral"
          />
          <CompactStatCard
            icon={PlusCircle}
            label="Added Elements"
            value={`+${comparisonResult.added_count}`}
            subtext="Newly observed surface"
            color="emerald"
          />
          <CompactStatCard
            icon={MinusCircle}
            label="Removed Elements"
            value={`-${comparisonResult.removed_count}`}
            subtext="Absent in current snapshot"
            color="rose"
          />
          <CompactStatCard
            icon={RefreshCw}
            label="Modified Elements"
            value={`~${comparisonResult.modified_count}`}
            subtext="Property mutations"
            color="amber"
          />
          <CompactStatCard
            icon={Clock}
            label="Snapshot Attribution"
            value={`#${comparisonResult.baseline_scan_run_number || 1} → #${comparisonResult.current_scan_run_number || (snapshots.length >= 2 ? snapshots[snapshots.length - 1].run_number : 1)}`}
            subtext="Point-in-time diffing"
            color="cyan"
          />
        </div>
      ) : (
        <div className="compact-stats-grid">
          <CompactStatCard
            icon={Layers}
            label="Total Changes"
            value={0}
            subtext="Run snapshot comparison"
            color="neutral"
          />
          <CompactStatCard
            icon={PlusCircle}
            label="Added Elements"
            value={0}
            subtext="Newly observed surface"
            color="emerald"
          />
          <CompactStatCard
            icon={MinusCircle}
            label="Removed Elements"
            value={0}
            subtext="Absent in current snapshot"
            color="rose"
          />
          <CompactStatCard
            icon={RefreshCw}
            label="Modified Elements"
            value={0}
            subtext="Property mutations"
            color="amber"
          />
        </div>
      )}

      {/* Filters & Search */}
      {changes.length > 0 && (
        <div className="glass-panel" style={{ padding: '0.65rem 1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.6rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flex: 1, minWidth: '240px', flexWrap: 'wrap' }}>
              <div style={{ position: 'relative', width: '100%', maxWidth: '260px' }}>
                <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  className="form-input"
                  placeholder="Search entity key, description..."
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  style={{ paddingLeft: '2rem', padding: '0.35rem 0.6rem 0.35rem 2rem', fontSize: '0.78rem' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <Filter size={14} color="var(--text-muted)" />
                <select
                  className="form-input"
                  value={typeFilter}
                  onChange={e => setTypeFilter(e.target.value)}
                  style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
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
                style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
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
      )}

      {/* Changes Split Workspace */}
      {changes.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1.1fr)', gap: '1rem', alignItems: 'start' }}>

          {/* Left: Change Records List */}
          <div className="glass-panel" style={{ padding: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                Observed Change Records ({filteredChanges.length})
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Click record to inspect state diff
              </span>
            </div>

            <div style={{ maxHeight: '540px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
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
                      padding: '0.75rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(6, 182, 212, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                      border: `1px solid ${isSelected ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <span
                          className="badge"
                          style={{
                            fontSize: '0.62rem',
                            background: typeBadge.bg,
                            border: `1px solid ${typeBadge.border}`,
                            color: typeBadge.color,
                            fontWeight: 700,
                          }}
                        >
                          {typeBadge.label}
                        </span>
                        <span className="badge badge-neutral" style={{ fontSize: '0.62rem' }}>
                          {change.category}
                        </span>
                      </div>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                        {new Date(change.detected_at).toLocaleTimeString()}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {change.description || change.entity_key}
                    </div>

                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {change.entity_key}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected Change Inspector */}
          <div className="glass-panel" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.65rem' }}>
              <History size={16} color="var(--cyan-400)" />
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                State Differential & Evidence Inspector
              </h4>
            </div>

            {selectedChange ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>ENTITY KEY</div>
                  <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)', wordBreak: 'break-all', marginTop: '0.15rem' }}>
                    {selectedChange.entity_key}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.2rem' }}>OBSERVATION DESCRIPTION</div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: 1.4, background: 'rgba(0,0,0,0.25)', padding: '0.65rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', margin: 0 }}>
                    {selectedChange.description}
                  </p>
                </div>

                {/* Old vs New JSON Diff View */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem' }}>
                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--rose-400)', fontWeight: 700, marginBottom: '0.25rem' }}>
                      BASELINE STATE (OLD)
                    </div>
                    <pre
                      style={{
                        background: 'rgba(0, 0, 0, 0.45)',
                        border: '1px solid rgba(244, 63, 94, 0.25)',
                        padding: '0.65rem',
                        borderRadius: '6px',
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '220px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        margin: 0
                      }}
                    >
                      {selectedChange.old_value ? JSON.stringify(selectedChange.old_value, null, 2) : 'null (Newly Added)'}
                    </pre>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--emerald-400)', fontWeight: 700, marginBottom: '0.25rem' }}>
                      CURRENT STATE (NEW)
                    </div>
                    <pre
                      style={{
                        background: 'rgba(0, 0, 0, 0.45)',
                        border: '1px solid rgba(16, 185, 129, 0.25)',
                        padding: '0.65rem',
                        borderRadius: '6px',
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '220px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        margin: 0
                      }}
                    >
                      {selectedChange.new_value ? JSON.stringify(selectedChange.new_value, null, 2) : 'null (Unobserved in current completed snapshot)'}
                    </pre>
                  </div>
                </div>

                {/* Evidence Hash */}
                {selectedChange.evidence_hash && (
                  <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '0.55rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.72rem' }}>
                    <div style={{ color: 'var(--text-muted)', marginBottom: '0.15rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Hash size={12} color="var(--cyan-400)" />
                      <span>Evidence Provenance Hash (SHA-256)</span>
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                      {selectedChange.evidence_hash}
                    </span>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', padding: '3rem 1rem' }}>
                Select a change record from the list to inspect state diffs and evidence hashes.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '2.5rem 1.5rem', textAlign: 'center' }}>
          {snapshots.length === 0 ? (
            <EmptyState
              title="No Assessment Snapshots Captured"
              description="Capture a point-in-time Complete Assessment Snapshot to establish an immutable baseline of your attack surface."
              icon={Camera}
              actionLabel="Capture Baseline Snapshot"
              onAction={onCaptureSnapshot}
            />
          ) : isSingleBaseline ? (
            <EmptyState
              title="Baseline Established — No Prior Snapshot for Diffing"
              description="Assessment Snapshot #1 establishes the baseline attack surface. Capture a second assessment snapshot after performing updates to detect additions, removals, and modifications."
              icon={Camera}
              actionLabel="Capture Second Snapshot"
              onAction={onCaptureSnapshot}
            />
          ) : (
            <EmptyState
              title="Compare Attack Surface Snapshots"
              description="Select eligible assessment snapshots above and click 'Compare Snapshots' to compute deterministic differential changes."
              icon={GitCompare}
              actionLabel="Compare Snapshots"
              onAction={onCompareSnapshots}
            />
          )}
        </div>
      )}
    </div>
  );
};

export default MonitoringChangesView;
