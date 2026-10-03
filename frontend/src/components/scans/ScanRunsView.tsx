import React, { useState } from 'react';
import {
  History,
  Activity,
  Clock,
  Search,
  Radio,
  Cpu,
  Flame,
  Zap,
  Globe,
  CheckCircle2,
  Layers,
  Target
} from 'lucide-react';
import { InvestigationResponse, ScanRunResponse } from '../../types/api';
import { StatusBadge } from '../common/StatusBadge';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';

interface ScanRunsViewProps {
  investigation: InvestigationResponse;
  scanRuns: ScanRunResponse[];
  onRefreshScans: () => void;
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
}

export const ScanRunsView: React.FC<ScanRunsViewProps> = ({
  investigation,
  scanRuns,
  onRefreshScans,
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
}) => {
  const [selectedScan, setSelectedScan] = useState<ScanRunResponse | null>(scanRuns.length > 0 ? scanRuns[0] : null);

  const calculateDuration = (startStr: string, endStr?: string | null) => {
    if (!endStr) return 'In Progress';
    const start = new Date(startStr).getTime();
    const end = new Date(endStr).getTime();
    const sec = Math.max(0, Math.round((end - start) / 1000));
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    return `${min}m ${sec % 60}s`;
  };

  const completedCount = scanRuns.filter(s => s.status === 'completed' || s.status === 'COMPLETED').length;
  const latestRun = scanRuns.length > 0 ? scanRuns[0] : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & Investigation Scope */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.85rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
              <div style={{
                background: 'rgba(56, 189, 248, 0.15)',
                color: 'var(--cyan-400)',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <History size={18} />
              </div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Investigation & ScanRun History</h2>
              <span className="badge badge-info" style={{ fontSize: '0.68rem' }}>Scan Timeline</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
              Point-in-time scan execution timeline, scan parameter provenance, and modular pipeline triggers.
            </p>
          </div>

          <button
            onClick={onRefreshScans}
            className="btn btn-secondary"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }}
          >
            <Activity size={13} />
            <span>Refresh Scan History</span>
          </button>
        </div>

        {/* Investigation Details Pill */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          marginTop: '0.85rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '0.75rem',
          fontSize: '0.78rem'
        }}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Investigation Title: </span>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>{investigation.title}</div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Target Scope Domain: </span>
            <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--cyan-400)', marginTop: '0.1rem' }}>{investigation.target_domain}</div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Organization: </span>
            <div style={{ color: 'var(--text-primary)', marginTop: '0.1rem' }}>{investigation.scan_options?.organization || 'Not Specified'}</div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Reference Code: </span>
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginTop: '0.1rem' }}>{investigation.reference_code}</div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Created At: </span>
            <div style={{ color: 'var(--text-primary)', marginTop: '0.1rem' }}>{new Date(investigation.created_at).toLocaleString()}</div>
          </div>
        </div>
      </div>

      {/* Compact Metrics Strip */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Layers}
          label="Total Scan Runs"
          value={scanRuns.length}
          subtext="Executed pipeline runs"
          color="cyan"
        />
        <CompactStatCard
          icon={CheckCircle2}
          label="Completed Runs"
          value={completedCount}
          subtext="Successful execution"
          color="emerald"
        />
        <CompactStatCard
          icon={Target}
          label="Target Scope"
          value={investigation.target_domain}
          subtext="Assessment apex domain"
          color="purple"
        />
        <CompactStatCard
          icon={Clock}
          label="Latest Execution"
          value={latestRun ? `Run #${latestRun.run_number}` : 'None'}
          subtext={latestRun ? new Date(latestRun.started_at).toLocaleTimeString() : 'No scan runs'}
          color="amber"
        />
      </div>

      {/* Manual Pipeline Execution Station */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <h3 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Zap size={14} color="var(--cyan-400)" />
          <span>Modular OSINT Intelligence Pipeline Triggers</span>
        </h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
          Execute discrete discovery, enrichment, correlation, and risk assessment stages on target <strong>{investigation.target_domain}</strong>.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.5rem' }}>
          <button
            onClick={onRunCT}
            disabled={runningCT}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.5rem 0.75rem', fontSize: '0.78rem' }}
          >
            <Search size={13} className={runningCT ? 'spin' : ''} />
            <span>{runningCT ? 'Scanning CT...' : '1. Discover CT'}</span>
          </button>

          <button
            onClick={onRunResolve}
            disabled={runningResolve}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.5rem 0.75rem', fontSize: '0.78rem' }}
          >
            <Radio size={13} className={runningResolve ? 'spin' : ''} />
            <span>{runningResolve ? 'Probing DNS...' : '2. Resolve DNS'}</span>
          </button>

          <button
            onClick={onRunIPEnrich}
            disabled={runningIPEnrich}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.5rem 0.75rem', fontSize: '0.78rem' }}
          >
            <Globe size={13} className={runningIPEnrich ? 'spin' : ''} />
            <span>{runningIPEnrich ? 'Enriching IP...' : '3. IP/ASN/RDAP'}</span>
          </button>

          <button
            onClick={onRunFingerprint}
            disabled={runningFingerprint}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.5rem 0.75rem', fontSize: '0.78rem' }}
          >
            <Cpu size={13} className={runningFingerprint ? 'spin' : ''} />
            <span>{runningFingerprint ? 'Fingerprinting...' : '4. Tech & Headers'}</span>
          </button>

          <button
            onClick={onRunVulnCorrelate}
            disabled={runningVulnCorrelate}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.5rem 0.75rem', fontSize: '0.78rem' }}
          >
            <Flame size={13} className={runningVulnCorrelate ? 'spin' : ''} />
            <span>{runningVulnCorrelate ? 'Correlating...' : '5. Correlate CVEs'}</span>
          </button>

          <button
            onClick={onRunFindings}
            disabled={runningFindings}
            className="btn btn-primary"
            style={{ justifyContent: 'center', padding: '0.5rem 0.75rem', fontSize: '0.78rem', background: 'linear-gradient(135deg, #e11d48, #f43f5e)', border: 'none' }}
          >
            <Zap size={13} className={runningFindings ? 'spin' : ''} />
            <span>{runningFindings ? 'Assessing Risk...' : '6. Generate Findings'}</span>
          </button>
        </div>
      </div>

      {/* Scan Runs List and Inspector */}
      {scanRuns.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1.1fr)', gap: '1rem', alignItems: 'start' }}>

          {/* Left: ScanRuns Table */}
          <div className="glass-panel" style={{ padding: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                Point-in-Time Scan Runs ({scanRuns.length})
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Click scan run to inspect execution state
              </span>
            </div>

            <div style={{ maxHeight: '480px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
              {scanRuns.map(scan => {
                const isSelected = selectedScan?.id === scan.id;

                return (
                  <div
                    key={scan.id}
                    onClick={() => setSelectedScan(scan)}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                      border: `1px solid ${isSelected ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                          Run #{scan.run_number}
                        </span>
                        <span className="badge badge-neutral" style={{ fontSize: '0.62rem' }}>
                          Assets: {scan.total_discovered_assets}
                        </span>
                      </div>
                      <StatusBadge status={scan.status} />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                      <span>Duration: {calculateDuration(scan.started_at, scan.completed_at)}</span>
                    </div>

                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      ID: {scan.id}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected ScanRun Inspector */}
          <div className="glass-panel" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.65rem' }}>
              <Clock size={16} color="var(--cyan-400)" />
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                ScanRun Point-in-Time Inspector
              </h4>
            </div>

            {selectedScan ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                      Scan Run #{selectedScan.run_number}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {selectedScan.id}
                    </div>
                  </div>
                  <StatusBadge status={selectedScan.status} />
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.78rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Target Scope Domain: </span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>{investigation.target_domain}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Discovered Assets Count: </span>
                    <strong style={{ color: 'var(--text-primary)' }}>{selectedScan.total_discovered_assets}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Resolving Assets Count: </span>
                    <strong style={{ color: 'var(--emerald-400)' }}>{selectedScan.total_resolving_assets}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Synthesized Findings: </span>
                    <strong style={{ color: 'var(--rose-400)' }}>{selectedScan.total_findings}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Started At: </span>
                    <span style={{ color: 'var(--text-primary)' }}>{new Date(selectedScan.started_at).toLocaleString()}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Completed At: </span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedScan.completed_at ? new Date(selectedScan.completed_at).toLocaleString() : 'In Progress'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Execution Duration: </span>
                    <span style={{ color: 'var(--emerald-400)', fontWeight: 600 }}>{calculateDuration(selectedScan.started_at, selectedScan.completed_at)}</span>
                  </div>
                </div>

                {selectedScan.summary && Object.keys(selectedScan.summary).length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Scan Execution Summary Telemetry</div>
                    <pre
                      style={{
                        background: 'rgba(0,0,0,0.4)',
                        padding: '0.65rem',
                        borderRadius: '6px',
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '180px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        border: '1px solid var(--border-subtle)',
                        margin: 0
                      }}
                    >
                      {JSON.stringify(selectedScan.summary, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', padding: '3rem 1rem' }}>
                Select a scan run to view execution telemetry.
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <EmptyState
            title="No Scan Runs Recorded"
            description="No point-in-time scan runs have been captured yet for this investigation. Use the pipeline action buttons above to execute initial reconnaissance."
            icon={History}
            actionLabel="Discover Certificate Transparency"
            onAction={onRunCT}
          />
        </div>
      )}
    </div>
  );
};

export default ScanRunsView;
