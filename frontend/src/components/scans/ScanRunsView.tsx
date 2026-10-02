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
  Globe
} from 'lucide-react';
import { InvestigationResponse, ScanRunResponse } from '../../types/api';
import { StatusBadge } from '../common/StatusBadge';
import { EmptyState } from '../common/EmptyState';

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Investigation Metadata */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(56, 189, 248, 0.15)',
                color: 'var(--cyan-400)',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <History size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Investigation & ScanRun History</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Detailed point-in-time scan execution timeline, investigation parameters, and modular pipeline execution triggers.
            </p>
          </div>

          <button
            onClick={onRefreshScans}
            className="btn btn-secondary"
            style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem' }}
          >
            <Activity size={14} />
            <span>Refresh Scan History</span>
          </button>
        </div>

        {/* Investigation Details Card */}
        <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1.25rem', marginTop: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--cyan-400)', letterSpacing: '0.04em', marginBottom: '0.75rem' }}>
            INVESTIGATION SCOPE & ATTRIBUTES
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', fontSize: '0.82rem' }}>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Investigation Title: </span>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.15rem' }}>{investigation.title}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Target Domain: </span>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--cyan-400)', marginTop: '0.15rem' }}>{investigation.target_domain}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Organization: </span>
              <div style={{ color: 'var(--text-primary)', marginTop: '0.15rem' }}>{investigation.scan_options?.organization || 'Not Specified'}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Reference Code: </span>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>{investigation.reference_code}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Investigation UUID: </span>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.15rem', wordBreak: 'break-all' }}>{investigation.id}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Created Date: </span>
              <div style={{ color: 'var(--text-primary)', marginTop: '0.15rem' }}>{new Date(investigation.created_at).toLocaleString()}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Manual Pipeline Execution Station */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
          <Zap size={16} color="var(--cyan-400)" />
          <span>On-Demand Intelligence Pipeline Triggers</span>
        </h3>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
          Execute modular OSINT discovery and correlation stages against target <strong>{investigation.target_domain}</strong>.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
          <button
            onClick={onRunCT}
            disabled={runningCT}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.65rem 1rem' }}
          >
            <Search size={15} className={runningCT ? 'spin' : ''} />
            <span>{runningCT ? 'Scanning CT...' : '1. Discover CT'}</span>
          </button>

          <button
            onClick={onRunResolve}
            disabled={runningResolve}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.65rem 1rem' }}
          >
            <Radio size={15} className={runningResolve ? 'spin' : ''} />
            <span>{runningResolve ? 'Probing DNS...' : '2. DNS & Reachability'}</span>
          </button>

          <button
            onClick={onRunIPEnrich}
            disabled={runningIPEnrich}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.65rem 1rem' }}
          >
            <Globe size={15} className={runningIPEnrich ? 'spin' : ''} />
            <span>{runningIPEnrich ? 'Enriching IP, ASN & RDAP...' : '3. IP / ASN / RDAP'}</span>
          </button>

          <button
            onClick={onRunFingerprint}
            disabled={runningFingerprint}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.65rem 1rem' }}
          >
            <Cpu size={15} className={runningFingerprint ? 'spin' : ''} />
            <span>{runningFingerprint ? 'Fingerprinting...' : '4. Tech & Headers'}</span>
          </button>

          <button
            onClick={onRunVulnCorrelate}
            disabled={runningVulnCorrelate}
            className="btn btn-secondary"
            style={{ justifyContent: 'center', padding: '0.65rem 1rem' }}
          >
            <Flame size={15} className={runningVulnCorrelate ? 'spin' : ''} />
            <span>{runningVulnCorrelate ? 'Correlating...' : '5. Correlate CVEs'}</span>
          </button>

          <button
            onClick={onRunFindings}
            disabled={runningFindings}
            className="btn btn-primary"
            style={{ justifyContent: 'center', padding: '0.65rem 1rem', background: 'linear-gradient(135deg, #e11d48, #f43f5e)', border: 'none' }}
          >
            <Zap size={15} className={runningFindings ? 'spin' : ''} />
            <span>{runningFindings ? 'Assessing Risk...' : '6. Generate Findings'}</span>
          </button>
        </div>
      </div>

      {/* Scan Runs List and Inspector */}
      {scanRuns.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1.1fr)', gap: '1.25rem', alignItems: 'start' }}>

          {/* Left: ScanRuns Table */}
          <div className="glass-panel" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                Point-in-Time Scan Runs ({scanRuns.length})
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Click scan run to inspect execution state
              </span>
            </div>

            <div style={{ maxHeight: '480px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {scanRuns.map(scan => {
                const isSelected = selectedScan?.id === scan.id;

                return (
                  <div
                    key={scan.id}
                    onClick={() => setSelectedScan(scan)}
                    style={{
                      padding: '0.85rem',
                      borderRadius: '8px',
                      background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                      border: `1px solid ${isSelected ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.45rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                          Run #{scan.run_number}
                        </span>
                        <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                          Assets: {scan.total_discovered_assets}
                        </span>
                      </div>
                      <StatusBadge status={scan.status} />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                      <span>Duration: {calculateDuration(scan.started_at, scan.completed_at)}</span>
                    </div>

                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      ID: {scan.id}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected ScanRun Inspector */}
          <div className="glass-panel" style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.85rem' }}>
              <Clock size={18} color="var(--cyan-400)" />
              <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                ScanRun Point-in-Time Inspector
              </h4>
            </div>

            {selectedScan ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                      Scan Run #{selectedScan.run_number}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {selectedScan.id}
                    </div>
                  </div>
                  <StatusBadge status={selectedScan.status} />
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Target Domain Scope: </span>
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
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Scan Execution Summary</div>
                    <pre
                      style={{
                        background: 'rgba(0,0,0,0.4)',
                        padding: '0.75rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '200px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        border: '1px solid var(--border-subtle)'
                      }}
                    >
                      {JSON.stringify(selectedScan.summary, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '3.5rem 1rem' }}>
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
