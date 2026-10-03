import React, { useState, useEffect } from 'react';
import {
  Network,
  Search,
  Radio,
  Globe2,
  Building,
  Server,
  History,
  CheckCircle2
} from 'lucide-react';
import { DNSRecordSummary, IPAddressSummary, ASNSummary } from '../../types/api';
import { ActionResultInfo } from '../overview/OverviewDashboard';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';

interface DnsInfrastructureViewProps {
  dnsRecords: DNSRecordSummary[];
  ipAddresses: IPAddressSummary[];
  asns: ASNSummary[];
  onRunResolve: () => void;
  onRunIPEnrich: () => void;
  runningResolve: boolean;
  runningIPEnrich: boolean;
  resolveError: string | null;
  ipEnrichError: string | null;
  targetDomain: string;
  actionStatus?: ActionResultInfo | null;
  onDismissStatus?: () => void;
}

export const DnsInfrastructureView: React.FC<DnsInfrastructureViewProps> = ({
  dnsRecords,
  ipAddresses,
  asns,
  onRunResolve,
  onRunIPEnrich,
  runningResolve,
  runningIPEnrich,
  resolveError,
  ipEnrichError,
  targetDomain,
  actionStatus,
  onDismissStatus,
}) => {
  const [activeTab, setActiveTab] = useState<'dns' | 'ips' | 'asns'>('dns');
  const [searchTerm, setSearchTerm] = useState('');
  const [recordTypeFilter, setRecordTypeFilter] = useState('ALL');
  const [dnsViewMode, setDnsViewMode] = useState<'current' | 'previous'>('current');

  // Auto-select "Current Scan" when a scan finishes
  useEffect(() => {
    if (!runningResolve) {
      setDnsViewMode('current');
    }
  }, [runningResolve]);

  const filteredRecords = dnsRecords.filter(r => {
    if (recordTypeFilter !== 'ALL' && r.record_type !== recordTypeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchVal = r.value ? r.value.toLowerCase().includes(term) : false;
      const matchType = r.record_type ? r.record_type.toLowerCase().includes(term) : false;
      const matchResolver = r.resolver ? r.resolver.toLowerCase().includes(term) : false;
      if (!matchVal && !matchType && !matchResolver) return false;
    }
    return true;
  });

  const filteredIPs = ipAddresses.filter(ip => {
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchIp = ip.ip_address.toLowerCase().includes(term);
      const matchOrg = ip.organization ? ip.organization.toLowerCase().includes(term) : false;
      const matchCountry = ip.country ? ip.country.toLowerCase().includes(term) : false;
      const matchRev = ip.reverse_dns ? ip.reverse_dns.toLowerCase().includes(term) : false;
      if (!matchIp && !matchOrg && !matchCountry && !matchRev) return false;
    }
    return true;
  });

  const filteredASNs = asns.filter(asn => {
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchNum = asn.asn_number.toString().includes(term);
      const matchName = asn.name.toLowerCase().includes(term);
      const matchCountry = asn.country ? asn.country.toLowerCase().includes(term) : false;
      if (!matchNum && !matchName && !matchCountry) return false;
    }
    return true;
  });

  const recordTypes = Array.from(new Set(dnsRecords.map(r => r.record_type))).sort();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & Controls Panel */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <div style={{
                background: 'rgba(56, 189, 248, 0.15)',
                color: 'var(--cyan-400)',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Network size={18} />
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>DNS & Infrastructure Intelligence</h2>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Observed DNS records, authoritative nameserver resolutions, IP routing topology, Autonomous Systems (ASNs), and RDAP network allocations.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <button
              onClick={onRunResolve}
              disabled={runningResolve || runningIPEnrich}
              className="btn btn-secondary"
            >
              <Radio size={14} className={runningResolve ? 'spin' : ''} />
              <span>{runningResolve ? 'Probing DNS...' : '2. Resolve DNS'}</span>
            </button>

            <button
              onClick={onRunIPEnrich}
              disabled={runningIPEnrich || runningResolve}
              className="btn btn-primary"
            >
              <Globe2 size={14} className={runningIPEnrich ? 'spin' : ''} />
              <span>{runningIPEnrich ? 'Enriching...' : '3. IP/ASN'}</span>
            </button>
          </div>
        </div>

        {/* Real-Time Action Feedback Banner */}
        {actionStatus && (
          <div
            style={{
              marginTop: '1rem',
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

            {onDismissStatus && actionStatus.type !== 'running' && (
              <button
                onClick={onDismissStatus}
                className="btn btn-secondary"
                style={{ padding: '0.2rem 0.45rem', fontSize: '0.72rem' }}
                title="Dismiss notification"
              >
                &times;
              </button>
            )}
          </div>
        )}

        {(resolveError || ipEnrichError) && (
          <div className="alert alert-danger" style={{ marginTop: '0.75rem', marginBottom: 0 }}>
            {resolveError || ipEnrichError}
          </div>
        )}
      </div>

      {/* Compact Metrics Grid */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Network}
          label="DNS Records"
          value={dnsRecords.length}
          subtext={`Across ${recordTypes.length} record types`}
          color="cyan"
          onClick={() => setActiveTab('dns')}
        />

        <CompactStatCard
          icon={Server}
          label="Public IP Addresses"
          value={ipAddresses.length}
          subtext="Unique routable hosts"
          color="emerald"
          onClick={() => setActiveTab('ips')}
        />

        <CompactStatCard
          icon={Building}
          label="Autonomous Systems"
          value={asns.length}
          subtext="BGP routing origins"
          color="amber"
          onClick={() => setActiveTab('asns')}
        />

        <CompactStatCard
          icon={Globe2}
          label="Target Scope"
          value={targetDomain}
          subtext="Root assessment target"
          color="neutral"
        />
      </div>

      {/* Tabs and DNS Observation Mode Toggle */}
      <div className="glass-panel" style={{ padding: '0.75rem 1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          {/* Sub-View Navigation Tabs */}
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button
              onClick={() => setActiveTab('dns')}
              className={`btn ${activeTab === 'dns' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <Network size={13} />
              <span>DNS Records ({dnsRecords.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('ips')}
              className={`btn ${activeTab === 'ips' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <Server size={13} />
              <span>IP Addresses ({ipAddresses.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('asns')}
              className={`btn ${activeTab === 'asns' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <Building size={13} />
              <span>Autonomous Systems ({asns.length})</span>
            </button>
          </div>

          {/* Current Scan vs Previous Observations Toggle (for DNS tab) */}
          {activeTab === 'dns' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Observation State:</span>
              <div className="segmented-toggle">
                <button
                  className={`segmented-toggle-btn ${dnsViewMode === 'current' ? 'active' : ''}`}
                  onClick={() => setDnsViewMode('current')}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <CheckCircle2 size={12} />
                    Current Scan
                  </span>
                </button>
                <button
                  className={`segmented-toggle-btn ${dnsViewMode === 'previous' ? 'active' : ''}`}
                  onClick={() => setDnsViewMode('previous')}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <History size={12} />
                    Previous Observations
                  </span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Scan in Progress Indicator / Observation Mode Banner */}
        {runningResolve && (
          <div style={{ marginTop: '0.75rem', padding: '0.5rem 0.85rem', borderRadius: '6px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.25)', fontSize: '0.75rem', color: 'var(--cyan-400)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Radio size={13} className="spin" />
            <span>Active DNS scan in progress... Showing existing baseline observations below until the new ScanRun completes.</span>
          </div>
        )}

        {!runningResolve && dnsViewMode === 'previous' && (
          <div style={{ marginTop: '0.75rem', padding: '0.5rem 0.85rem', borderRadius: '6px', background: 'rgba(148, 163, 184, 0.1)', border: '1px solid rgba(148, 163, 184, 0.2)', fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <History size={13} color="var(--amber-400)" />
            <span>Viewing historical baseline DNS observations. Click <strong>Current Scan</strong> to view newly verified results.</span>
          </div>
        )}
      </div>

      {/* Sub-View 1: DNS Records Table */}
      {activeTab === 'dns' && (
        <>
          <div className="glass-panel" style={{ padding: '0.65rem 1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '220px' }}>
                <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
                  <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Filter records..."
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    style={{ width: '100%', paddingLeft: '1.9rem', fontSize: '0.8rem' }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Type:</span>
                  <select
                    className="form-input"
                    value={recordTypeFilter}
                    onChange={e => setRecordTypeFilter(e.target.value)}
                    style={{ fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
                  >
                    <option value="ALL">All Types</option>
                    {recordTypes.map(rt => (
                      <option key={rt} value={rt}>{rt}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Showing <strong>{filteredRecords.length}</strong> of {dnsRecords.length} records
              </div>
            </div>
          </div>

          {filteredRecords.length > 0 ? (
            <div className="glass-panel" style={{ overflow: 'hidden' }}>
              <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Record Type</th>
                      <th>Resolved Value / Target</th>
                      <th>TTL (s)</th>
                      <th>Authoritative Resolver</th>
                      <th>Observed Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRecords.map((r, i) => (
                      <tr key={i}>
                        <td>
                          <span
                            className="badge"
                            style={{
                              fontSize: '0.68rem',
                              fontFamily: 'var(--font-mono)',
                              background:
                                r.record_type === 'A' ? 'rgba(56, 189, 248, 0.15)' :
                                r.record_type === 'AAAA' ? 'rgba(168, 85, 247, 0.15)' :
                                r.record_type === 'MX' ? 'rgba(52, 211, 153, 0.15)' :
                                r.record_type === 'NS' ? 'rgba(251, 191, 36, 0.15)' :
                                'rgba(148, 163, 184, 0.15)',
                              color:
                                r.record_type === 'A' ? 'var(--cyan-400)' :
                                r.record_type === 'AAAA' ? 'var(--purple-400)' :
                                r.record_type === 'MX' ? 'var(--emerald-400)' :
                                r.record_type === 'NS' ? 'var(--amber-400)' :
                                'var(--text-secondary)',
                            }}
                          >
                            {r.record_type}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {r.value}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                            {r.ttl || '—'}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            {r.resolver || 'Default Recursive'}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {r.collected_at ? new Date(r.collected_at).toLocaleString() : 'Recent'}
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
                title={dnsRecords.length === 0 ? "No DNS Records Observed" : "No Matching Records"}
                description={
                  dnsRecords.length === 0
                    ? "Click '2. Resolve DNS' above to actively probe DNS records and reachability for all discovered candidate assets."
                    : "No DNS records matched your search term or record type filter."
                }
                icon={Network}
                actionLabel={dnsRecords.length === 0 ? "2. Resolve DNS" : undefined}
                onAction={dnsRecords.length === 0 ? onRunResolve : undefined}
              />
            </div>
          )}
        </>
      )}

      {/* Sub-View 2: IP Addresses Grid / Table */}
      {activeTab === 'ips' && (
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          {filteredIPs.length > 0 ? (
            <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Type / Version</th>
                    <th>Organization / ISP</th>
                    <th>Country / Geo</th>
                    <th>Reverse DNS (PTR)</th>
                    <th>Associated ASN</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIPs.map((ip, i) => (
                    <tr key={i}>
                      <td>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--cyan-400)' }}>
                          {ip.ip_address}
                        </span>
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                          IPv{ip.ip_version}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 500 }}>{ip.organization || '—'}</span>
                      </td>
                      <td>
                        <span className="badge badge-info" style={{ fontSize: '0.68rem' }}>
                          {ip.country || 'Global'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {ip.reverse_dns || '—'}
                      </td>
                      <td>
                        {ip.asn ? (
                          <span className="badge badge-purple" style={{ fontSize: '0.68rem' }}>
                            AS{ip.asn.asn_number} ({ip.asn.name})
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '2rem' }}>
              <EmptyState
                title={ipAddresses.length === 0 ? "No IP Addresses Enriched Yet" : "No Matching IP Addresses"}
                description={
                  ipAddresses.length === 0
                    ? "Click '3. IP/ASN' above to enrich geolocation, ASN origin, and RDAP network ownership."
                    : "No IP addresses matched your search term."
                }
                icon={Server}
                actionLabel={ipAddresses.length === 0 ? "3. IP/ASN" : undefined}
                onAction={ipAddresses.length === 0 ? onRunIPEnrich : undefined}
              />
            </div>
          )}
        </div>
      )}

      {/* Sub-View 3: Autonomous Systems (ASNs) */}
      {activeTab === 'asns' && (
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          {filteredASNs.length > 0 ? (
            <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ASN Number</th>
                    <th>Autonomous System Name</th>
                    <th>Country / Registry</th>
                    <th>Allocated BGP Prefix</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredASNs.map((asn, i) => (
                    <tr key={i}>
                      <td>
                        <span className="badge badge-purple font-mono" style={{ fontSize: '0.75rem', fontWeight: 700 }}>
                          AS{asn.asn_number}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{asn.name}</span>
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                          {asn.country || 'Global'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--cyan-400)' }}>
                        {asn.allocated_prefix || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '2rem' }}>
              <EmptyState
                title={asns.length === 0 ? "No ASNs Discovered Yet" : "No Matching ASNs"}
                description={
                  asns.length === 0
                    ? "Click '3. IP/ASN' above to perform BGP ASN origin lookup for all resolved public IP addresses."
                    : "No ASNs matched your search term."
                }
                icon={Building}
                actionLabel={asns.length === 0 ? "3. IP/ASN" : undefined}
                onAction={asns.length === 0 ? onRunIPEnrich : undefined}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default DnsInfrastructureView;
