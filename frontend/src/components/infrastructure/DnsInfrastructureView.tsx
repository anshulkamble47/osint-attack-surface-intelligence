import React, { useState } from 'react';
import {
  Network,
  Search,
  Radio,
  Globe2,
  Building
} from 'lucide-react';
import { DNSRecordSummary, IPAddressSummary, ASNSummary } from '../../types/api';
import { ActionResultInfo } from '../overview/OverviewDashboard';
import { EmptyState } from '../common/EmptyState';

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Controls Panel */}
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
                <Network size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>DNS & Infrastructure Intelligence</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Observed DNS records, authoritative nameserver resolutions, IP routing topology, Autonomous Systems (ASNs), and RDAP network allocations.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              onClick={onRunResolve}
              disabled={runningResolve || runningIPEnrich}
              className="btn btn-secondary"
            >
              <Radio size={16} className={runningResolve ? 'spin' : ''} />
              <span>{runningResolve ? 'Probing DNS...' : 'Resolve DNS & Reachability'}</span>
            </button>

            <button
              onClick={onRunIPEnrich}
              disabled={runningIPEnrich || runningResolve}
              className="btn btn-primary"
            >
              <Globe2 size={16} className={runningIPEnrich ? 'spin' : ''} />
              <span>{runningIPEnrich ? 'Enriching IP, ASN & RDAP...' : 'Enrich IP, ASN & RDAP'}</span>
            </button>
          </div>
        </div>

        {/* Real-Time Action Feedback Banner */}
        {actionStatus && (
          <div
            style={{
              marginTop: '1.25rem',
              padding: '0.85rem 1.15rem',
              borderRadius: '8px',
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '0.75rem',
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <span
                className="badge"
                style={{
                  fontSize: '0.7rem',
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
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    {actionStatus.detail}
                  </div>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {actionStatus.type === 'error' && (
                <button
                  className="btn btn-primary"
                  onClick={actionStatus.stageNumber === 2 ? onRunResolve : onRunIPEnrich}
                  style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
                >
                  Retry Action
                </button>
              )}
              {onDismissStatus && actionStatus.type !== 'running' && (
                <button
                  onClick={onDismissStatus}
                  className="btn btn-secondary"
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                  title="Dismiss notification"
                >
                  &times;
                </button>
              )}
            </div>
          </div>
        )}

        {!actionStatus && (resolveError || ipEnrichError) && (
          <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
            {resolveError || ipEnrichError}
          </div>
        )}
      </div>

      {/* Summary Metrics Strip */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Observed DNS Records</div>
          <div className="stat-value">{dnsRecords.length}</div>
          <div className="stat-subtext">Across {recordTypes.length} record types</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Discovered Public IPs</div>
          <div className="stat-value">{ipAddresses.length}</div>
          <div className="stat-subtext">Resolved external endpoints</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Observed Autonomous Systems (ASNs)</div>
          <div className="stat-value">{asns.length}</div>
          <div className="stat-subtext">Network routing prefixes</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Root Target Domain</div>
          <div className="stat-value" style={{ fontSize: '1.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {targetDomain}
          </div>
          <div className="stat-subtext">Authoritative zone</div>
        </div>
      </div>

      {/* Navigation Tabs & Search Toolbar */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => setActiveTab('dns')}
              className={`btn ${activeTab === 'dns' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 1rem', fontSize: '0.85rem' }}
            >
              <Network size={15} />
              <span>DNS Records ({dnsRecords.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('ips')}
              className={`btn ${activeTab === 'ips' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 1rem', fontSize: '0.85rem' }}
            >
              <Globe2 size={15} />
              <span>IP Addresses ({ipAddresses.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('asns')}
              className={`btn ${activeTab === 'asns' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 1rem', fontSize: '0.85rem' }}
            >
              <Building size={15} />
              <span>ASNs & RDAP ({asns.length})</span>
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, maxWidth: '450px', justifyContent: 'flex-end' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Filter infrastructure..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>

            {activeTab === 'dns' && recordTypes.length > 0 && (
              <select
                className="form-input"
                value={recordTypeFilter}
                onChange={e => setRecordTypeFilter(e.target.value)}
                style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
              >
                <option value="ALL">All Types</option>
                {recordTypes.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            )}
          </div>
        </div>
      </div>

      {/* Tab Content Panels */}
      {activeTab === 'dns' && (
        dnsRecords.length > 0 ? (
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Record Type</th>
                    <th>Record Value / Resolution</th>
                    <th>TTL</th>
                    <th>Resolver Source</th>
                    <th>Subdomain ID</th>
                    <th>Collected</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRecords.map(rec => (
                    <tr key={rec.id}>
                      <td>
                        <span className="badge badge-info" style={{ fontSize: '0.75rem', fontWeight: 700 }}>
                          {rec.record_type}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--cyan-400)', wordBreak: 'break-all' }}>
                        {rec.value}
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                        {rec.ttl !== null && rec.ttl !== undefined ? `${rec.ttl}s` : '—'}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {rec.resolver || 'Authoritative DNS'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {rec.subdomain_id ? rec.subdomain_id.substring(0, 8) + '...' : '—'}
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                        {new Date(rec.collected_at).toLocaleTimeString()}
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
              title="No DNS Records Observed"
              description="No DNS resolution data is available for this investigation. Run the DNS resolution probe to enumerate active A, AAAA, CNAME, MX, and TXT records."
              icon={Network}
              actionLabel="Run DNS & Reachability Probe"
              onAction={onRunResolve}
            />
          </div>
        )
      )}

      {activeTab === 'ips' && (
        ipAddresses.length > 0 ? (
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Version</th>
                    <th>Observed Organization / Network</th>
                    <th>ASN Number</th>
                    <th>Country</th>
                    <th>Reverse DNS (PTR)</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIPs.map(ip => (
                    <tr key={ip.id}>
                      <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--emerald-400)' }}>
                        {ip.ip_address}
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                          IPv{ip.ip_version}
                        </span>
                      </td>
                      <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                        {ip.organization || ip.asn?.name || 'Not Enriched / Unallocated'}
                      </td>
                      <td>
                        {ip.asn ? (
                          <span className="badge badge-info font-mono" style={{ fontSize: '0.75rem' }}>
                            AS{ip.asn.asn_number}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>
                      <td>
                        {ip.country ? (
                          <span className="badge badge-neutral" style={{ fontSize: '0.75rem' }}>
                            {ip.country}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {ip.reverse_dns || '—'}
                      </td>
                      <td>
                        <span className={`badge ${ip.is_active ? 'badge-success' : 'badge-neutral'}`} style={{ fontSize: '0.7rem' }}>
                          {ip.is_active ? 'Active' : 'Inactive'}
                        </span>
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
              title="No IP Addresses Enriched"
              description="No enriched IP address observations are recorded yet. Run IP & ASN enrichment to resolve geolocation, BGP routing prefixes, and network attribution."
              icon={Globe2}
              actionLabel="Enrich IP, ASN & RDAP"
              onAction={onRunIPEnrich}
            />
          </div>
        )
      )}

      {activeTab === 'asns' && (
        asns.length > 0 ? (
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ASN Number</th>
                    <th>Autonomous System Name</th>
                    <th>Allocated Routing Prefix</th>
                    <th>Country</th>
                    <th>Associated Observed IPs</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredASNs.map((asn, idx) => (
                    <tr key={idx}>
                      <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                        AS{asn.asn_number}
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {asn.name}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {asn.allocated_prefix || '—'}
                      </td>
                      <td>
                        {asn.country ? (
                          <span className="badge badge-neutral" style={{ fontSize: '0.75rem' }}>
                            {asn.country}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>
                      <td>
                        <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>
                          {asn.ip_count || 1} IPs
                        </span>
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
              title="No Autonomous Systems (ASNs) Observed"
              description="No ASN routing data has been recorded for this investigation. Run IP & ASN enrichment to map IP addresses to their autonomous network providers."
              icon={Building}
              actionLabel="Enrich IP, ASN & RDAP"
              onAction={onRunIPEnrich}
            />
          </div>
        )
      )}
    </div>
  );
};

export default DnsInfrastructureView;
