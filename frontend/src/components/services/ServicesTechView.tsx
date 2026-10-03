import React, { useState, useMemo } from 'react';
import {
  Cpu,
  Search,
  ShieldCheck,
  Lock,
  Code2,
  Server,
  Info
} from 'lucide-react';
import {
  TechnologySummary,
  ServiceExposureSummary,
  SecurityHeadersSummary,
  TLSMetadataSummary,
} from '../../types/api';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';

interface ServicesTechViewProps {
  services: ServiceExposureSummary[];
  technologies: TechnologySummary[];
  securityHeaders: SecurityHeadersSummary[];
  tlsMetadata: TLSMetadataSummary[];
  onRunFingerprint: () => void;
  loading: boolean;
  error: string | null;
  targetDomain: string;
}

export const ServicesTechView: React.FC<ServicesTechViewProps> = ({
  services,
  technologies,
  securityHeaders,
  tlsMetadata,
  onRunFingerprint,
  loading,
  error,
  targetDomain,
}) => {
  const [activeTab, setActiveTab] = useState<'services' | 'tech' | 'headers' | 'tls'>(() => {
    return technologies.length > 0 ? 'tech' : 'services';
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [techCategoryFilter, setTechCategoryFilter] = useState<string>('ALL');

  const categories = useMemo(() => {
    return Array.from(new Set(technologies.map(t => t.category))).sort();
  }, [technologies]);

  const filteredTech = useMemo(() => {
    return technologies.filter(t => {
      if (techCategoryFilter !== 'ALL' && t.category.toLowerCase() !== techCategoryFilter.toLowerCase()) {
        return false;
      }
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          t.name.toLowerCase().includes(term) ||
          (t.version || '').toLowerCase().includes(term) ||
          (t.cpe || '').toLowerCase().includes(term) ||
          (t.asset_value || '').toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [technologies, techCategoryFilter, searchTerm]);

  const filteredServices = useMemo(() => {
    return services.filter(s => {
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          s.service_name.toLowerCase().includes(term) ||
          (s.page_title || '').toLowerCase().includes(term) ||
          String(s.port).includes(term)
        );
      }
      return true;
    });
  }, [services, searchTerm]);

  const filteredTLS = useMemo(() => {
    return tlsMetadata.filter(t => {
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          t.url.toLowerCase().includes(term) ||
          (t.tls_version || '').toLowerCase().includes(term) ||
          (t.cert_subject || '').toLowerCase().includes(term) ||
          (t.cert_issuer || '').toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [tlsMetadata, searchTerm]);

  const httpCount = services.filter(s => s.port === 80 || s.port === 443 || s.service_name.toLowerCase().includes('http')).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & Action */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <div style={{
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#fbbf24',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Cpu size={18} />
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Services & Technology Fingerprinting</h2>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Web server banners, exposed network ports, HTTP security headers, and TLS configurations for <strong>{targetDomain}</strong>.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onRunFingerprint}
              disabled={loading}
              className="btn btn-primary"
            >
              <Cpu size={14} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Fingerprinting...' : '4. Tech/Headers'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '0.75rem', marginBottom: 0 }}>
            {error}
          </div>
        )}
      </div>

      {/* Compact Summary Metrics Strip */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Server}
          label="Exposed Services"
          value={services.length}
          subtext={`${httpCount} HTTP/HTTPS endpoints`}
          color="cyan"
          onClick={() => setActiveTab('services')}
        />

        <CompactStatCard
          icon={Code2}
          label="Software Technologies"
          value={technologies.length}
          subtext={technologies.length === 0 ? 'No version disclosures observed' : 'Fingerprinted components'}
          color={technologies.length > 0 ? 'emerald' : 'neutral'}
          onClick={() => setActiveTab('tech')}
        />

        <CompactStatCard
          icon={ShieldCheck}
          label="Security Headers"
          value={securityHeaders.length}
          subtext="Evaluated configurations"
          color="amber"
          onClick={() => setActiveTab('headers')}
        />

        <CompactStatCard
          icon={Lock}
          label="TLS Endpoints"
          value={tlsMetadata.length}
          subtext="Cryptographic suites analyzed"
          color="purple"
          onClick={() => setActiveTab('tls')}
        />
      </div>

      {/* Contextual Clarification Banner when services exist but 0 technologies detected */}
      {services.length > 0 && technologies.length === 0 && (
        <div style={{
          background: 'rgba(15, 23, 42, 0.65)',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)'
        }}>
          <Info size={16} color="var(--cyan-400)" style={{ flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--text-primary)' }}>Passive Discovery Scope: </strong>
            {services.length} exposed network services are active and reachable.
            Probed web servers returned generic HTTP response headers (e.g. CDN proxies, custom edge gateways) or omitted explicit software version banners.
            As a result, no identifiable third-party software components (like Apache, nginx, or WordPress) were fingerprinted for version matching.
          </div>
        </div>
      )}

      {/* Tabs and Search Controls */}
      <div className="glass-panel" style={{ padding: '0.75rem 1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
            <button
              className={`btn ${activeTab === 'services' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('services')}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <Server size={13} />
              <span>Services ({services.length})</span>
            </button>

            <button
              className={`btn ${activeTab === 'tech' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('tech')}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <Code2 size={13} />
              <span>Technologies ({technologies.length})</span>
            </button>

            <button
              className={`btn ${activeTab === 'headers' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('headers')}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <ShieldCheck size={13} />
              <span>Security Headers ({securityHeaders.length})</span>
            </button>

            <button
              className={`btn ${activeTab === 'tls' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('tls')}
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            >
              <Lock size={13} />
              <span>TLS Metadata ({tlsMetadata.length})</span>
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flex: 1, maxWidth: '420px', justifyContent: 'flex-end' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '260px' }}>
              <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ width: '100%', paddingLeft: '1.9rem', fontSize: '0.8rem' }}
              />
            </div>

            {activeTab === 'tech' && categories.length > 0 && (
              <select
                className="form-input"
                value={techCategoryFilter}
                onChange={e => setTechCategoryFilter(e.target.value)}
                style={{ fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
              >
                <option value="ALL">All Categories</option>
                {categories.map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            )}
          </div>
        </div>
      </div>

      {/* Tab Panel 1: Services */}
      {activeTab === 'services' && (
        filteredServices.length > 0 ? (
          <div className="glass-panel" style={{ overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Service Name</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>HTTP Status</th>
                    <th>Page Title / Banner</th>
                    <th>Observed At</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredServices.map(svc => (
                    <tr key={svc.id}>
                      <td style={{ fontWeight: 600, color: 'var(--cyan-400)' }}>
                        {svc.service_name}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        {svc.port}
                      </td>
                      <td>
                        <span className="badge badge-neutral font-mono" style={{ fontSize: '0.68rem' }}>
                          {svc.protocol}
                        </span>
                      </td>
                      <td>
                        {svc.http_status ? (
                          <span className={`badge ${svc.http_status < 400 ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.68rem' }}>
                            HTTP {svc.http_status}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-primary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {svc.page_title || '—'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(svc.observed_at).toLocaleTimeString()}
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
              title="No Exposed Services Observed"
              description="No active service exposures recorded for target domain."
              icon={Server}
              actionLabel="4. Tech/Headers"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}

      {/* Tab Panel 2: Technologies */}
      {activeTab === 'tech' && (
        filteredTech.length > 0 ? (
          <div className="glass-panel" style={{ overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset / Hostname</th>
                    <th>Technology Name</th>
                    <th>Category</th>
                    <th>Observed Version</th>
                    <th>Confidence</th>
                    <th>CPE Identifier</th>
                    <th>Evidence Source</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTech.map(tech => (
                    <tr key={tech.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {tech.asset_value || '—'}
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--cyan-400)' }}>
                        {tech.name}
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                          {tech.category}
                        </span>
                      </td>
                      <td>
                        {tech.version ? (
                          <span className="badge badge-success font-mono" style={{ fontSize: '0.72rem' }}>
                            {tech.version}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>Version not observed</span>
                        )}
                      </td>
                      <td>
                        <span className="badge badge-info" style={{ fontSize: '0.68rem' }}>
                          {(tech.confidence * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {tech.cpe || '—'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {tech.evidence_source}
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
              title="No Technologies Detected"
              description="No software or framework fingerprints were disclosed in HTTP response headers, cookies, or HTML markers for the probed endpoints."
              icon={Cpu}
              actionLabel={services.length > 0 ? "View Exposed Services" : "4. Tech/Headers"}
              onAction={services.length > 0 ? () => setActiveTab('services') : onRunFingerprint}
            />
          </div>
        )
      )}

      {/* Tab Panel 3: Security Headers */}
      {activeTab === 'headers' && (
        securityHeaders.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {securityHeaders.map(sh => (
              <div key={sh.service_id} className="glass-panel" style={{ padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                      {sh.url}
                    </span>
                    <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                      {sh.port}/{sh.protocol}
                    </span>
                    {sh.http_status && (
                      <span className={`badge ${sh.http_status < 400 ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.68rem' }}>
                        HTTP {sh.http_status}
                      </span>
                    )}
                  </div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                    Observed: {new Date(sh.observed_at).toLocaleTimeString()}
                  </span>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table" style={{ fontSize: '0.78rem' }}>
                    <thead>
                      <tr>
                        <th>Security Header Name</th>
                        <th>Header State</th>
                        <th>Observed Interpretation / Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(sh.headers).map(([hName, hData]: [string, any]) => (
                        <tr key={hName}>
                          <td style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{hName}</td>
                          <td>
                            <span
                              className={`badge ${hData.present ? 'badge-success' : 'badge-danger'}`}
                              style={{ fontSize: '0.65rem' }}
                            >
                              {hData.status || (hData.present ? 'PRESENT' : 'MISSING')}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                            {hData.value || hData.reason || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="glass-panel" style={{ padding: '2rem' }}>
            <EmptyState
              title="No Security Headers Analyzed"
              description="Click '4. Tech/Headers' to inspect HTTP response headers and security policies."
              icon={ShieldCheck}
              actionLabel="4. Tech/Headers"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}

      {/* Tab Panel 4: TLS Metadata */}
      {activeTab === 'tls' && (
        filteredTLS.length > 0 ? (
          <div className="glass-panel" style={{ overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target Endpoint</th>
                    <th>Negotiated Protocol</th>
                    <th>Certificate Subject (CN)</th>
                    <th>Issuer Authority</th>
                    <th>Validity Window</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTLS.map((tls, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {tls.url}
                      </td>
                      <td>
                        <span className="badge badge-purple font-mono" style={{ fontSize: '0.68rem' }}>
                          {tls.tls_version || 'TLS'}
                        </span>
                      </td>
                      <td style={{ fontWeight: 500 }}>
                        {tls.cert_subject || '—'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {tls.cert_issuer || '—'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {tls.cert_valid_to ? `Expires: ${new Date(tls.cert_valid_to).toLocaleDateString()}` : '—'}
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
              title="No TLS Metadata Observed"
              description="No TLS/SSL metadata observed for this target. Run fingerprinting to inspect HTTPS certificates."
              icon={Lock}
              actionLabel="4. Tech/Headers"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}
    </div>
  );
};

export default ServicesTechView;
