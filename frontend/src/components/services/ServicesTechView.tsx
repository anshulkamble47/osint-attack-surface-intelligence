import React, { useState, useMemo } from 'react';
import {
  Cpu,
  Search,
  ShieldCheck,
  Lock,
  Code2,
  Server
} from 'lucide-react';
import {
  TechnologySummary,
  ServiceExposureSummary,
  SecurityHeadersSummary,
  TLSMetadataSummary,
} from '../../types/api';
import { EmptyState } from '../common/EmptyState';

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
  const [activeTab, setActiveTab] = useState<'tech' | 'services' | 'headers' | 'tls'>('tech');
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Action */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#fbbf24',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Cpu size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Services & Technology Fingerprinting</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Observed web servers, application frameworks, exposed TCP ports, HTTP security header interpretations, and TLS cryptographic configurations for <strong>{targetDomain}</strong>.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onRunFingerprint}
              disabled={loading}
              className="btn btn-primary"
            >
              <Cpu size={16} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Fingerprinting...' : 'Run Fingerprinting Probe'}</span>
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
          <div className="stat-label">Observed Technologies</div>
          <div className="stat-value">{technologies.length}</div>
          <div className="stat-subtext">Across {categories.length} categories</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Exposed Services</div>
          <div className="stat-value">{services.length}</div>
          <div className="stat-subtext">Active ports & endpoints</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Analyzed Security Headers</div>
          <div className="stat-value">{securityHeaders.length}</div>
          <div className="stat-subtext">Evaluated web services</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">TLS Session Observations</div>
          <div className="stat-value">{tlsMetadata.length}</div>
          <div className="stat-subtext">Encrypted endpoints</div>
        </div>
      </div>

      {/* Navigation Toolbar */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              onClick={() => setActiveTab('tech')}
              className={`btn ${activeTab === 'tech' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.95rem', fontSize: '0.85rem' }}
            >
              <Code2 size={15} />
              <span>Technologies ({technologies.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('services')}
              className={`btn ${activeTab === 'services' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.95rem', fontSize: '0.85rem' }}
            >
              <Server size={15} />
              <span>Exposed Services ({services.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('headers')}
              className={`btn ${activeTab === 'headers' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.95rem', fontSize: '0.85rem' }}
            >
              <ShieldCheck size={15} />
              <span>Security Headers ({securityHeaders.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('tls')}
              className={`btn ${activeTab === 'tls' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.95rem', fontSize: '0.85rem' }}
            >
              <Lock size={15} />
              <span>TLS Metadata ({tlsMetadata.length})</span>
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, maxWidth: '450px', justifyContent: 'flex-end' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search tech, port, header..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>

            {activeTab === 'tech' && categories.length > 0 && (
              <select
                className="form-input"
                value={techCategoryFilter}
                onChange={e => setTechCategoryFilter(e.target.value)}
                style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
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

      {/* Tab Panels */}
      {activeTab === 'tech' && (
        filteredTech.length > 0 ? (
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
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
                        <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                          {tech.category}
                        </span>
                      </td>
                      <td>
                        {tech.version ? (
                          <span className="badge badge-success font-mono" style={{ fontSize: '0.75rem' }}>
                            {tech.version}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Version not observed</span>
                        )}
                      </td>
                      <td>
                        <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>
                          {(tech.confidence * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {tech.cpe || '—'}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
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
              description="No software or framework fingerprints observed. Run the fingerprinting probe to analyze HTTP headers, script tags, cookies, and TLS banners."
              icon={Cpu}
              actionLabel="Run Fingerprinting Probe"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}

      {activeTab === 'services' && (
        filteredServices.length > 0 ? (
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Service Name</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>HTTP Status</th>
                    <th>Page Title</th>
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
                        <span className="badge badge-neutral font-mono" style={{ fontSize: '0.7rem' }}>
                          {svc.protocol}
                        </span>
                      </td>
                      <td>
                        {svc.http_status ? (
                          <span className={`badge ${svc.http_status < 400 ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.75rem' }}>
                            HTTP {svc.http_status}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-primary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
              actionLabel="Run Fingerprinting Probe"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}

      {activeTab === 'headers' && (
        securityHeaders.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {securityHeaders.map(sh => (
              <div key={sh.service_id} className="glass-panel" style={{ padding: '1.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--cyan-400)', fontFamily: 'var(--font-mono)' }}>
                      {sh.url}
                    </span>
                    <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                      {sh.port}/{sh.protocol}
                    </span>
                    {sh.http_status && (
                      <span className={`badge ${sh.http_status < 400 ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.7rem' }}>
                        HTTP {sh.http_status}
                      </span>
                    )}
                  </div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    Observed: {new Date(sh.observed_at).toLocaleTimeString()}
                  </span>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table" style={{ fontSize: '0.8rem' }}>
                    <thead>
                      <tr>
                        <th>Security Header Name</th>
                        <th>Header State</th>
                        <th>Observed Interpretation / Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(sh.headers).map(([k, h]) => (
                        <tr key={k}>
                          <td style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{h.header_name}</td>
                          <td>
                            <span className={`badge ${h.present ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.7rem' }}>
                              {h.present ? 'Present' : 'Missing'}
                            </span>
                          </td>
                          <td style={{ color: h.present ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                            {h.interpretation} {h.value ? `("${h.value}")` : ''}
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
              title="No Security Header Records"
              description="No HTTP security header evaluations recorded. Run the fingerprinting probe to inspect HSTS, CSP, X-Frame-Options, and cookie attributes."
              icon={ShieldCheck}
              actionLabel="Run Fingerprinting Probe"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}

      {activeTab === 'tls' && (
        filteredTLS.length > 0 ? (
          <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Endpoint URL</th>
                    <th>TLS Version</th>
                    <th>Cipher Suite</th>
                    <th>Subject CN</th>
                    <th>Issuer</th>
                    <th>Validity Period</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTLS.map((tls, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {tls.url}
                      </td>
                      <td>
                        <span className="badge badge-info font-mono" style={{ fontSize: '0.75rem' }}>
                          {tls.tls_version || 'TLS'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {tls.cipher_suite || '—'}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                        {tls.cert_subject || '—'}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {tls.cert_issuer || '—'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {tls.cert_valid_from ? `${new Date(tls.cert_valid_from).toLocaleDateString()} - ${new Date(tls.cert_valid_to || '').toLocaleDateString()}` : '—'}
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
              title="No TLS Metadata Records"
              description="No active TLS handshake observations recorded for this target."
              icon={Lock}
              actionLabel="Run Fingerprinting Probe"
              onAction={onRunFingerprint}
            />
          </div>
        )
      )}
    </div>
  );
};

export default ServicesTechView;
