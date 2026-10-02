import React, { useState, useMemo } from 'react';
import {
  Globe,
  Search,
  Filter,
  Eye
} from 'lucide-react';
import {
  AssetSummary
} from '../../types/api';
import { StatusBadge } from '../common/StatusBadge';
import { Modal } from '../common/Modal';
import { EmptyState } from '../common/EmptyState';

interface AssetInventoryProps {
  assets: AssetSummary[];
  onRunCT: () => void;
  loading: boolean;
  error: string | null;
  targetDomain: string;
}

export const AssetInventory: React.FC<AssetInventoryProps> = ({
  assets,
  onRunCT,
  loading,
  error,
  targetDomain,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedAsset, setSelectedAsset] = useState<AssetSummary | null>(null);

  const filteredAssets = useMemo(() => {
    return assets.filter(a => {
      if (selectedType !== 'ALL' && a.asset_type !== selectedType) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          a.value.toLowerCase().includes(term) ||
          a.asset_type.toLowerCase().includes(term) ||
          a.source.toLowerCase().includes(term) ||
          (a.tags && a.tags.some(t => t.toLowerCase().includes(term)))
        );
      }
      return true;
    });
  }, [assets, selectedType, searchTerm]);

  const assetTypes = useMemo(() => {
    return Array.from(new Set(assets.map(a => a.asset_type))).sort();
  }, [assets]);

  const activeCount = assets.filter(a => a.is_active).length;
  const subdomainCount = assets.filter(a => a.asset_type === 'subdomain').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & CT Discovery Trigger */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(14, 165, 233, 0.15)',
                color: 'var(--cyan-400)',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Globe size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Discovered Asset Inventory</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Catalog of domains, subdomains, and discovered digital assets mapped via Certificate Transparency logs and DNS enumeration.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onRunCT}
              disabled={loading}
              className="btn btn-primary"
            >
              <Search size={16} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Scanning CT Logs...' : 'Discover CT Logs'}</span>
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
          <div className="stat-label">Total Discovered Assets</div>
          <div className="stat-value">{assets.length}</div>
          <div className="stat-subtext">Across target scope</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Subdomains Discovered</div>
          <div className="stat-value" style={{ color: 'var(--cyan-400)' }}>{subdomainCount}</div>
          <div className="stat-subtext">FQDNs mapped from CT</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Active / Resolving Assets</div>
          <div className="stat-value" style={{ color: 'var(--emerald-400)' }}>{activeCount}</div>
          <div className="stat-subtext">Confirmed responsive endpoints</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Primary Root Domain</div>
          <div className="stat-value" style={{ fontSize: '1.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {targetDomain}
          </div>
          <div className="stat-subtext">Investigation target</div>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '240px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '320px' }}>
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search asset, FQDN, tag..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '2.25rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={15} color="var(--text-muted)" />
              <select
                className="form-input"
                value={selectedType}
                onChange={e => setSelectedType(e.target.value)}
                style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
              >
                <option value="ALL">All Asset Types ({assets.length})</option>
                {assetTypes.map(type => (
                  <option key={type} value={type}>
                    {type.toUpperCase()} ({assets.filter(a => a.asset_type === type).length})
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Assets Table */}
      {filteredAssets.length > 0 ? (
        <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
              Discovered Assets ({filteredAssets.length})
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Click row to inspect asset details
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Asset Value / FQDN</th>
                  <th>Type</th>
                  <th>Discovery Source</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Tags</th>
                  <th>First Observed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.map(asset => (
                  <tr key={asset.id} onClick={() => setSelectedAsset(asset)} style={{ cursor: 'pointer' }}>
                    <td style={{ fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                      {asset.value}
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ fontSize: '0.7rem', textTransform: 'uppercase' }}>
                        {asset.asset_type}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {asset.source}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>
                        {(asset.confidence * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={asset.is_active ? 'active' : 'inactive'} />
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                        {asset.tags && asset.tags.length > 0 ? (
                          asset.tags.map((t, idx) => (
                            <span key={idx} className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                              {t}
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                        )}
                      </div>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(asset.first_seen_at).toLocaleDateString()}
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAsset(asset);
                        }}
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
                      </button>
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
            title="No Assets Discovered"
            description="No digital assets have been discovered for this target yet. Run Certificate Transparency discovery to identify external subdomains."
            icon={Globe}
            actionLabel="Run Certificate Transparency Discovery"
            onAction={onRunCT}
          />
        </div>
      )}

      {/* Asset Detail Inspector Modal */}
      {selectedAsset && (
        <Modal
          title={`Asset Details: ${selectedAsset.value}`}
          isOpen={!!selectedAsset}
          onClose={() => setSelectedAsset(null)}
          maxWidth="600px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '1.15rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                  {selectedAsset.value}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
                  UUID: {selectedAsset.id}
                </div>
              </div>
              <StatusBadge status={selectedAsset.is_active ? 'active' : 'inactive'} />
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.82rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Asset Type: </span>
                <span className="badge badge-neutral font-mono" style={{ fontSize: '0.7rem', textTransform: 'uppercase' }}>
                  {selectedAsset.asset_type}
                </span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Discovery Source: </span>
                <span style={{ color: 'var(--text-primary)' }}>{selectedAsset.source}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Confidence Score: </span>
                <span style={{ color: 'var(--cyan-400)', fontWeight: 600 }}>{(selectedAsset.confidence * 100).toFixed(0)}%</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Base Risk Score: </span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{selectedAsset.risk_score}/100</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>First Seen: </span>
                <span style={{ color: 'var(--text-secondary)' }}>{new Date(selectedAsset.first_seen_at).toLocaleString()}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Last Seen: </span>
                <span style={{ color: 'var(--text-secondary)' }}>{new Date(selectedAsset.last_seen_at).toLocaleString()}</span>
              </div>
            </div>

            {selectedAsset.tags && selectedAsset.tags.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>Tags</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {selectedAsset.tags.map((t, idx) => (
                    <span key={idx} className="badge badge-info" style={{ fontSize: '0.75rem' }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};

export default AssetInventory;
