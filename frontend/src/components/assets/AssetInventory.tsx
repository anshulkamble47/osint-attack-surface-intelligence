import React, { useState, useMemo } from 'react';
import {
  Globe,
  Search,
  Filter,
  Eye,
  ShieldCheck,
  Radio,
  Layers
} from 'lucide-react';
import { AssetSummary } from '../../types/api';
import { StatusBadge } from '../common/StatusBadge';
import { Modal } from '../common/Modal';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';

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
  const candidateCount = assets.filter(a => !a.is_active).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & CT Discovery Trigger */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <div style={{
                background: 'rgba(14, 165, 233, 0.15)',
                color: 'var(--cyan-400)',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Globe size={18} />
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Discovered Asset Inventory</h2>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Catalog of domains, subdomains, and candidate hostnames mapped via resilient Certificate Transparency logs.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onRunCT}
              disabled={loading}
              className="btn btn-primary"
            >
              <Search size={14} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Scanning CT Logs...' : '1. Discover CT'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '0.75rem' }}>
            {error}
          </div>
        )}
      </div>

      {/* Compact Summary Metrics Strip */}
      <div className="compact-stats-grid">
        <CompactStatCard
          icon={Globe}
          label="Total Assets"
          value={assets.length}
          subtext={`Target: ${targetDomain}`}
          color="cyan"
        />

        <CompactStatCard
          icon={Layers}
          label="Subdomains"
          value={subdomainCount}
          subtext="Mapped from CT logs"
          color="neutral"
        />

        <CompactStatCard
          icon={ShieldCheck}
          label="Active & Resolving"
          value={activeCount}
          subtext="Confirmed via DNS resolution"
          color="emerald"
        />

        <CompactStatCard
          icon={Radio}
          label="CT Candidates"
          value={candidateCount}
          subtext="Unverified pending DNS probe"
          color="amber"
        />
      </div>

      {/* Search & Filter Toolbar */}
      <div className="glass-panel" style={{ padding: '0.75rem 1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '220px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '300px' }}>
              <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search asset, FQDN, tag..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ width: '100%', paddingLeft: '2rem', fontSize: '0.8rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                className="form-input"
                value={selectedType}
                onChange={e => setSelectedType(e.target.value)}
                style={{ fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
              >
                <option value="ALL">All Asset Types</option>
                {assetTypes.map(t => (
                  <option key={t} value={t}>
                    {t.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Showing <strong>{filteredAssets.length}</strong> of {assets.length} assets
          </div>
        </div>
      </div>

      {/* Assets Data Table */}
      {filteredAssets.length > 0 ? (
        <div className="glass-panel" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto', maxHeight: '550px' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Asset Identifier / Value</th>
                  <th>Type</th>
                  <th>Reachability / Status</th>
                  <th>Discovery Source</th>
                  <th>Confidence</th>
                  <th>First Observed</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.map(asset => (
                  <tr key={asset.id} onClick={() => setSelectedAsset(asset)} style={{ cursor: 'pointer' }}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <Globe size={14} color="var(--cyan-400)" />
                        <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                          {asset.value}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                        {asset.asset_type}
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={asset.is_active ? 'active' : 'candidate'} />
                    </td>
                    <td>
                      <span className="badge badge-info" style={{ fontSize: '0.68rem', textTransform: 'lowercase' }}>
                        {asset.source}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {Math.round(asset.confidence * 100)}%
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(asset.first_seen_at).toLocaleDateString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-secondary"
                        onClick={e => {
                          e.stopPropagation();
                          setSelectedAsset(asset);
                        }}
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
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
            title={assets.length === 0 ? "No Assets Discovered Yet" : "No Matching Assets"}
            description={
              assets.length === 0
                ? "Run Certificate Transparency (CT) discovery to passively map subdomains and certificates for this target."
                : "No assets match your search term or filter selection."
            }
            icon={Globe}
            actionLabel={assets.length === 0 ? "1. Discover CT" : undefined}
            onAction={assets.length === 0 ? onRunCT : undefined}
          />
        </div>
      )}

      {/* Asset Inspection Modal */}
      {selectedAsset && (
        <Modal
          title={`Asset Inspection: ${selectedAsset.value}`}
          isOpen={!!selectedAsset}
          onClose={() => setSelectedAsset(null)}
          maxWidth="640px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', background: 'rgba(15, 23, 42, 0.5)', padding: '0.85rem', borderRadius: '8px' }}>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Asset Identifier</div>
                <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)', marginTop: '0.2rem' }}>
                  {selectedAsset.value}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Asset Category</div>
                <div style={{ marginTop: '0.2rem' }}>
                  <span className="badge badge-neutral">{selectedAsset.asset_type}</span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Verification State</div>
                <div style={{ marginTop: '0.2rem' }}>
                  <StatusBadge status={selectedAsset.is_active ? 'active' : 'candidate'} />
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Discovery Provenance</div>
                <div style={{ marginTop: '0.2rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                  {selectedAsset.source}
                </div>
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem', textTransform: 'uppercase' }}>
                Operational Context & Flags
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, background: 'rgba(15, 23, 42, 0.4)', padding: '0.75rem', borderRadius: '8px' }}>
                {selectedAsset.is_active
                  ? "This asset is actively resolving to routable public IP addresses and responding to network probes."
                  : "This asset is currently a candidate discovered from passive Certificate Transparency logs. It has not yet been confirmed via active Stage 3B DNS resolution."}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button className="btn btn-secondary" onClick={() => setSelectedAsset(null)}>
                Close
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

export default AssetInventory;
