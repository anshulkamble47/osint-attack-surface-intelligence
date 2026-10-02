import React, { useState } from 'react';
import {
  Share2,
  GitFork,
  Filter,
  Eye,
  RefreshCw,
  Info,
  Search
} from 'lucide-react';
import { GraphResponse, GraphNode } from '../../types/api';
import { EmptyState } from '../common/EmptyState';

interface AttackSurfaceGraphViewProps {
  graphData: GraphResponse | null;
  onRefreshGraph: () => void;
  loading: boolean;
  error: string | null;
  selectedNodeType: string;
  onChangeNodeType: (type: string) => void;
  selectedRelType: string;
  onChangeRelType: (rel: string) => void;
}

export const AttackSurfaceGraphView: React.FC<AttackSurfaceGraphViewProps> = ({
  graphData,
  onRefreshGraph,
  loading,
  error,
  selectedNodeType,
  onChangeNodeType,
  selectedRelType,
  onChangeRelType,
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [activeTab, setActiveTab] = useState<'visual' | 'nodes' | 'edges'>('visual');
  const [searchTerm, setSearchTerm] = useState('');

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'domain': return 'var(--cyan-400)';
      case 'subdomain': return 'var(--blue-400)';
      case 'ip': return 'var(--emerald-400)';
      case 'asn': return '#fbbf24';
      case 'service': return '#38bdf8';
      case 'technology': return '#a78bfa';
      case 'vulnerability': return 'var(--rose-400)';
      case 'certificate': return '#f472b6';
      default: return 'var(--text-secondary)';
    }
  };

  const filteredNodes = graphData?.nodes.filter(n => {
    if (searchTerm && !n.label.toLowerCase().includes(searchTerm.toLowerCase()) && !n.id.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    return true;
  }) || [];

  const filteredEdges = graphData?.edges.filter(e => {
    if (searchTerm && !e.source.toLowerCase().includes(searchTerm.toLowerCase()) && !e.target.toLowerCase().includes(searchTerm.toLowerCase()) && !e.relationship_type.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    return true;
  }) || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Controls */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div style={{
                background: 'rgba(168, 85, 247, 0.15)',
                color: '#c084fc',
                padding: '0.45rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Share2 size={20} />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>Attack Surface Relationship Graph</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '800px' }}>
              Deterministic, scan-isolated graph connecting Domains, Subdomains, IPs, ASNs, Exposed Services, Technologies, and Correlated Vulnerabilities.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '200px' }}>
              <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search nodes/edges..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '1.8rem', padding: '0.4rem 0.6rem 0.4rem 1.8rem', fontSize: '0.8rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={15} color="var(--text-muted)" />
              <select
                className="form-input"
                value={selectedNodeType}
                onChange={e => onChangeNodeType(e.target.value)}
                style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
              >
                <option value="ALL">All Node Types</option>
                <option value="domain">Domain</option>
                <option value="subdomain">Subdomain</option>
                <option value="ip">IP Address</option>
                <option value="asn">ASN</option>
                <option value="service">Service</option>
                <option value="technology">Technology</option>
                <option value="vulnerability">Vulnerability</option>
                <option value="certificate">Certificate</option>
              </select>
            </div>

            <select
              className="form-input"
              value={selectedRelType}
              onChange={e => onChangeRelType(e.target.value)}
              style={{ width: 'auto', padding: '0.4rem 0.75rem' }}
            >
              <option value="ALL">All Relationships</option>
              <option value="CONTAINS">CONTAINS</option>
              <option value="RESOLVES_TO">RESOLVES_TO</option>
              <option value="ANNOUNCED_BY">ANNOUNCED_BY</option>
              <option value="EXPOSES">EXPOSES</option>
              <option value="USES_TECHNOLOGY">USES_TECHNOLOGY</option>
              <option value="AFFECTED_BY">AFFECTED_BY</option>
              <option value="HAS_CERTIFICATE">HAS_CERTIFICATE</option>
            </select>

            <button
              onClick={onRefreshGraph}
              disabled={loading}
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #9333ea, #a855f7)', border: 'none' }}
            >
              <RefreshCw size={15} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Correlating...' : 'Refresh Graph'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
            {error}
          </div>
        )}
      </div>

      {graphData ? (
        <>
          {/* Summary Strip */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label">Total Graph Nodes</div>
              <div className="stat-value" style={{ color: '#c084fc' }}>{graphData.statistics.node_count}</div>
              <div className="stat-subtext">Discovered entities</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Total Correlated Edges</div>
              <div className="stat-value" style={{ color: 'var(--cyan-400)' }}>{graphData.statistics.edge_count}</div>
              <div className="stat-subtext">Deterministic relationships</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Scan Attribution</div>
              <div className="stat-value" style={{ color: 'var(--emerald-400)', fontSize: '1.25rem' }}>
                {graphData.scan_run_number ? `Run #${graphData.scan_run_number}` : 'Latest Snapshot'}
              </div>
              <div className="stat-subtext">Isolated point-in-time state</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Target Scope</div>
              <div className="stat-value" style={{ fontSize: '1.15rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {graphData.target_domain}
              </div>
              <div className="stat-subtext">Primary root asset</div>
            </div>
          </div>

          {/* Node and Edge Category Distribution Pills */}
          <div className="glass-panel" style={{ padding: '0.85rem 1.25rem' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>NODES:</span>
                {Object.entries(graphData.statistics.nodes_by_type).map(([type, count]) => (
                  <button
                    key={type}
                    onClick={() => onChangeNodeType(type)}
                    className="badge"
                    style={{
                      background: selectedNodeType === type ? 'rgba(168, 85, 247, 0.25)' : 'rgba(15, 23, 42, 0.6)',
                      border: `1px solid ${selectedNodeType === type ? '#a855f7' : 'var(--border-subtle)'}`,
                      color: getNodeColor(type),
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      padding: '0.2rem 0.5rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.35rem'
                    }}
                  >
                    <span style={{ textTransform: 'capitalize' }}>{type}</span>
                    <span style={{ fontWeight: 700 }}>({count})</span>
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>EDGES:</span>
                {Object.entries(graphData.statistics.edges_by_type).map(([rel, count]) => (
                  <button
                    key={rel}
                    onClick={() => onChangeRelType(rel)}
                    className="badge"
                    style={{
                      background: selectedRelType === rel ? 'rgba(56, 189, 248, 0.25)' : 'rgba(15, 23, 42, 0.6)',
                      border: `1px solid ${selectedRelType === rel ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                      color: 'var(--cyan-400)',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      padding: '0.2rem 0.5rem'
                    }}
                  >
                    <span>{rel}</span>: <strong>{count}</strong>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Graph Explorer & Split Inspector */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr)', gap: '1.25rem', alignItems: 'start' }}>

            {/* Left: Interactive Visual Topology & Node/Edge Explorer */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

              {/* Tab Navigation */}
              <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                <button
                  onClick={() => setActiveTab('visual')}
                  className={`btn ${activeTab === 'visual' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }}
                >
                  Topology View ({graphData.nodes.length})
                </button>
                <button
                  onClick={() => setActiveTab('nodes')}
                  className={`btn ${activeTab === 'nodes' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }}
                >
                  Node List ({filteredNodes.length})
                </button>
                <button
                  onClick={() => setActiveTab('edges')}
                  className={`btn ${activeTab === 'edges' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }}
                >
                  Edge Relationships ({filteredEdges.length})
                </button>
              </div>

              {/* Topology / Visual Representation */}
              {activeTab === 'visual' && (
                <div className="glass-panel" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                      Deterministic Attack Surface Topology
                    </h3>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Click any entity card to inspect attributes
                    </span>
                  </div>

                  {/* Grouped Entity Cards by Type */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxHeight: '480px', overflowY: 'auto' }}>
                    {['domain', 'subdomain', 'ip', 'asn', 'service', 'technology', 'vulnerability', 'certificate'].map(type => {
                      const nodesOfType = graphData.nodes.filter(n => n.type === type);
                      if (nodesOfType.length === 0) return null;

                      return (
                        <div key={type} style={{ background: 'rgba(15, 23, 42, 0.4)', borderRadius: '8px', padding: '0.85rem', border: '1px solid var(--border-subtle)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                            <span
                              className="badge"
                              style={{
                                fontSize: '0.7rem',
                                background: 'rgba(0,0,0,0.3)',
                                color: getNodeColor(type),
                                border: `1px solid ${getNodeColor(type)}`,
                                textTransform: 'uppercase',
                                fontWeight: 700
                              }}
                            >
                              {type}
                            </span>
                            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                              ({nodesOfType.length} nodes)
                            </span>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.5rem' }}>
                            {nodesOfType.map(node => {
                              const isSelected = selectedNode?.id === node.id;
                              return (
                                <div
                                  key={node.id}
                                  onClick={() => setSelectedNode(node)}
                                  style={{
                                    padding: '0.5rem 0.75rem',
                                    borderRadius: '6px',
                                    background: isSelected ? 'rgba(168, 85, 247, 0.2)' : 'rgba(30, 41, 59, 0.6)',
                                    border: `1px solid ${isSelected ? '#a855f7' : 'var(--border-subtle)'}`,
                                    cursor: 'pointer',
                                    transition: 'all 0.15s ease',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between',
                                    gap: '0.5rem'
                                  }}
                                >
                                  <div style={{ fontSize: '0.8rem', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {node.label}
                                  </div>
                                  <Eye size={13} color={isSelected ? '#c084fc' : 'var(--text-muted)'} style={{ flexShrink: 0 }} />
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Node List Tab */}
              {activeTab === 'nodes' && (
                <div className="glass-panel" style={{ padding: '1rem' }}>
                  <div style={{ maxHeight: '420px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {filteredNodes.map(node => {
                      const isSelected = selectedNode?.id === node.id;
                      const typeColor = getNodeColor(node.type);

                      return (
                        <div
                          key={node.id}
                          onClick={() => setSelectedNode(node)}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '0.55rem 0.75rem',
                            borderRadius: '6px',
                            background: isSelected ? 'rgba(168, 85, 247, 0.2)' : 'rgba(30, 41, 59, 0.5)',
                            border: isSelected ? '1px solid #a855f7' : '1px solid var(--border-subtle)',
                            cursor: 'pointer',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', minWidth: 0 }}>
                            <span
                              className="badge"
                              style={{
                                fontSize: '0.65rem',
                                background: 'rgba(0,0,0,0.3)',
                                color: typeColor,
                                border: `1px solid ${typeColor}`,
                                padding: '0.1rem 0.4rem',
                              }}
                            >
                              {node.type.toUpperCase()}
                            </span>
                            <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {node.label}
                            </span>
                          </div>
                          <Eye size={14} color={isSelected ? '#c084fc' : 'var(--text-muted)'} />
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Edge List Tab */}
              {activeTab === 'edges' && (
                <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
                  <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
                    <table className="data-table" style={{ fontSize: '0.8rem' }}>
                      <thead>
                        <tr>
                          <th>Source Node</th>
                          <th>Relationship</th>
                          <th>Target Node</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredEdges.map(edge => (
                          <tr key={edge.id}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                              {edge.source}
                            </td>
                            <td>
                              <span
                                className="badge"
                                style={{
                                  fontSize: '0.65rem',
                                  background: 'rgba(168, 85, 247, 0.15)',
                                  color: '#c084fc',
                                  border: '1px solid rgba(168, 85, 247, 0.3)',
                                  fontFamily: 'var(--font-mono)',
                                }}
                              >
                                {edge.relationship_type}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan-400)' }}>
                              {edge.target}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Relationship Legend */}
              <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  <Info size={14} color="var(--cyan-400)" />
                  <span>Relationship Semantics Legend</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>CONTAINS:</strong> Domain → Subdomain</div>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>RESOLVES_TO:</strong> Subdomain → IP Address</div>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>ANNOUNCED_BY:</strong> IP Address → ASN</div>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>EXPOSES:</strong> Subdomain → Service Exposure</div>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>USES_TECHNOLOGY:</strong> Subdomain → Technology</div>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>AFFECTED_BY:</strong> Technology → Vulnerability</div>
                  <div>• <strong style={{ color: 'var(--text-primary)' }}>HAS_CERTIFICATE:</strong> Subdomain → Certificate</div>
                </div>
              </div>
            </div>

            {/* Right: Selected Node Inspector Panel */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem' }}>
                <GitFork size={18} color="#c084fc" />
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Node Entity Inspector
                </h4>
              </div>

              {selectedNode ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Node Identifier</div>
                    <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: '#c084fc', wordBreak: 'break-all' }}>
                      {selectedNode.id}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Entity Type</div>
                      <span
                        className="badge"
                        style={{
                          fontSize: '0.75rem',
                          marginTop: '0.2rem',
                          background: 'rgba(0,0,0,0.3)',
                          color: getNodeColor(selectedNode.type),
                          border: `1px solid ${getNodeColor(selectedNode.type)}`
                        }}
                      >
                        {selectedNode.type.toUpperCase()}
                      </span>
                    </div>

                    {selectedNode.asset_id && (
                      <div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Asset UUID</div>
                        <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {selectedNode.asset_id}
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Display Label</div>
                    <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                      {selectedNode.label}
                    </div>
                  </div>

                  {/* Connected Edges */}
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                      Associated Edges ({graphData.edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).length})
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: '140px', overflowY: 'auto' }}>
                      {graphData.edges
                        .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                        .map(e => (
                          <div
                            key={e.id}
                            style={{
                              background: 'rgba(0,0,0,0.3)',
                              padding: '0.35rem 0.5rem',
                              borderRadius: '4px',
                              fontSize: '0.72rem',
                              fontFamily: 'var(--font-mono)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              gap: '0.5rem'
                            }}
                          >
                            <span style={{ color: e.source === selectedNode.id ? 'var(--cyan-400)' : 'var(--text-secondary)' }}>{e.source}</span>
                            <span style={{ color: '#c084fc', fontWeight: 600 }}>{e.relationship_type}</span>
                            <span style={{ color: e.target === selectedNode.id ? 'var(--cyan-400)' : 'var(--text-secondary)' }}>{e.target}</span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* Node Metadata JSON */}
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>Deterministic Metadata</div>
                    <pre
                      style={{
                        background: 'rgba(0, 0, 0, 0.4)',
                        padding: '0.75rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '260px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        border: '1px solid var(--border-subtle)'
                      }}
                    >
                      {JSON.stringify(selectedNode.metadata, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '3rem 1rem' }}>
                  Select an entity node from the topology or node list to view its deterministic attributes and associated edges.
                </div>
              )}
            </div>
          </div>
        </>
      ) : (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <EmptyState
            title="No Relationship Data Available"
            description="No graph correlation data has been built for this investigation yet. Build the graph to deterministically connect discovered assets, DNS observations, services, technologies, and vulnerabilities."
            icon={Share2}
            actionLabel="Build Attack Surface Graph"
            onAction={onRefreshGraph}
          />
        </div>
      )}
    </div>
  );
};
