import React, { useState } from 'react';
import {
  Share2,
  GitFork,
  Filter,
  Eye,
  RefreshCw,
  Info,
  Search,
  Layers,
  Link,
  Target,
  Clock,
  ArrowRight
} from 'lucide-react';
import { GraphResponse, GraphNode } from '../../types/api';
import { EmptyState } from '../common/EmptyState';
import { CompactStatCard } from '../common/CompactStatCard';
import { InteractiveGraphCanvas } from './InteractiveGraphCanvas';

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
      case 'subdomain': return '#60a5fa';
      case 'ip': return 'var(--emerald-400)';
      case 'asn': return '#fbbf24';
      case 'service': return '#38bdf8';
      case 'technology': return '#a78bfa';
      case 'vulnerability': return 'var(--rose-400)';
      case 'certificate': return '#f472b6';
      default: return 'var(--text-secondary)';
    }
  };

  // 1. Filter nodes based on selectedNodeType and searchTerm
  const filteredNodes = (graphData?.nodes || []).filter(n => {
    if (selectedNodeType !== 'ALL' && n.type.toLowerCase() !== selectedNodeType.toLowerCase()) {
      return false;
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return n.label.toLowerCase().includes(term) || n.id.toLowerCase().includes(term);
    }
    return true;
  });

  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));

  // 2. Filter edges:
  // - If selectedRelType is set, filter by relationship_type.
  // - If selectedNodeType is set (e.g. 'asn' or 'service'), show incident edges (edges where source OR target is in filteredNodes).
  // - If searchTerm is set, match source, target, or relationship_type.
  const filteredEdges = (graphData?.edges || []).filter(e => {
    if (selectedRelType !== 'ALL' && e.relationship_type.toUpperCase() !== selectedRelType.toUpperCase()) {
      return false;
    }
    if (selectedNodeType !== 'ALL') {
      if (!filteredNodeIds.has(e.source) && !filteredNodeIds.has(e.target)) {
        return false;
      }
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        e.source.toLowerCase().includes(term) ||
        e.target.toLowerCase().includes(term) ||
        e.relationship_type.toLowerCase().includes(term)
      );
    }
    return true;
  });

  const findAndSelectNode = (nodeId: string) => {
    const target = (graphData?.nodes || []).find(n => n.id === nodeId);
    if (target) {
      setSelectedNode(target);
    }
  };

  // Check if topology has deeper entities or only domain/subdomain
  const hasExtendedTopology = graphData && graphData.nodes.some(n => !['domain', 'subdomain'].includes(n.type));

  const isFiltered = selectedNodeType !== 'ALL' || selectedRelType !== 'ALL' || Boolean(searchTerm);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {/* Header & Controls */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.85rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
              <div style={{
                background: 'rgba(168, 85, 247, 0.15)',
                color: '#c084fc',
                padding: '0.4rem',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Share2 size={18} />
              </div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Attack Surface Relationship Graph</h2>
              <span className="badge badge-purple" style={{ fontSize: '0.68rem' }}>Deterministic Topology</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
              Deterministic, scan-isolated graph correlating discovered assets, infrastructure, exposed services, technologies, and vulnerabilities.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '180px' }}>
              <Search size={13} color="var(--text-muted)" style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Search nodes/edges..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '1.75rem', padding: '0.35rem 0.6rem 0.35rem 1.75rem', fontSize: '0.78rem' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                className="form-input"
                value={selectedNodeType}
                onChange={e => onChangeNodeType(e.target.value)}
                style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
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
              style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
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
              style={{ background: 'linear-gradient(135deg, #9333ea, #a855f7)', border: 'none', padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
            >
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
              <span>{loading ? 'Correlating...' : 'Refresh Graph'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '0.75rem', padding: '0.5rem 0.75rem', fontSize: '0.8rem' }}>
            {error}
          </div>
        )}
      </div>

      {graphData ? (
        <>
          {/* Compact Summary Strip */}
          <div className="compact-stats-grid">
            <CompactStatCard
              icon={Layers}
              label="Graph Entities"
              value={graphData.statistics.node_count}
              subtext={selectedNodeType !== 'ALL' || searchTerm ? `${filteredNodes.length} matching filter` : `${Object.keys(graphData.statistics.nodes_by_type || {}).length} entity types`}
              color="purple"
            />
            <CompactStatCard
              icon={Link}
              label="Correlated Edges"
              value={graphData.statistics.edge_count}
              subtext={isFiltered ? `${filteredEdges.length} matching filter` : 'Deterministic relationships'}
              color="cyan"
            />
            <CompactStatCard
              icon={Target}
              label="Target Scope"
              value={graphData.target_domain}
              subtext="Root apex boundary"
              color="emerald"
            />
            <CompactStatCard
              icon={Clock}
              label="Scan Attribution"
              value={graphData.scan_run_number ? `Run #${graphData.scan_run_number}` : 'Latest State'}
              subtext="Point-in-time snapshot"
              color="amber"
            />
          </div>

          {/* Graph Semantics & Architecture Flow Explanation */}
          <div className="glass-panel" style={{ padding: '0.85rem 1.15rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem', fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              <Info size={14} color="var(--cyan-400)" />
              <span>Attack Surface Topology & Relationship Architecture</span>
            </div>
            
            <div style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.5rem',
              alignItems: 'center',
              background: 'rgba(15, 23, 42, 0.6)',
              padding: '0.6rem 0.85rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.75rem'
            }}>
              <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: 'var(--cyan-400)', border: '1px solid var(--cyan-400)' }}>Domain</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span style={{ color: '#c084fc', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>CONTAINS</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span className="badge" style={{ background: 'rgba(96, 165, 250, 0.15)', color: '#60a5fa', border: '1px solid #60a5fa' }}>Subdomain</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span style={{ color: '#c084fc', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>RESOLVES_TO</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span className="badge" style={{ background: 'rgba(52, 211, 153, 0.15)', color: 'var(--emerald-400)', border: '1px solid var(--emerald-400)' }}>IP Address</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span style={{ color: '#c084fc', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>ANNOUNCED_BY</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span className="badge" style={{ background: 'rgba(251, 191, 36, 0.15)', color: '#fbbf24', border: '1px solid #fbbf24' }}>ASN</span>
            </div>

            <div style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.5rem',
              alignItems: 'center',
              background: 'rgba(15, 23, 42, 0.6)',
              padding: '0.6rem 0.85rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.75rem',
              marginTop: '0.4rem'
            }}>
              <span className="badge" style={{ background: 'rgba(96, 165, 250, 0.15)', color: '#60a5fa', border: '1px solid #60a5fa' }}>Subdomain</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span style={{ color: '#c084fc', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>EXPOSES</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid #38bdf8' }}>Service</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span style={{ color: '#c084fc', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>USES_TECHNOLOGY</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span className="badge" style={{ background: 'rgba(167, 139, 250, 0.15)', color: '#a78bfa', border: '1px solid #a78bfa' }}>Technology</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span style={{ color: '#c084fc', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>AFFECTED_BY</span>
              <ArrowRight size={12} color="var(--text-muted)" />
              <span className="badge" style={{ background: 'rgba(244, 63, 94, 0.15)', color: 'var(--rose-400)', border: '1px solid var(--rose-400)' }}>Vulnerability</span>
            </div>

            {!hasExtendedTopology && (
              <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--amber-400)', background: 'rgba(251, 191, 36, 0.08)', padding: '0.4rem 0.65rem', borderRadius: '6px', border: '1px solid rgba(251, 191, 36, 0.2)' }}>
                <strong>Limited topology:</strong> Only domain and subdomain relationships are currently present in this snapshot. Run DNS Resolution, IP/ASN enrichment, and Service Fingerprinting from Overview to correlate infrastructure nodes.
              </div>
            )}
          </div>

          {/* Node and Edge Category Distribution Pills */}
          <div className="glass-panel" style={{ padding: '0.65rem 1rem' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>NODES:</span>
                {Object.entries(graphData.statistics.nodes_by_type).map(([type, count]) => {
                  const isActive = selectedNodeType.toLowerCase() === type.toLowerCase();
                  return (
                    <button
                      key={type}
                      onClick={() => onChangeNodeType(isActive ? 'ALL' : type)}
                      className="badge"
                      style={{
                        background: isActive ? 'rgba(168, 85, 247, 0.25)' : 'rgba(15, 23, 42, 0.6)',
                        border: `1px solid ${isActive ? '#a855f7' : 'var(--border-subtle)'}`,
                        color: getNodeColor(type),
                        cursor: 'pointer',
                        fontSize: '0.72rem',
                        padding: '0.15rem 0.45rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.3rem'
                      }}
                    >
                      <span style={{ textTransform: 'capitalize' }}>{type}</span>
                      <span style={{ fontWeight: 700 }}>({count})</span>
                    </button>
                  );
                })}
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>EDGES:</span>
                {Object.entries(graphData.statistics.edges_by_type).map(([rel, count]) => {
                  const isActive = selectedRelType.toUpperCase() === rel.toUpperCase();
                  return (
                    <button
                      key={rel}
                      onClick={() => onChangeRelType(isActive ? 'ALL' : rel)}
                      className="badge"
                      style={{
                        background: isActive ? 'rgba(56, 189, 248, 0.25)' : 'rgba(15, 23, 42, 0.6)',
                        border: `1px solid ${isActive ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
                        color: 'var(--cyan-400)',
                        cursor: 'pointer',
                        fontSize: '0.72rem',
                        padding: '0.15rem 0.45rem'
                      }}
                    >
                      <span>{rel}</span>: <strong>{count}</strong>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Graph Explorer & Split Inspector */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.45fr) minmax(0, 1fr)', gap: '1rem', alignItems: 'start' }}>

            {/* Left: Interactive Visual Topology & Node/Edge Explorer */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>

              {/* Tab Navigation */}
              <div style={{ display: 'flex', gap: '0.4rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                <button
                  onClick={() => setActiveTab('visual')}
                  className={`btn ${activeTab === 'visual' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.3rem 0.75rem', fontSize: '0.78rem' }}
                >
                  Topology View ({filteredNodes.length})
                </button>
                <button
                  onClick={() => setActiveTab('nodes')}
                  className={`btn ${activeTab === 'nodes' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.3rem 0.75rem', fontSize: '0.78rem' }}
                >
                  Node List ({filteredNodes.length})
                </button>
                <button
                  onClick={() => setActiveTab('edges')}
                  className={`btn ${activeTab === 'edges' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.3rem 0.75rem', fontSize: '0.78rem' }}
                >
                  Edge Relationships ({filteredEdges.length})
                </button>
              </div>

              {/* Topology / Visual Representation */}
              {activeTab === 'visual' && (
                <div className="glass-panel" style={{ padding: '0.75rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <h3 style={{ fontSize: '0.88rem', fontWeight: 600, margin: 0, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      <Share2 size={14} color="#c084fc" />
                      <span>Interactive Attack Surface Graph {selectedNodeType !== 'ALL' ? `(${selectedNodeType.toUpperCase()})` : ''}</span>
                    </h3>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      Pan & Zoom canvas • Click nodes to inspect in panel
                    </span>
                  </div>

                  {/* High Performance Visual Graph Canvas */}
                  <InteractiveGraphCanvas
                    nodes={filteredNodes}
                    edges={filteredEdges}
                    allNodes={graphData.nodes}
                    allEdges={graphData.edges}
                    selectedNode={selectedNode}
                    onSelectNode={setSelectedNode}
                    selectedNodeType={selectedNodeType}
                    selectedRelType={selectedRelType}
                    searchTerm={searchTerm}
                  />
                </div>
              )}

              {/* Node List Tab */}
              {activeTab === 'nodes' && (
                <div className="glass-panel" style={{ padding: '0.75rem' }}>
                  <div style={{ maxHeight: '480px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
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
                            padding: '0.45rem 0.65rem',
                            borderRadius: '6px',
                            background: isSelected ? 'rgba(168, 85, 247, 0.2)' : 'rgba(30, 41, 59, 0.5)',
                            border: isSelected ? '1px solid #a855f7' : '1px solid var(--border-subtle)',
                            cursor: 'pointer',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 }}>
                            <span
                              className="badge"
                              style={{
                                fontSize: '0.62rem',
                                background: 'rgba(0,0,0,0.3)',
                                color: typeColor,
                                border: `1px solid ${typeColor}`,
                                padding: '0.05rem 0.35rem',
                              }}
                            >
                              {node.type.toUpperCase()}
                            </span>
                            <span style={{ fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {node.label}
                            </span>
                          </div>
                          <Eye size={13} color={isSelected ? '#c084fc' : 'var(--text-muted)'} />
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Edge List Tab */}
              {activeTab === 'edges' && (
                <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
                  <div style={{ maxHeight: '480px', overflowY: 'auto' }}>
                    <table className="data-table" style={{ fontSize: '0.78rem' }}>
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
                            <td
                              onClick={() => findAndSelectNode(edge.source)}
                              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--cyan-400)', cursor: 'pointer' }}
                              title="Click to inspect source node"
                            >
                              {edge.source}
                            </td>
                            <td>
                              <span
                                className="badge"
                                style={{
                                  fontSize: '0.62rem',
                                  background: 'rgba(168, 85, 247, 0.15)',
                                  color: '#c084fc',
                                  border: '1px solid rgba(168, 85, 247, 0.3)',
                                  fontFamily: 'var(--font-mono)',
                                }}
                              >
                                {edge.relationship_type}
                              </span>
                            </td>
                            <td
                              onClick={() => findAndSelectNode(edge.target)}
                              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--cyan-400)', cursor: 'pointer' }}
                              title="Click to inspect target node"
                            >
                              {edge.target}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>

            {/* Right: Selected Node Inspector Panel */}
            <div className="glass-panel" style={{ padding: '1rem 1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.85rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.65rem' }}>
                <GitFork size={16} color="#c084fc" />
                <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Entity Node Inspector
                </h4>
              </div>

              {selectedNode ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Node Identifier</div>
                    <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: '#c084fc', wordBreak: 'break-all' }}>
                      {selectedNode.id}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Entity Type</div>
                      <span
                        className="badge"
                        style={{
                          fontSize: '0.7rem',
                          marginTop: '0.15rem',
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
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Asset UUID</div>
                        <div style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          {selectedNode.asset_id}
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Display Label</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.15rem' }}>
                      {selectedNode.label}
                    </div>
                  </div>

                  {/* Connected Edges */}
                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                      Associated Edges ({graphData.edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).length})
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', maxHeight: '130px', overflowY: 'auto' }}>
                      {graphData.edges
                        .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                        .map(e => (
                          <div
                            key={e.id}
                            style={{
                              background: 'rgba(0,0,0,0.3)',
                              padding: '0.3rem 0.45rem',
                              borderRadius: '4px',
                              fontSize: '0.7rem',
                              fontFamily: 'var(--font-mono)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              gap: '0.4rem'
                            }}
                          >
                            <span
                              onClick={() => findAndSelectNode(e.source)}
                              style={{
                                color: e.source === selectedNode.id ? 'var(--cyan-400)' : 'var(--text-secondary)',
                                cursor: 'pointer',
                                textDecoration: e.source !== selectedNode.id ? 'underline' : 'none'
                              }}
                              title={`Select node ${e.source}`}
                            >
                              {e.source}
                            </span>
                            <span style={{ color: '#c084fc', fontWeight: 600 }}>{e.relationship_type}</span>
                            <span
                              onClick={() => findAndSelectNode(e.target)}
                              style={{
                                color: e.target === selectedNode.id ? 'var(--cyan-400)' : 'var(--text-secondary)',
                                cursor: 'pointer',
                                textDecoration: e.target !== selectedNode.id ? 'underline' : 'none'
                              }}
                              title={`Select node ${e.target}`}
                            >
                              {e.target}
                            </span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* Node Metadata JSON */}
                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Deterministic Metadata</div>
                    <pre
                      style={{
                        background: 'rgba(0, 0, 0, 0.4)',
                        padding: '0.65rem',
                        borderRadius: '6px',
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                        maxHeight: '200px',
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
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', padding: '2.5rem 1rem' }}>
                  Select an entity node from the visual graph or list to view its deterministic attributes and associated edges.
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

export default AttackSurfaceGraphView;
