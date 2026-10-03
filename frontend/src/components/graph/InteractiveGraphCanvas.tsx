import React, { useRef, useEffect, useState, useCallback, useMemo } from 'react';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Compass,
} from 'lucide-react';
import { GraphNode, GraphEdge } from '../../types/api';

export interface InteractiveGraphCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  allNodes?: GraphNode[];
  allEdges: GraphEdge[];
  selectedNode: GraphNode | null;
  onSelectNode: (node: GraphNode | null) => void;
  selectedNodeType: string;
  selectedRelType?: string;
  searchTerm?: string;
}

type LayoutMode = 'hierarchical' | 'radial' | 'grid';

interface PositionedNode {
  node: GraphNode;
  x: number;
  y: number;
  radius: number;
  color: string;
  badge: string;
  tier: number;
}

export const InteractiveGraphCanvas: React.FC<InteractiveGraphCanvasProps> = ({
  nodes,
  edges,
  allEdges,
  selectedNode,
  onSelectNode,
  selectedNodeType,
  searchTerm = '',
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Transform state (Pan & Zoom)
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [hoverPos, setHoverPos] = useState<{ x: number; y: number } | null>(null);

  // Layout & Visibility Settings
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('hierarchical');
  const [maxRenderLimit, setMaxRenderLimit] = useState<number>(350);
  const [showEdgeLabels, setShowEdgeLabels] = useState<boolean>(true);

  // Color mappings
  const getNodeColor = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'domain': return '#38bdf8'; // Cyan
      case 'subdomain': return '#60a5fa'; // Blue
      case 'ip': return '#34d399'; // Emerald
      case 'asn': return '#fbbf24'; // Amber
      case 'service': return '#06b6d4'; // Cyan dark
      case 'technology': return '#a78bfa'; // Purple
      case 'vulnerability': return '#fb7185'; // Rose
      case 'certificate': return '#f472b6'; // Pink
      default: return '#94a3b8';
    }
  }, []);

  const getNodeBadge = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'domain': return 'DOM';
      case 'subdomain': return 'SUB';
      case 'ip': return 'IP';
      case 'asn': return 'ASN';
      case 'service': return 'SVC';
      case 'technology': return 'TECH';
      case 'vulnerability': return 'VULN';
      case 'certificate': return 'CERT';
      default: return 'NODE';
    }
  }, []);

  const getNodeTier = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'domain': return 0;
      case 'subdomain': return 1;
      case 'ip': return 2;
      case 'service': return 2;
      case 'asn': return 3;
      case 'technology': return 3;
      case 'vulnerability': return 4;
      case 'certificate': return 4;
      default: return 2;
    }
  }, []);

  const getEdgeColor = useCallback((relType: string) => {
    switch (relType.toUpperCase()) {
      case 'CONTAINS': return 'rgba(96, 165, 250, 0.6)';
      case 'RESOLVES_TO': return 'rgba(52, 211, 153, 0.7)';
      case 'ANNOUNCED_BY': return 'rgba(251, 191, 36, 0.75)';
      case 'EXPOSES': return 'rgba(6, 182, 212, 0.65)';
      case 'USES_TECHNOLOGY': return 'rgba(167, 139, 250, 0.7)';
      case 'AFFECTED_BY': return 'rgba(251, 113, 133, 0.8)';
      case 'HAS_CERTIFICATE': return 'rgba(244, 114, 182, 0.55)';
      default: return 'rgba(148, 163, 184, 0.4)';
    }
  }, []);

  // Filter and prioritize visible nodes for performance
  const visibleNodes = useMemo(() => {
    // If filtered by specific node type or search term, show all matching nodes
    if (selectedNodeType !== 'ALL' || searchTerm.trim() !== '' || nodes.length <= maxRenderLimit) {
      return nodes.slice(0, maxRenderLimit === 0 ? nodes.length : Math.max(maxRenderLimit, 600));
    }

    // When showing ALL in large dataset (e.g. Netflix 4,867 nodes):
    // Distribute budget evenly across tiers so all layers (Domain, Subdomain, IP, ASN, Service, Tech, Vuln, Cert) are visible!
    const byType: Record<string, GraphNode[]> = {};
    for (const n of nodes) {
      if (!byType[n.type]) byType[n.type] = [];
      byType[n.type].push(n);
    }

    const result: GraphNode[] = [];
    const limits: Record<string, number> = {
      domain: 10,
      asn: 20,
      technology: 40,
      vulnerability: 40,
      service: 50,
      ip: 50,
      subdomain: 80,
      certificate: 50,
    };

    // If a node is currently selected, ensure it and its connected neighbors are in visibleNodes
    const priorityIds = new Set<string>();
    if (selectedNode) {
      priorityIds.add(selectedNode.id);
      for (const e of edges) {
        if (e.source === selectedNode.id) priorityIds.add(e.target);
        if (e.target === selectedNode.id) priorityIds.add(e.source);
      }
    }

    // Add priority nodes first
    for (const n of nodes) {
      if (priorityIds.has(n.id)) {
        result.push(n);
      }
    }

    // Fill remaining budget per category
    for (const [type, typeNodes] of Object.entries(byType)) {
      const limit = limits[type] || 30;
      let count = result.filter(n => n.type === type).length;
      for (const n of typeNodes) {
        if (count >= limit) break;
        if (!priorityIds.has(n.id)) {
          result.push(n);
          count++;
        }
      }
    }

    return result;
  }, [nodes, maxRenderLimit, selectedNodeType, searchTerm, selectedNode, edges]);

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes]);

  // Edges connecting visible nodes or incident to visible nodes
  const visibleEdges = useMemo(() => {
    return edges.filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));
  }, [edges, visibleNodeIds]);

  // Compute node layout positions
  const positionedNodes = useMemo(() => {
    const posMap = new Map<string, PositionedNode>();
    if (visibleNodes.length === 0) return posMap;

    const width = containerRef.current ? containerRef.current.clientWidth : 800;
    const height = containerRef.current ? containerRef.current.clientHeight : 520;

    if (layoutMode === 'hierarchical') {
      // 5 Column Tiers: [Domain] -> [Subdomains] -> [IPs / Services] -> [ASNs / Tech] -> [Vulns / Certs]
      const tiers: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
      for (const n of visibleNodes) {
        const t = getNodeTier(n.type);
        tiers[t].push(n);
      }

      const activeTiers = Object.keys(tiers)
        .map(Number)
        .filter(t => tiers[t].length > 0);

      const numCols = Math.max(activeTiers.length, 1);
      const colWidth = Math.max((width - 160) / Math.max(numCols - 1, 1), 220);

      activeTiers.forEach((t, colIdx) => {
        const colNodes = tiers[t];
        const x = 80 + colIdx * colWidth;
        const count = colNodes.length;

        // Calculate dynamic vertical spacing
        const verticalSpacing = Math.max(38, Math.min(60, (height - 80) / Math.max(count, 1)));
        const totalHeight = count * verticalSpacing;
        const startY = Math.max(50, (height - totalHeight) / 2);

        colNodes.forEach((node, rowIdx) => {
          const y = startY + rowIdx * verticalSpacing;
          const radius = node.type === 'domain' ? 22 : node.type === 'asn' || node.type === 'vulnerability' ? 18 : 14;
          posMap.set(node.id, {
            node,
            x,
            y,
            radius,
            color: getNodeColor(node.type),
            badge: getNodeBadge(node.type),
            tier: t,
          });
        });
      });
    } else if (layoutMode === 'radial') {
      // Concentric circular orbit
      const centerX = width / 2;
      const centerY = height / 2;

      // Group nodes by tier
      const tiers: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
      for (const n of visibleNodes) {
        tiers[getNodeTier(n.type)].push(n);
      }

      // Root domain at center
      if (tiers[0].length > 0) {
        tiers[0].forEach((node, idx) => {
          posMap.set(node.id, {
            node,
            x: centerX + (idx * 40),
            y: centerY,
            radius: 24,
            color: getNodeColor(node.type),
            badge: getNodeBadge(node.type),
            tier: 0,
          });
        });
      }

      // Radial rings
      const radii = [0, Math.min(width, height) * 0.22, Math.min(width, height) * 0.38, Math.min(width, height) * 0.52, Math.min(width, height) * 0.65];
      [1, 2, 3, 4].forEach(t => {
        const ringNodes = tiers[t];
        const count = ringNodes.length;
        if (count === 0) return;
        const ringRadius = radii[t];

        ringNodes.forEach((node, idx) => {
          const angle = (idx / count) * 2 * Math.PI - Math.PI / 2;
          const x = centerX + ringRadius * Math.cos(angle);
          const y = centerY + ringRadius * Math.sin(angle);
          posMap.set(node.id, {
            node,
            x,
            y,
            radius: node.type === 'asn' || node.type === 'vulnerability' ? 18 : 14,
            color: getNodeColor(node.type),
            badge: getNodeBadge(node.type),
            tier: t,
          });
        });
      });
    } else {
      // Grid Layout
      const cols = Math.ceil(Math.sqrt(visibleNodes.length * 1.6));
      const cellW = 180;
      const cellH = 70;
      visibleNodes.forEach((node, idx) => {
        const col = idx % cols;
        const row = Math.floor(idx / cols);
        posMap.set(node.id, {
          node,
          x: 80 + col * cellW,
          y: 60 + row * cellH,
          radius: 16,
          color: getNodeColor(node.type),
          badge: getNodeBadge(node.type),
          tier: getNodeTier(node.type),
        });
      });
    }

    return posMap;
  }, [visibleNodes, layoutMode, getNodeColor, getNodeBadge, getNodeTier]);

  // Fit to view utility
  const handleFitToView = useCallback(() => {
    if (positionedNodes.size === 0 || !containerRef.current) return;
    const containerW = containerRef.current.clientWidth || 800;
    const containerH = containerRef.current.clientHeight || 520;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    positionedNodes.forEach(p => {
      minX = Math.min(minX, p.x - p.radius - 80);
      maxX = Math.max(maxX, p.x + p.radius + 80);
      minY = Math.min(minY, p.y - p.radius - 40);
      maxY = Math.max(maxY, p.y + p.radius + 40);
    });

    const graphW = maxX - minX || 100;
    const graphH = maxY - minY || 100;

    const scaleX = (containerW - 60) / graphW;
    const scaleY = (containerH - 60) / graphH;
    const newZoom = Math.max(0.2, Math.min(1.4, Math.min(scaleX, scaleY)));

    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;

    setZoom(newZoom);
    setPan({
      x: containerW / 2 - centerX * newZoom,
      y: containerH / 2 - centerY * newZoom,
    });
  }, [positionedNodes]);

  // Reset View
  const handleResetView = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    handleFitToView();
  }, [handleFitToView]);

  // Auto-fit on layout or node set change
  useEffect(() => {
    const timer = setTimeout(() => {
      handleFitToView();
    }, 50);
    return () => clearTimeout(timer);
  }, [layoutMode, selectedNodeType, maxRenderLimit]);

  // Connected node IDs for highlighting
  const connectedNodeIds = useMemo(() => {
    if (!selectedNode) return new Set<string>();
    const set = new Set<string>();
    set.add(selectedNode.id);
    for (const e of allEdges) {
      if (e.source === selectedNode.id) set.add(e.target);
      if (e.target === selectedNode.id) set.add(e.source);
    }
    return set;
  }, [selectedNode, allEdges]);

  // Canvas Render Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const width = canvas.parentElement?.clientWidth || 800;
    const height = canvas.parentElement?.clientHeight || 520;

    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    ctx.save();
    ctx.scale(dpr, dpr);

    // Background
    ctx.fillStyle = '#090d16';
    ctx.fillRect(0, 0, width, height);

    // Draw Subtle Grid Dots
    ctx.save();
    ctx.fillStyle = 'rgba(56, 189, 248, 0.04)';
    const gridSize = 32 * zoom;
    const offsetX = pan.x % gridSize;
    const offsetY = pan.y % gridSize;
    for (let gx = offsetX; gx < width; gx += gridSize) {
      for (let gy = offsetY; gy < height; gy += gridSize) {
        ctx.beginPath();
        ctx.arc(gx, gy, 1, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    ctx.restore();

    // Apply Pan & Zoom Transform
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    // 1. Draw Edges
    for (const edge of visibleEdges) {
      const src = positionedNodes.get(edge.source);
      const tgt = positionedNodes.get(edge.target);
      if (!src || !tgt) continue;

      const isConnectedToSelected = selectedNode && (edge.source === selectedNode.id || edge.target === selectedNode.id);
      const isDimmed = selectedNode && !isConnectedToSelected;

      ctx.save();
      ctx.beginPath();

      // Curved or straight edge
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const angle = Math.atan2(dy, dx);

      // Clip arrow at node border
      const startX = src.x + Math.cos(angle) * src.radius;
      const startY = src.y + Math.sin(angle) * src.radius;
      const endX = tgt.x - Math.cos(angle) * (tgt.radius + 4);
      const endY = tgt.y - Math.sin(angle) * (tgt.radius + 4);

      if (layoutMode === 'hierarchical') {
        const cp1x = startX + (endX - startX) * 0.5;
        const cp1y = startY;
        const cp2x = startX + (endX - startX) * 0.5;
        const cp2y = endY;

        ctx.moveTo(startX, startY);
        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, endX, endY);
      } else {
        ctx.moveTo(startX, startY);
        ctx.lineTo(endX, endY);
      }

      ctx.strokeStyle = isConnectedToSelected
        ? '#c084fc'
        : isDimmed
        ? 'rgba(148, 163, 184, 0.12)'
        : getEdgeColor(edge.relationship_type);
      ctx.lineWidth = isConnectedToSelected ? 2.5 : isDimmed ? 1 : 1.4;
      ctx.stroke();

      // Draw Arrow Head
      const arrowLen = isConnectedToSelected ? 9 : 7;
      ctx.fillStyle = ctx.strokeStyle;
      ctx.beginPath();
      ctx.moveTo(endX, endY);
      ctx.lineTo(
        endX - arrowLen * Math.cos(angle - Math.PI / 7),
        endY - arrowLen * Math.sin(angle - Math.PI / 7)
      );
      ctx.lineTo(
        endX - arrowLen * Math.cos(angle + Math.PI / 7),
        endY - arrowLen * Math.sin(angle + Math.PI / 7)
      );
      ctx.closePath();
      ctx.fill();

      // Draw Edge Label (when zoomed in or hovered)
      if (showEdgeLabels && (zoom >= 0.75 || isConnectedToSelected) && dist > 70) {
        const midX = (startX + endX) / 2;
        const midY = (startY + endY) / 2;

        ctx.font = '9px monospace';
        ctx.fillStyle = isConnectedToSelected ? '#e9d5ff' : 'rgba(203, 213, 225, 0.75)';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        // Label background pill
        const labelText = edge.relationship_type;
        const textWidth = ctx.measureText(labelText).width;
        ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
        ctx.fillRect(midX - textWidth / 2 - 4, midY - 6, textWidth + 8, 12);

        ctx.fillStyle = isConnectedToSelected ? '#c084fc' : 'rgba(148, 163, 184, 0.85)';
        ctx.fillText(labelText, midX, midY);
      }

      ctx.restore();
    }

    // 2. Draw Nodes
    positionedNodes.forEach(p => {
      const isSelected = selectedNode?.id === p.node.id;
      const isConnected = connectedNodeIds.has(p.node.id);
      const isHovered = hoveredNode?.id === p.node.id;
      const isDimmed = selectedNode && !isConnected;

      ctx.save();

      // Selected / Hovered Halo Glow
      if (isSelected || isHovered) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius + 8, 0, Math.PI * 2);
        ctx.fillStyle = isSelected ? 'rgba(168, 85, 247, 0.28)' : 'rgba(56, 189, 248, 0.2)';
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#c084fc' : '#38bdf8';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Node Body Circle
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = isDimmed ? 'rgba(30, 41, 59, 0.6)' : 'rgba(15, 23, 42, 0.95)';
      ctx.fill();

      ctx.strokeStyle = isDimmed ? 'rgba(100, 116, 139, 0.3)' : isSelected ? '#a855f7' : p.color;
      ctx.lineWidth = isSelected ? 3 : 2;
      ctx.stroke();

      // Inner Badge Glyph
      ctx.font = `bold ${p.radius >= 20 ? 10 : 8}px sans-serif`;
      ctx.fillStyle = isDimmed ? 'rgba(148, 163, 184, 0.4)' : p.color;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(p.badge, p.x, p.y);

      // Node Label (underneath)
      if (zoom >= 0.5 || isSelected || isHovered || p.node.type === 'domain') {
        ctx.font = `${isSelected ? 'bold 11px' : '10px'} -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';

        // Truncate label if too long
        let label = p.node.label;
        if (label.length > 24 && !isSelected && !isHovered) {
          label = label.slice(0, 22) + '…';
        }

        const textMetrics = ctx.measureText(label);
        const bgWidth = textMetrics.width + 8;
        const bgHeight = 14;

        // Label background for contrast
        ctx.fillStyle = isSelected ? 'rgba(147, 51, 234, 0.25)' : 'rgba(8, 12, 22, 0.85)';
        ctx.fillRect(p.x - bgWidth / 2, p.y + p.radius + 3, bgWidth, bgHeight);

        if (isSelected) {
          ctx.strokeStyle = '#a855f7';
          ctx.lineWidth = 1;
          ctx.strokeRect(p.x - bgWidth / 2, p.y + p.radius + 3, bgWidth, bgHeight);
        }

        ctx.fillStyle = isSelected ? '#f8fafc' : isDimmed ? 'rgba(148, 163, 184, 0.5)' : '#e2e8f0';
        ctx.fillText(label, p.x, p.y + p.radius + 4);
      }

      ctx.restore();
    });

    ctx.restore();
  }, [
    positionedNodes,
    visibleEdges,
    pan,
    zoom,
    selectedNode,
    hoveredNode,
    connectedNodeIds,
    layoutMode,
    showEdgeLabels,
    getEdgeColor,
  ]);

  // Mouse / Pointer Event Handlers for Canvas
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (e.button !== 0) return; // Only main left click
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
      return;
    }

    // Hit-testing for Hover
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const worldX = (mouseX - pan.x) / zoom;
    const worldY = (mouseY - pan.y) / zoom;

    let found: GraphNode | null = null;
    positionedNodes.forEach(p => {
      const dx = worldX - p.x;
      const dy = worldY - p.y;
      if (dx * dx + dy * dy <= (p.radius + 6) * (p.radius + 6)) {
        found = p.node;
      }
    });

    setHoveredNode(found);
    if (found) {
      setHoverPos({ x: mouseX + 12, y: mouseY + 12 });
    } else {
      setHoverPos(null);
    }
  };

  const handleMouseUp = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDragging) return;
    setIsDragging(false);

    // If mouse didn't drag significantly, treat as Click
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const worldX = (mouseX - pan.x) / zoom;
    const worldY = (mouseY - pan.y) / zoom;

    let clickedNode: GraphNode | null = null;
    positionedNodes.forEach(p => {
      const dx = worldX - p.x;
      const dy = worldY - p.y;
      if (dx * dx + dy * dy <= (p.radius + 8) * (p.radius + 8)) {
        clickedNode = p.node;
      }
    });

    onSelectNode(clickedNode);
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
    const newZoom = Math.min(Math.max(zoom * zoomFactor, 0.15), 4.5);

    setPan({
      x: mouseX - (mouseX - pan.x) * (newZoom / zoom),
      y: mouseY - (mouseY - pan.y) * (newZoom / zoom),
    });
    setZoom(newZoom);
  };

  return (
    <div
      ref={containerRef}
      style={{
        position: 'relative',
        width: '100%',
        height: '520px',
        background: '#090d16',
        borderRadius: '10px',
        border: '1px solid var(--border-subtle)',
        overflow: 'hidden',
        userSelect: 'none',
      }}
    >
      {/* Canvas Element */}
      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onWheel={handleWheel}
        style={{
          width: '100%',
          height: '100%',
          cursor: isDragging ? 'grabbing' : hoveredNode ? 'pointer' : 'grab',
          display: 'block',
        }}
      />

      {/* Top Controls Overlay */}
      <div
        style={{
          position: 'absolute',
          top: '0.75rem',
          left: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          background: 'rgba(15, 23, 42, 0.85)',
          backdropFilter: 'blur(10px)',
          padding: '0.35rem 0.65rem',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          <Compass size={14} color="#38bdf8" />
          <span>Layout:</span>
        </div>
        <select
          value={layoutMode}
          onChange={e => setLayoutMode(e.target.value as LayoutMode)}
          className="form-input"
          style={{
            padding: '0.15rem 0.5rem',
            fontSize: '0.72rem',
            background: 'rgba(30, 41, 59, 0.8)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-primary)',
            width: 'auto',
          }}
        >
          <option value="hierarchical">Hierarchical Tier Flow</option>
          <option value="radial">Concentric Radial Orbit</option>
          <option value="grid">Structured Matrix</option>
        </select>

        {nodes.length > 250 && selectedNodeType === 'ALL' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', marginLeft: '0.4rem', borderLeft: '1px solid var(--border-subtle)', paddingLeft: '0.5rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Render Budget:</span>
            <select
              value={maxRenderLimit}
              onChange={e => setMaxRenderLimit(Number(e.target.value))}
              className="form-input"
              style={{
                padding: '0.15rem 0.4rem',
                fontSize: '0.72rem',
                background: 'rgba(30, 41, 59, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
                width: 'auto',
              }}
            >
              <option value={200}>200 Nodes</option>
              <option value={350}>350 Nodes (Fast)</option>
              <option value={600}>600 Nodes (Dense)</option>
              <option value={0}>All ({nodes.length})</option>
            </select>
          </div>
        )}
      </div>

      {/* Floating Status Indicator (Visible Node Count / Filter Info) */}
      <div
        style={{
          position: 'absolute',
          top: '0.75rem',
          right: '0.75rem',
          background: 'rgba(15, 23, 42, 0.85)',
          backdropFilter: 'blur(10px)',
          padding: '0.35rem 0.65rem',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          fontSize: '0.72rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          zIndex: 10,
        }}
      >
        <span style={{ color: 'var(--cyan-400)', fontWeight: 600 }}>
          {positionedNodes.size} / {nodes.length} Nodes Rendered
        </span>
        <span style={{ color: 'var(--text-muted)' }}>•</span>
        <span style={{ color: 'var(--text-secondary)' }}>
          {visibleEdges.length} / {edges.length} Edges
        </span>
        <button
          onClick={() => setShowEdgeLabels(!showEdgeLabels)}
          className="badge"
          style={{
            cursor: 'pointer',
            background: showEdgeLabels ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.6)',
            border: `1px solid ${showEdgeLabels ? 'var(--cyan-400)' : 'var(--border-subtle)'}`,
            color: showEdgeLabels ? 'var(--cyan-400)' : 'var(--text-muted)',
            fontSize: '0.68rem',
            padding: '0.1rem 0.35rem',
          }}
        >
          {showEdgeLabels ? 'Labels: ON' : 'Labels: OFF'}
        </button>
      </div>

      {/* Bottom Floating Navigation Toolbar */}
      <div
        style={{
          position: 'absolute',
          bottom: '0.75rem',
          right: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.35rem',
          background: 'rgba(15, 23, 42, 0.85)',
          backdropFilter: 'blur(10px)',
          padding: '0.3rem 0.45rem',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          zIndex: 10,
        }}
      >
        <button
          onClick={() => setZoom(z => Math.min(z * 1.25, 4.5))}
          title="Zoom In"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            padding: '0.25rem',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <ZoomIn size={15} />
        </button>
        <button
          onClick={() => setZoom(z => Math.max(z * 0.8, 0.15))}
          title="Zoom Out"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            padding: '0.25rem',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <ZoomOut size={15} />
        </button>
        <button
          onClick={handleFitToView}
          title="Fit Graph to View"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            padding: '0.25rem',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <Maximize2 size={15} />
        </button>
        <button
          onClick={handleResetView}
          title="Reset Layout & View"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            padding: '0.25rem',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <RotateCcw size={15} />
        </button>
      </div>

      {/* Hover Node Tooltip */}
      {hoveredNode && hoverPos && (
        <div
          style={{
            position: 'absolute',
            left: `${hoverPos.x}px`,
            top: `${hoverPos.y}px`,
            background: 'rgba(15, 23, 42, 0.95)',
            border: `1px solid ${getNodeColor(hoveredNode.type)}`,
            borderRadius: '6px',
            padding: '0.5rem 0.75rem',
            pointerEvents: 'none',
            zIndex: 100,
            boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6)',
            maxWidth: '260px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
            <span
              className="badge"
              style={{
                fontSize: '0.62rem',
                background: 'rgba(0,0,0,0.4)',
                color: getNodeColor(hoveredNode.type),
                border: `1px solid ${getNodeColor(hoveredNode.type)}`,
                textTransform: 'uppercase',
                fontWeight: 700,
              }}
            >
              {hoveredNode.type}
            </span>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {hoveredNode.label}
            </span>
          </div>
          <div style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
            ID: {hoveredNode.id}
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Click to inspect in Entity Inspector
          </div>
        </div>
      )}
    </div>
  );
};

export default InteractiveGraphCanvas;
