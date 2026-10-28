import React, { useState, useMemo, useRef } from 'react';
import {
  Network,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  User,
  Database,
  Lock,
  Key,
  X,
  Sparkles,
  Bot,
  Clock,
  History,
  AlertOctagon,
  ArrowRight,
  Info,
} from 'lucide-react';
import { IAMDataSet, Principal, Resource, GraphEdge, IdentityRiskMetrics } from '../../types/iam';
import { TabKey } from '../layout/Navbar';

interface AccessGraphCanvasProps {
  dataset: IAMDataSet;
  riskMetrics: Map<string, IdentityRiskMetrics>;
  highlightedPathNodeIds?: string[];
  onSelectPrincipalForSimulation: (principalId: string) => void;
  onSelectPrincipalForRemediation: (principalId: string) => void;
  onNavigateTab: (tab: TabKey) => void;
}

interface NodeLayout {
  id: string;
  name: string;
  type: 'User' | 'Role' | 'ServiceAccount' | 'Group' | 'Resource';
  subType?: string;
  isCrownJewel?: boolean;
  sensitivity?: string;
  provider: string;
  x: number;
  y: number;
  riskScore: number;
  isUnused: boolean;
  roles: string[];
  permissionsCount: number;
}

interface EdgeClassification {
  id: string;
  source: string;
  target: string;
  sourceName: string;
  targetName: string;
  colorType: 'GREEN' | 'YELLOW' | 'RED';
  colorHex: string;
  permission: string;
  warningMessage?: string;
  sourceUnused: boolean;
  targetUnused: boolean;
  sourceNode: NodeLayout;
  targetNode: NodeLayout;
}

export const AccessGraphCanvas: React.FC<AccessGraphCanvasProps> = ({
  dataset,
  riskMetrics,
  highlightedPathNodeIds = [],
  onSelectPrincipalForSimulation,
  onSelectPrincipalForRemediation,
  onNavigateTab,
}) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [providerFilter, setProviderFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');

  // Pop-up modals
  const [historyModalPrincipalId, setHistoryModalPrincipalId] = useState<string | null>(null);
  const [selectedEdgeWarning, setSelectedEdgeWarning] = useState<EdgeClassification | null>(null);

  // AI Helping Box state
  const [aiSelectedIdentityName, setAiSelectedIdentityName] = useState<string>(
    dataset.principals[0]?.name || ''
  );
  const [aiReportGenerated, setAiReportGenerated] = useState<boolean>(true);

  const containerRef = useRef<HTMLDivElement>(null);
  const isDraggingRef = useRef(false);
  const dragStartRef = useRef({ x: 0, y: 0 });

  // Helper: Determine if principal is unused / dormant
  const checkIsPrincipalUnused = (p: Principal) => {
    return p.daysInactive >= 90 || p.grantedPermissions.every((perm) => !perm.isUsed);
  };

  // Calculate layout coordinates for all nodes in the dataset
  const layoutNodes = useMemo(() => {
    const nodes: NodeLayout[] = [];
    const width = 1100;
    const height = Math.max(680, dataset.principals.length * 34);

    const filteredPrincipals = dataset.principals.filter((p) => {
      const matchProvider = providerFilter === 'ALL' || p.provider === providerFilter;
      const matchType = typeFilter === 'ALL' || p.type === typeFilter;
      const matchSearch =
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.arn.toLowerCase().includes(searchQuery.toLowerCase());
      return matchProvider && matchType && matchSearch;
    });

    const filteredResources = dataset.resources.filter((r) => {
      const matchProvider = providerFilter === 'ALL' || r.provider === providerFilter;
      const matchType =
        typeFilter === 'ALL' ||
        (typeFilter === 'CrownJewel' ? r.isCrownJewel : typeFilter === 'Resource');
      const matchSearch =
        r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.arn.toLowerCase().includes(searchQuery.toLowerCase());
      return matchProvider && matchType && matchSearch;
    });

    // Column 1: Users & Service Accounts (x: 160)
    const userNodes = filteredPrincipals.filter(
      (p) => p.type === 'User' || p.type === 'ServiceAccount'
    );
    userNodes.forEach((p, idx) => {
      const ySpacing = height / (userNodes.length + 1);
      nodes.push({
        id: p.id,
        name: p.name,
        type: p.type,
        provider: p.provider,
        x: 170,
        y: (idx + 1) * ySpacing,
        riskScore: riskMetrics.get(p.id)?.compositeRiskScore || 15,
        isUnused: checkIsPrincipalUnused(p),
        roles: p.attachedPolicies || [],
        permissionsCount: p.grantedPermissions.length,
      });
    });

    // Column 2: Roles & Groups (x: 550)
    const roleNodes = filteredPrincipals.filter(
      (p) => p.type === 'Role' || p.type === 'Group'
    );
    roleNodes.forEach((p, idx) => {
      const ySpacing = height / (roleNodes.length + 1);
      nodes.push({
        id: p.id,
        name: p.name,
        type: p.type,
        provider: p.provider,
        x: 550,
        y: (idx + 1) * ySpacing,
        riskScore: riskMetrics.get(p.id)?.compositeRiskScore || 25,
        isUnused: checkIsPrincipalUnused(p),
        roles: p.attachedPolicies || [],
        permissionsCount: p.grantedPermissions.length,
      });
    });

    // Column 3: Resources (x: 920)
    filteredResources.forEach((r, idx) => {
      const ySpacing = height / (filteredResources.length + 1);
      nodes.push({
        id: r.id,
        name: r.name,
        type: 'Resource',
        subType: r.type,
        isCrownJewel: r.isCrownJewel,
        sensitivity: r.sensitivity,
        provider: r.provider,
        x: 930,
        y: (idx + 1) * ySpacing,
        riskScore: r.isCrownJewel ? 95 : 30,
        isUnused: false,
        roles: [],
        permissionsCount: 0,
      });
    });

    return nodes;
  }, [dataset, riskMetrics, providerFilter, typeFilter, searchQuery]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, NodeLayout>();
    layoutNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [layoutNodes]);

  // Classified Edges with the three required link colors:
  // 1. GREEN: Active user identity to active secure target
  // 2. YELLOW: Active user identity connected with unused identity (Warning: should be solved soon)
  // 3. RED: Two unused identities connected together (Alert: should be removed/solved immediately)
  const classifiedEdges = useMemo(() => {
    const edges: EdgeClassification[] = [];

    for (const e of dataset.edges) {
      const sourceNode = nodeMap.get(e.source);
      const targetNode = nodeMap.get(e.target);

      if (!sourceNode || !targetNode) continue;

      const sourceUnused = sourceNode.isUnused;
      const targetUnused = targetNode.isUnused;
      const permission = e.permissions?.[0] || e.label || e.type.replace(/_/g, ' ');

      let colorType: 'GREEN' | 'YELLOW' | 'RED' = 'GREEN';
      let colorHex = '#10b981'; // Green
      let warningMessage: string | undefined = undefined;

      if (sourceUnused && targetUnused) {
        // Red link: Two unused identities connected together
        colorType = 'RED';
        colorHex = '#ef4444';
        warningMessage = `CRITICAL ALERT: Two unused/dormant identities ("${sourceNode.name}" and "${targetNode.name}") are connected via "${permission}". This forms an unmonitored shadow backdoor path and should be removed or severed immediately!`;
      } else if (sourceUnused || targetUnused) {
        // Yellow link: Active user identity connected with unused identity
        colorType = 'YELLOW';
        colorHex = '#eab308';
        warningMessage = `WARNING: Active identity is connected with unused/dormant identity ("${sourceNode.name}" -> "${targetNode.name}"). Potential lateral movement risk. This trust relationship should be solved soon!`;
      } else {
        // Green link: Active secure connection
        colorType = 'GREEN';
        colorHex = '#10b981';
      }

      edges.push({
        id: e.id,
        source: e.source,
        target: e.target,
        sourceName: sourceNode.name,
        targetName: targetNode.name,
        colorType,
        colorHex,
        permission,
        warningMessage,
        sourceUnused,
        targetUnused,
        sourceNode,
        targetNode,
      });
    }

    return edges;
  }, [dataset.edges, nodeMap]);

  // Find currently inspected principal for Full History Pop-up Box
  const historyPrincipal = useMemo(() => {
    if (!historyModalPrincipalId) return null;
    return dataset.principals.find((p) => p.id === historyModalPrincipalId) || null;
  }, [historyModalPrincipalId, dataset.principals]);

  // Find AI target principal
  const aiPrincipal = useMemo(() => {
    return (
      dataset.principals.find(
        (p) =>
          p.name.toLowerCase() === aiSelectedIdentityName.toLowerCase() ||
          p.id.toLowerCase() === aiSelectedIdentityName.toLowerCase()
      ) || dataset.principals[0]
    );
  }, [aiSelectedIdentityName, dataset.principals]);

  // Mouse pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).tagName === 'rect') {
      isDraggingRef.current = true;
      dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDraggingRef.current) {
      setPan({
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y,
      });
    }
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  // Generate AI security report content dynamically for aiPrincipal
  const aiReport = useMemo(() => {
    if (!aiPrincipal) return null;

    const m = riskMetrics.get(aiPrincipal.id);
    const isUnused = checkIsPrincipalUnused(aiPrincipal);
    const score = m?.compositeRiskScore || 0;
    const isDangerous = score >= 50 || isUnused || m?.wildcardPermissions.length! > 0 || aiPrincipal.grantedPermissions.some((p) => p.action.includes('PassRole'));

    const dangerousPerms = aiPrincipal.grantedPermissions.filter(
      (p) => p.isDangerous || p.action.includes('*') || p.action.includes('PassRole') || p.action.includes('AssumeRole')
    );

    const usedActions = aiPrincipal.grantedPermissions.filter((p) => p.isUsed);
    const unusedActions = aiPrincipal.grantedPermissions.filter((p) => !p.isUsed);

    // Filter relevant CloudTrail logs for this identity
    const identityAuditLogs = dataset.cloudTrailEvents.filter(
      (ev) => ev.principalId === aiPrincipal.id || ev.principalId === aiPrincipal.name
    );

    return {
      principal: aiPrincipal,
      metrics: m,
      isUnused,
      score,
      isDangerous,
      dangerousPerms,
      usedActions,
      unusedActions,
      identityAuditLogs,
      verdict: isDangerous ? 'DANGEROUS / HIGH RISK' : 'SAFE / RIGHT-SIZED',
    };
  }, [aiPrincipal, riskMetrics, dataset.cloudTrailEvents]);

  return (
    <div className="space-y-6">
      {/* Topology Control Header & Link Color Legend */}
      <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-xl space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search identity, role, or resource..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-52 sm:w-64"
              />
            </div>

            {/* Provider Filter */}
            <select
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">Provider: All</option>
              <option value="AWS">AWS</option>
              <option value="Azure">Azure</option>
              <option value="GCP">GCP</option>
            </select>

            {/* Type Filter */}
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">Type: All Entities</option>
              <option value="User">Users</option>
              <option value="Role">Roles</option>
              <option value="ServiceAccount">Service Accounts</option>
              <option value="CrownJewel">Crown Jewels</option>
            </select>
          </div>

          {/* Zoom & Fit Controls */}
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setZoom((z) => Math.min(2.2, z + 0.15))}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 cursor-pointer"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.4, z - 0.15))}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 cursor-pointer"
              title="Reset Pan & Zoom"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* 3 Link Color Legend & Node Status Explanation */}
        <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-slate-800/80 text-xs font-mono">
          <span className="text-slate-400 font-semibold uppercase text-[10px]">Relationship Link Status:</span>
          
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-1 rounded bg-emerald-400" />
            <span className="text-emerald-300">Green: Active Secure Identities</span>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="w-3 h-1 rounded bg-amber-400" />
            <span className="text-amber-300">Yellow: Active Connected to Unused (Warning: Solve Soon)</span>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="w-3 h-1 rounded bg-rose-500" />
            <span className="text-rose-400">Red: Two Unused Connected (Alert: Remove Immediately)</span>
          </div>
        </div>
      </div>

      {/* Main Interactive Topology Canvas */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        className="relative bg-slate-950 border border-slate-800 rounded-2xl h-[620px] overflow-hidden cursor-grab active:cursor-grabbing select-none shadow-inner"
      >
        <svg
          className="w-full h-full"
          viewBox="0 0 1100 680"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '50% 50%',
          }}
        >
          <defs>
            <marker
              id="arrow-green"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
            </marker>
            <marker
              id="arrow-yellow"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#eab308" />
            </marker>
            <marker
              id="arrow-red"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
            </marker>
            <filter id="glow-gold" x="-50%" y="-50%" width="200%" height="200%">
              <feDropShadow dx="0" dy="0" stdDeviation="6" floodColor="#f59e0b" floodOpacity="0.8" />
            </filter>
            <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
              <feDropShadow dx="0" dy="0" stdDeviation="6" floodColor="#ef4444" floodOpacity="0.8" />
            </filter>
          </defs>

          {/* Background grid */}
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
          </pattern>
          <rect width="100%" height="100%" fill="url(#grid)" />

          {/* Render Classified Edges with Hover & Click Warnings */}
          {classifiedEdges.map((e) => {
            const isHighlighted =
              highlightedPathNodeIds.includes(e.source) && highlightedPathNodeIds.includes(e.target);

            // Compute curved bezier path
            const dx = e.targetNode.x - e.sourceNode.x;
            const dy = e.targetNode.y - e.sourceNode.y;
            const cx = e.sourceNode.x + dx * 0.5;
            const cy = e.sourceNode.y + dy * 0.15;

            const strokeColor = isHighlighted ? '#06b6d4' : e.colorHex;
            const markerId =
              isHighlighted
                ? 'arrow-green'
                : e.colorType === 'RED'
                ? 'url(#arrow-red)'
                : e.colorType === 'YELLOW'
                ? 'url(#arrow-yellow)'
                : 'url(#arrow-green)';

            return (
              <g
                key={e.id}
                className="cursor-pointer group"
                onClick={() => {
                  if (e.warningMessage) {
                    setSelectedEdgeWarning(e);
                  }
                }}
              >
                {/* Wider invisible stroke for easy clicking/hovering */}
                <path
                  d={`M ${e.sourceNode.x} ${e.sourceNode.y} Q ${cx} ${cy} ${e.targetNode.x} ${e.targetNode.y}`}
                  fill="none"
                  stroke="transparent"
                  strokeWidth="12"
                />

                {/* Visible colored edge */}
                <path
                  d={`M ${e.sourceNode.x} ${e.sourceNode.y} Q ${cx} ${cy} ${e.targetNode.x} ${e.targetNode.y}`}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={isHighlighted ? 3.5 : e.colorType === 'RED' ? 2.5 : e.colorType === 'YELLOW' ? 2 : 1.5}
                  strokeDasharray={e.colorType === 'RED' ? '5,4' : undefined}
                  markerEnd={markerId}
                  className="transition-all group-hover:stroke-width-3"
                />

                {/* Edge Permission Label */}
                <text
                  x={cx}
                  y={cy - 6}
                  fill={isHighlighted ? '#22d3ee' : e.colorType === 'RED' ? '#fca5a5' : e.colorType === 'YELLOW' ? '#fde047' : '#86efac'}
                  fontSize="8.5"
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="pointer-events-none select-none drop-shadow"
                >
                  {e.permission}
                </text>
              </g>
            );
          })}

          {/* Render Nodes with Roles & Permissions Indicators */}
          {layoutNodes.map((n) => {
            const isCrown = n.isCrownJewel;
            const isPathNode = highlightedPathNodeIds.includes(n.id);

            let fillColor = '#1e293b';
            let strokeColor = '#475569';
            let filter = undefined;

            if (isCrown) {
              fillColor = '#78350f';
              strokeColor = '#f59e0b';
              filter = 'url(#glow-gold)';
            } else if (n.type === 'Role' || n.type === 'Group') {
              fillColor = '#3b0764';
              strokeColor = '#a855f7';
            } else if (n.riskScore >= 75) {
              fillColor = '#881337';
              strokeColor = '#f43f5e';
              filter = 'url(#glow-red)';
            } else if (n.riskScore >= 45) {
              fillColor = '#713f12';
              strokeColor = '#eab308';
            } else {
              fillColor = '#064e3b';
              strokeColor = '#10b981';
            }

            return (
              <g
                key={n.id}
                transform={`translate(${n.x}, ${n.y})`}
                onClick={(e) => {
                  e.stopPropagation();
                  setHistoryModalPrincipalId(n.id);
                  setAiSelectedIdentityName(n.name);
                }}
                className="cursor-pointer group"
              >
                {/* Node Shape */}
                {n.type === 'Role' || n.type === 'Group' ? (
                  <rect
                    x="-55"
                    y="-22"
                    width="110"
                    height="44"
                    rx="8"
                    fill={fillColor}
                    stroke={isPathNode ? '#06b6d4' : strokeColor}
                    strokeWidth={isPathNode ? 3 : 1.5}
                    className="transition-all group-hover:scale-105"
                  />
                ) : (
                  <circle
                    r={isCrown ? 26 : 22}
                    fill={fillColor}
                    stroke={isPathNode ? '#06b6d4' : strokeColor}
                    strokeWidth={isPathNode ? 3.5 : 2}
                    filter={filter}
                    className="transition-all group-hover:scale-110"
                  />
                )}

                {/* Node Label / Glyph */}
                <text
                  textAnchor="middle"
                  dy={n.type === 'Role' || n.type === 'Group' ? -2 : 4}
                  fill="#ffffff"
                  fontSize="10"
                  fontWeight="bold"
                  fontFamily="monospace"
                  className="pointer-events-none select-none"
                >
                  {isCrown ? '👑' : n.type === 'Role' ? 'ROLE' : n.type === 'User' ? 'USER' : 'SVC'}
                </text>

                {/* Label Under Node */}
                <text
                  textAnchor="middle"
                  dy={n.type === 'Role' || n.type === 'Group' ? 32 : 36}
                  fill="#e2e8f0"
                  fontSize="10"
                  fontFamily="sans-serif"
                  fontWeight="600"
                  className="pointer-events-none select-none drop-shadow"
                >
                  {n.name.length > 18 ? n.name.substring(0, 16) + '...' : n.name}
                </text>

                {/* Status indicator: Active vs Unused */}
                {!isCrown && (
                  <text
                    textAnchor="middle"
                    dy={n.type === 'Role' || n.type === 'Group' ? 12 : -28}
                    fill={n.isUnused ? '#f43f5e' : '#34d399'}
                    fontSize="8.5"
                    fontFamily="monospace"
                    className="pointer-events-none"
                  >
                    {n.isUnused ? 'UNUSED (STALE)' : 'ACTIVE'}
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* EDGE WARNING POPUP MODAL (When yellow or red link is clicked) */}
        {selectedEdgeWarning && (
          <div className="absolute top-4 left-4 right-4 sm:left-auto sm:right-6 sm:w-96 z-30 bg-slate-900 border border-slate-700 rounded-xl p-4 shadow-2xl space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {selectedEdgeWarning.colorType === 'RED' ? (
                  <AlertOctagon className="w-5 h-5 text-rose-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                )}
                <span className="font-bold text-white text-xs uppercase font-mono">
                  {selectedEdgeWarning.colorType === 'RED'
                    ? 'CRITICAL BACKDOOR ALERT'
                    : 'TRUST PATH WARNING'}
                </span>
              </div>
              <button
                onClick={() => setSelectedEdgeWarning(null)}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-200 leading-relaxed">
              {selectedEdgeWarning.warningMessage}
            </p>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono space-y-1">
              <div className="text-slate-400">
                Source: <span className="text-slate-200">{selectedEdgeWarning.sourceName}</span> (
                {selectedEdgeWarning.sourceUnused ? 'UNUSED' : 'ACTIVE'})
              </div>
              <div className="text-slate-400">
                Target: <span className="text-slate-200">{selectedEdgeWarning.targetName}</span> (
                {selectedEdgeWarning.targetUnused ? 'UNUSED' : 'ACTIVE'})
              </div>
              <div className="text-slate-400">
                Permission: <span className="text-rose-300 font-bold">{selectedEdgeWarning.permission}</span>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <button
                onClick={() => {
                  setAiSelectedIdentityName(selectedEdgeWarning.sourceName);
                  setSelectedEdgeWarning(null);
                }}
                className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold cursor-pointer"
              >
                Investigate in AI Assistant
              </button>
            </div>
          </div>
        )}
      </div>

      {/* POP-UP BOX: FULL HISTORY OF CLICKED IDENTITY */}
      {historyPrincipal && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[88vh] overflow-hidden flex flex-col shadow-2xl">
            {/* Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400">
                  <User className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <span>{historyPrincipal.name}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                        checkIsPrincipalUnused(historyPrincipal)
                          ? 'bg-purple-950 text-purple-300 border border-purple-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}
                    >
                      {checkIsPrincipalUnused(historyPrincipal) ? 'STATUS: UNUSED' : 'STATUS: ACTIVE'}
                    </span>
                  </h3>
                  <p className="text-xs font-mono text-cyan-300 truncate max-w-lg mt-0.5">
                    {historyPrincipal.arn}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setHistoryModalPrincipalId(null)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
              {/* Key Attributes Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-[10px] uppercase font-mono text-slate-400">Identity Type</div>
                  <div className="font-bold text-white mt-1">{historyPrincipal.type}</div>
                  <div className="text-[10px] text-slate-500">{historyPrincipal.provider}</div>
                </div>

                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-[10px] uppercase font-mono text-slate-400">Inactivity Duration</div>
                  <div className={`font-bold mt-1 ${historyPrincipal.daysInactive > 90 ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {historyPrincipal.daysInactive} Days
                  </div>
                  <div className="text-[10px] text-slate-500">
                    Last active: {new Date(historyPrincipal.lastActiveTimestamp).toLocaleDateString()}
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-[10px] uppercase font-mono text-slate-400">MFA Status</div>
                  <div className="font-bold text-white mt-1">
                    {historyPrincipal.mfaEnabled ? (
                      <span className="text-emerald-400">Enforced</span>
                    ) : (
                      <span className="text-rose-400 font-bold">Disabled (High Risk)</span>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-500">Hardware / TOTP</div>
                </div>

                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-[10px] uppercase font-mono text-slate-400">Access Keys</div>
                  <div className="font-bold text-white mt-1">{historyPrincipal.accessKeysCount} Active Keys</div>
                  <div className="text-[10px] text-amber-400">
                    {historyPrincipal.unrotatedKeysCount} Unrotated (&gt;90d)
                  </div>
                </div>
              </div>

              {/* Roles & Attached Policies */}
              <div className="space-y-2">
                <div className="font-semibold text-white uppercase font-mono text-[11px] flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Associated Roles & Attached IAM Policies</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {historyPrincipal.attachedPolicies && historyPrincipal.attachedPolicies.length > 0 ? (
                    historyPrincipal.attachedPolicies.map((pol, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-purple-300"
                      >
                        {pol}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500">No attached managed policies found.</span>
                  )}
                </div>
              </div>

              {/* Full Permissions Breakdown (Used vs Unused) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span className="font-semibold text-white uppercase">
                    Configured Permissions ({historyPrincipal.grantedPermissions.length})
                  </span>
                  <span className="text-slate-400">
                    {historyPrincipal.grantedPermissions.filter((p) => p.isUsed).length} Used •{' '}
                    {historyPrincipal.grantedPermissions.filter((p) => !p.isUsed).length} Unused
                  </span>
                </div>

                <div className="max-h-48 overflow-y-auto space-y-1 pr-1">
                  {historyPrincipal.grantedPermissions.map((perm) => (
                    <div
                      key={perm.id}
                      className={`p-2 rounded-lg border flex items-center justify-between font-mono text-xs ${
                        perm.isUsed
                          ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
                          : 'bg-rose-950/20 border-rose-800/40 text-rose-200'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className={perm.isUsed ? 'text-emerald-400' : 'text-rose-400'}>
                          {perm.isUsed ? '✓' : '✗'}
                        </span>
                        <span>{perm.action}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {perm.isDangerous && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-900/60 text-rose-300 font-sans">
                            PrivEsc Risk
                          </span>
                        )}
                        <span className="text-[10px] text-slate-400">
                          {perm.isUsed ? 'Exercised' : 'Unexercised'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
              <button
                onClick={() => {
                  setAiSelectedIdentityName(historyPrincipal.name);
                  setHistoryModalPrincipalId(null);
                }}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-200 border border-cyan-800 text-xs font-semibold cursor-pointer"
              >
                <Bot className="w-4 h-4 text-cyan-400" />
                <span>Ask AI Advisor about this Identity</span>
              </button>

              <button
                onClick={() => setHistoryModalPrincipalId(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer"
              >
                Close History
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI HELPING BOX (Identity Security Investigator & Threat Advisor) */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Bot className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>AI Identity Security Advisor & Forensic Investigator</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  Automated LLM Forensics
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Select or type any identity name to generate an automated executive security audit, past activity history, safety verdict, and step-by-step threat mitigation plan.
              </p>
            </div>
          </div>

          {/* Identity Selector */}
          <div className="flex items-center gap-2">
            <select
              value={aiSelectedIdentityName}
              onChange={(e) => setAiSelectedIdentityName(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              {dataset.principals.map((p) => (
                <option key={p.id} value={p.name}>
                  {p.name} ({p.type} • {p.provider})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* AI Generated Analysis Card */}
        {aiReport && (
          <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-5 space-y-4">
            {/* Verdict Header */}
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-850">
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-400">Forensic Identity Audit</span>
                <div className="text-base font-bold text-white flex items-center gap-2">
                  <span>{aiReport.principal.name}</span>
                  <span className="text-xs font-mono text-slate-400">({aiReport.principal.arn})</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-bold ${
                    aiReport.isDangerous
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}
                >
                  Verdict: {aiReport.verdict}
                </span>
                <span className="text-xs font-mono text-slate-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                  Risk Score: {aiReport.score} / 100
                </span>
              </div>
            </div>

            {/* 3 Structured Sections: Activity Timeline, Safety Threat Assessment, Resolution Plan */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* Column 1: What has been done till now */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase font-mono text-cyan-400">
                  <History className="w-3.5 h-3.5" />
                  <span>1. Activity & Invocation History</span>
                </div>
                <div className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-850 space-y-2">
                  <p>
                    <strong>Observed Invocations:</strong> Exercised {aiReport.usedActions.length} of {aiReport.principal.grantedPermissions.length} configured permissions.
                  </p>
                  <p>
                    <strong>Inactivity:</strong> Inactive for <strong>{aiReport.principal.daysInactive} days</strong>.
                    {aiReport.principal.daysInactive > 90
                      ? ' High temporal decay of trust violation.'
                      : ' Within active monitoring window.'}
                  </p>
                  {aiReport.identityAuditLogs.length > 0 ? (
                    <div className="space-y-1 pt-1">
                      <span className="text-[10px] uppercase font-mono text-slate-400 block">CloudTrail Events:</span>
                      {aiReport.identityAuditLogs.slice(0, 3).map((log, idx) => (
                        <div key={idx} className="font-mono text-[10px] text-emerald-300 bg-slate-950 p-1.5 rounded">
                          {log.action} ({log.service}) from {log.sourceIp}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-400 text-[11px]">
                      No recorded API calls during the observation period.
                    </p>
                  )}
                </div>
              </div>

              {/* Column 2: Is it Safe or Dangerous? */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase font-mono text-amber-400">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>2. Threat & Risk Assessment</span>
                </div>
                <div className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-850 space-y-2">
                  <p>
                    {aiReport.isDangerous ? (
                      <span className="text-rose-300">
                        <strong>Threat Detected:</strong> This identity poses immediate risk due to{' '}
                        {aiReport.isUnused && 'account dormancy (>90d), '}
                        {aiReport.dangerousPerms.length > 0 &&
                          `dangerous escalation permissions (${aiReport.dangerousPerms.map((d) => d.action).join(', ')}), `}
                        {!aiReport.principal.mfaEnabled && 'lack of multi-factor authentication (MFA), '}
                        {aiReport.principal.unrotatedKeysCount > 0 && 'unrotated static access keys.'}
                      </span>
                    ) : (
                      <span className="text-emerald-300">
                        <strong>Secure Posture:</strong> Active credentials, healthy rotation status, and acceptable entitlement utilization without unmonitored backdoors.
                      </span>
                    )}
                  </p>
                  <p className="text-slate-400 text-[11px]">
                    <strong>Escalation Potential:</strong> Can be abused by an adversary to perform lateral movement or role assumption to critical databases.
                  </p>
                </div>
              </div>

              {/* Column 3: How can we solve that threat? */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase font-mono text-emerald-400">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>3. How to Solve this Threat</span>
                </div>
                <div className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-850 space-y-2">
                  <ol className="list-decimal list-inside space-y-1 font-sans text-slate-300">
                    <li>
                      <strong>Prune Unused Entitlements:</strong> Strip {aiReport.unusedActions.length} unexercised permissions ({Math.round(aiReport.metrics?.overPrivilegeScore! * 100)}% over-privilege).
                    </li>
                    {aiReport.isUnused && (
                      <li>
                        <strong>Quarantine / Deactivate:</strong> Revoke dormant login credentials and active sessions.
                      </li>
                    )}
                    {aiReport.dangerousPerms.length > 0 && (
                      <li>
                        <strong>Eliminate Escalation Vectors:</strong> Restrict wildcard (*) and <code className="text-rose-300">iam:PassRole</code> to specific designated ARNs.
                      </li>
                    )}
                    {!aiReport.principal.mfaEnabled && (
                      <li>
                        <strong>Enforce MFA:</strong> Require hardware-backed FIDO2 / TOTP multi-factor authentication.
                      </li>
                    )}
                  </ol>

                  <div className="pt-2 flex justify-end">
                    <button
                      onClick={() => {
                        onSelectPrincipalForRemediation(aiReport.principal.id);
                        onNavigateTab('remediation');
                      }}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition cursor-pointer"
                    >
                      Execute Right-Sizing Fix Now
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
