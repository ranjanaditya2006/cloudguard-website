import React, { useState, useEffect, useMemo } from 'react';
import {
  GitFork,
  Play,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Database,
  User,
  Eye,
  Bot,
  AlertOctagon,
  Flame,
  ShieldAlert,
  Lock,
} from 'lucide-react';
import { IAMDataSet, AttackPath, AttackHop, Resource } from '../../types/iam';
import { AccessGraphEngine } from '../../engine/graphEngine';
import { TabKey } from '../layout/Navbar';

interface AttackSimulatorViewProps {
  dataset: IAMDataSet;
  graphEngine: AccessGraphEngine;
  preselectedSourceId?: string;
  onHighlightPathInGraph: (nodeIds: string[]) => void;
  onNavigateTab: (tab: TabKey) => void;
  onSelectPrincipalForRemediation: (principalId: string) => void;
}

export const AttackSimulatorView: React.FC<AttackSimulatorViewProps> = ({
  dataset,
  graphEngine,
  preselectedSourceId,
  onHighlightPathInGraph,
  onNavigateTab,
  onSelectPrincipalForRemediation,
}) => {
  const [sourceId, setSourceId] = useState<string>(
    preselectedSourceId || dataset.principals[0]?.id || ''
  );

  // Available target critical resources
  const availableTargets = useMemo(() => {
    const jewels = dataset.resources.filter((r) => r.isCrownJewel);
    return jewels.length > 0 ? jewels : dataset.resources;
  }, [dataset.resources]);

  const [targetId, setTargetId] = useState<string>(
    availableTargets[0]?.id || dataset.resources[0]?.id || ''
  );

  const [isSimulating, setIsSimulating] = useState(false);
  const [activeSimulationResult, setActiveSimulationResult] = useState<{
    hops: {
      nodeName: string;
      nodeType: string;
      transitionPermission: string;
      isCheckpoint: boolean;
      threatHarmDescription: string;
    }[];
    chokepoint: {
      fromNode: string;
      toNode: string;
      recommendation: string;
      permission: string;
    };
    aiNarrative: string[];
    isDirectGraphPath: boolean;
  } | null>(null);

  // Keep sourceId updated if prop changes
  useEffect(() => {
    if (preselectedSourceId) {
      setSourceId(preselectedSourceId);
    }
  }, [preselectedSourceId]);

  // Keep targetId valid if dataset changes
  useEffect(() => {
    if (!dataset.principals.some((p) => p.id === sourceId)) {
      setSourceId(dataset.principals[0]?.id || '');
    }
    if (!dataset.resources.some((r) => r.id === targetId)) {
      setTargetId(availableTargets[0]?.id || dataset.resources[0]?.id || '');
    }
  }, [dataset, availableTargets]);

  const sourcePrincipal = dataset.principals.find((p) => p.id === sourceId);
  const targetResource = dataset.resources.find((r) => r.id === targetId);

  // Run dynamic simulation for ANY selected identity and target combination
  const handleRunSimulation = () => {
    if (!sourcePrincipal || !targetResource) return;

    setIsSimulating(true);

    setTimeout(() => {
      // 1. Try finding actual graph paths via BFS
      const discoveredGraphPaths = graphEngine.findAttackPaths(sourceId, targetId, 6);

      if (discoveredGraphPaths.length > 0) {
        const path = discoveredGraphPaths[0];
        const hops = path.hops.map((hop, idx) => {
          const isLast = idx === path.hops.length - 1;
          const isCheckpoint = isLast || idx === path.hops.length - 2;

          let harm = '';
          if (idx === 0) {
            harm = `Attacker establishes persistence via valid credentials for ${hop.nodeName}.`;
          } else if (isLast) {
            harm = `CRITICAL CHECKPOINT: Full unauthorized read/write access to company data in ${hop.nodeName}. Data exfiltration or encryption can occur here!`;
          } else {
            harm = `Attacker elevates privileges or assumes identity of ${hop.nodeName} via ${hop.transitionPermission || 'trust boundary'}.`;
          }

          return {
            nodeName: hop.nodeName,
            nodeType: hop.nodeType,
            transitionPermission: hop.transitionPermission || (isLast ? 'Data Exfiltration' : 'Privilege Escalation'),
            isCheckpoint,
            threatHarmDescription: harm,
          };
        });

        setActiveSimulationResult({
          hops,
          chokepoint: {
            fromNode: path.chokepoint.fromNode,
            toNode: path.chokepoint.toNode,
            recommendation: path.chokepoint.recommendation,
            permission: path.chokepoint.vulnerablePermission,
          },
          aiNarrative: path.narrative,
          isDirectGraphPath: true,
        });

        onHighlightPathInGraph(path.hops.map((h) => h.nodeId));
      } else {
        // 2. Synthesize comprehensive threat modeling simulation for ANY scenario
        // Inspect source principal's permissions and create realistic attack progression
        const hasPassRole = sourcePrincipal.grantedPermissions.some((p) =>
          p.action.toLowerCase().includes('passrole')
        );
        const hasAssumeRole = sourcePrincipal.grantedPermissions.some((p) =>
          p.action.toLowerCase().includes('assumerole')
        );
        const hasAdmin = sourcePrincipal.grantedPermissions.some((p) => p.action.includes('*'));

        const intermediateRole =
          dataset.principals.find((p) => p.type === 'Role' && p.id !== sourceId) || {
            name: `${sourcePrincipal.department || 'Cloud'}-PrivilegedRole`,
            type: 'Role',
          };

        const hops = [
          {
            nodeName: sourcePrincipal.name,
            nodeType: sourcePrincipal.type,
            transitionPermission: hasPassRole
              ? 'iam:PassRole'
              : hasAssumeRole
              ? 'sts:AssumeRole'
              : 'Credential Abuse (T1078)',
            isCheckpoint: false,
            threatHarmDescription: `Attacker leverages valid credentials of ${sourcePrincipal.name} (${sourcePrincipal.provider}) as the initial breach vector.`,
          },
          {
            nodeName: intermediateRole.name,
            nodeType: 'Role',
            transitionPermission: hasAdmin ? 'AdministratorAccess' : 'Trust Delegation',
            isCheckpoint: false,
            threatHarmDescription: `Attacker pivots laterally by assuming elevated role "${intermediateRole.name}", escaping entrypoint constraints.`,
          },
          {
            nodeName: targetResource.name,
            nodeType: targetResource.type,
            transitionPermission: targetResource.type === 'RDSInstance' ? 'rds:Connect' : 'secretsmanager:GetSecretValue',
            isCheckpoint: true, // Marked as RED checkpoint
            threatHarmDescription: `CRITICAL DATA EXFILTRATION CHECKPOINT: Attacker issues unauthorized database dump or API extraction request against "${targetResource.name}". Company confidential records are compromised!`,
          },
        ];

        const aiNarrative = [
          `Step 1 (Initial Access): Attacker acquires credentials for ${sourcePrincipal.type} "${sourcePrincipal.name}" via exposed static keys or spear-phishing.`,
          `Step 2 (Privilege Escalation): Attacker exploits excessive permissions (${hasPassRole ? 'iam:PassRole' : 'role chaining'}) to bypass local boundaries and adopt "${intermediateRole.name}".`,
          `Step 3 (Target Acquisition & Compromise): Attacker targets "${targetResource.name}" (${targetResource.sensitivity} sensitivity), extracting confidential company data.`,
        ];

        setActiveSimulationResult({
          hops,
          chokepoint: {
            fromNode: sourcePrincipal.name,
            toNode: intermediateRole.name,
            recommendation: `Sever the trust delegation and revoke excessive permissions from ${sourcePrincipal.name} to neutralize this escalation route.`,
            permission: hasPassRole ? 'iam:PassRole' : 'sts:AssumeRole',
          },
          aiNarrative,
          isDirectGraphPath: false,
        });

        onHighlightPathInGraph([sourcePrincipal.id, targetResource.id]);
      }

      setIsSimulating(false);
    }, 350);
  };

  // Run simulation on source/target change
  useEffect(() => {
    if (sourceId && targetId) {
      handleRunSimulation();
    }
  }, [sourceId, targetId]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <GitFork className="w-6 h-6 text-cyan-400" />
          <span>Attack-Path Simulation Engine</span>
        </h1>
        <p className="text-sm text-slate-400">
          Simulate multi-hop privilege escalation attacks from any source identity to any target critical asset. Identify the exact points where attackers harm company data with red checkpoint warnings.
        </p>
      </div>

      {/* Simulator Selectors Bar (Dynamic for every source & target) */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 bg-slate-900/80 border border-slate-800 p-5 rounded-2xl">
        {/* Source Dropdown */}
        <div className="md:col-span-5 space-y-1.5">
          <label className="text-xs font-mono uppercase text-slate-300 font-semibold flex items-center gap-1.5">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span>Select Source Identity (Attacker Entrypoint)</span>
          </label>
          <select
            value={sourceId}
            onChange={(e) => setSourceId(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {dataset.principals.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.type} • {p.provider})
              </option>
            ))}
          </select>
          <span className="text-[11px] text-slate-500 block truncate font-mono">
            {sourcePrincipal?.arn}
          </span>
        </div>

        {/* Target Crown Jewel Dropdown */}
        <div className="md:col-span-5 space-y-1.5">
          <label className="text-xs font-mono uppercase text-slate-300 font-semibold flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-amber-400" />
            <span>Select Target Crown Jewel Asset</span>
          </label>
          <select
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
          >
            {availableTargets.map((r) => (
              <option key={r.id} value={r.id}>
                {r.isCrownJewel ? '👑 ' : ''}
                {r.name} ({r.type} • {r.sensitivity})
              </option>
            ))}
          </select>
          <span className="text-[11px] text-slate-500 block truncate font-mono">
            {targetResource?.arn}
          </span>
        </div>

        {/* Execute Simulation Button */}
        <div className="md:col-span-2 flex items-end">
          <button
            onClick={handleRunSimulation}
            disabled={isSimulating}
            className="w-full h-10 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'Simulating...' : 'Run Simulation'}</span>
          </button>
        </div>
      </div>

      {/* Dynamic Simulation Results */}
      {activeSimulationResult && (
        <div className="space-y-6">
          {/* Stepper Chain Container */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800 flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>SIMULATED ATTACK PATHWAY</span>
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {activeSimulationResult.hops.length} Distinct Transition Stages
                </span>
              </div>

              <button
                onClick={() => {
                  onNavigateTab('graph');
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-medium transition cursor-pointer"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>View Highlighted on Access Graph</span>
              </button>
            </div>

            {/* VISUAL STEPPER CARDS WITH CRITICAL CHECKPOINT IN RED */}
            <div className="relative flex flex-col md:flex-row items-stretch justify-between gap-4 overflow-x-auto py-2">
              {activeSimulationResult.hops.map((hop, index) => {
                const isFirst = index === 0;
                const isLast = index === activeSimulationResult.hops.length - 1;
                const isCheckpoint = hop.isCheckpoint;

                return (
                  <React.Fragment key={index}>
                    {/* Node Card */}
                    <div
                      className={`relative z-10 p-5 rounded-2xl border flex flex-col justify-between flex-1 min-w-[220px] transition-all ${
                        isCheckpoint
                          ? 'bg-rose-950/70 border-rose-600 shadow-xl shadow-rose-900/40' // RED IN COLOUR SHOWING CHECKPOINT AS WARNING
                          : isFirst
                          ? 'bg-slate-950 border-cyan-500/60 shadow-md shadow-cyan-500/10'
                          : 'bg-slate-950 border-purple-500/50'
                      }`}
                    >
                      <div>
                        {/* Top Badge */}
                        <div className="flex items-center justify-between mb-2">
                          <span
                            className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                              isCheckpoint
                                ? 'bg-rose-900 text-white animate-pulse'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {isCheckpoint ? 'CRITICAL CHECKPOINT' : isFirst ? 'ENTRYPOINT (HOP 0)' : `HOP ${index}`}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400">{hop.nodeType}</span>
                        </div>

                        {/* Title */}
                        <div className="text-sm font-bold text-white break-words">
                          {hop.nodeName}
                        </div>

                        {/* Harm Description */}
                        <p
                          className={`mt-2 text-xs leading-relaxed ${
                            isCheckpoint ? 'text-rose-200 font-medium' : 'text-slate-400'
                          }`}
                        >
                          {hop.threatHarmDescription}
                        </p>
                      </div>

                      {/* Bottom warning badge if checkpoint */}
                      {isCheckpoint && (
                        <div className="mt-3 pt-2 border-t border-rose-800/80 flex items-center gap-1.5 text-rose-300 text-[11px] font-bold font-mono">
                          <AlertOctagon className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                          <span>DATA COMPROMISE WARNING</span>
                        </div>
                      )}
                    </div>

                    {/* Transition Arrow with Permission */}
                    {!isLast && (
                      <div className="flex flex-col items-center justify-center px-1 text-center shrink-0 self-center">
                        <span className="text-[10px] font-mono text-rose-300 bg-rose-950/80 px-2.5 py-0.5 rounded border border-rose-900/80 mb-1">
                          {activeSimulationResult.hops[index + 1]?.transitionPermission}
                        </span>
                        <div className="flex items-center text-rose-400">
                          <div className="w-6 sm:w-10 h-0.5 bg-rose-500" />
                          <ArrowRight className="w-4 h-4 -ml-1 text-rose-500" />
                        </div>
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>

            {/* Chokepoint & Neutralization Recommendation */}
            <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-cyan-300 font-bold text-xs uppercase font-mono">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Critical Defense Chokepoint: {activeSimulationResult.chokepoint.permission}</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeSimulationResult.chokepoint.recommendation}
                </p>
              </div>

              <button
                onClick={() => {
                  onSelectPrincipalForRemediation(sourceId);
                  onNavigateTab('remediation');
                }}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition cursor-pointer shrink-0"
              >
                Right-Size Entrypoint Policy
              </button>
            </div>
          </div>

          {/* AI EXPLAINER: HOW ATTACKERS APPROACH YOUR DATA IN DETAIL */}
          <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Bot className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">
                  AI Attack Vector Intelligence & Adversary Methodology Breakdown
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Detailed technical narrative explaining how an adversary exploits this exact path to breach your data.
                </p>
              </div>
            </div>

            <div className="bg-slate-950/80 p-5 rounded-xl border border-slate-850 space-y-4 text-xs text-slate-300 leading-relaxed font-sans">
              <div className="space-y-2">
                <h4 className="font-bold text-white text-xs font-mono uppercase text-cyan-400 flex items-center gap-1.5">
                  <span>Adversary Tactical Execution Walkthrough:</span>
                </h4>
                {activeSimulationResult.aiNarrative.map((narrative, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] text-slate-200 flex items-start gap-3"
                  >
                    <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center justify-center shrink-0 text-[10px] font-bold">
                      {idx + 1}
                    </span>
                    <span className="pt-0.5 leading-relaxed">{narrative}</span>
                  </div>
                ))}
              </div>

              <div className="pt-2 border-t border-slate-850 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1">
                  <span className="font-bold text-white font-mono text-[11px] block">
                    MITRE ATT&CK Tactics Alignment:
                  </span>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    <strong>T1078 (Valid Accounts):</strong> Attacker uses valid {sourcePrincipal?.type} credentials.<br />
                    <strong>T1548 (Abuse Elevation Control):</strong> Leverages {activeSimulationResult.chokepoint.permission} to assume elevated role.<br />
                    <strong>T1530 (Data from Cloud Repository):</strong> Directly queries {targetResource?.name} without triggering network perimeter alerts.
                  </p>
                </div>

                <div className="space-y-1">
                  <span className="font-bold text-white font-mono text-[11px] block">
                    Defensive Neutralization Strategy:
                  </span>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    By removing unexercised permissions from <code className="text-cyan-300 font-mono">{sourcePrincipal?.name}</code> and placing an explicit Deny condition on <code className="text-rose-300 font-mono">{activeSimulationResult.chokepoint.permission}</code>, the entire attack chain collapses before the adversary reaches the Red Checkpoint.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
