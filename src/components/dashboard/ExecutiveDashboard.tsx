import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  UserX,
  ArrowUpRight,
  TrendingUp,
  Lock,
} from 'lucide-react';
import { IAMDataSet, Principal, IdentityRiskMetrics } from '../../types/iam';
import { TabKey } from '../layout/Navbar';

interface ExecutiveDashboardProps {
  dataset: IAMDataSet;
  riskMetrics: Map<string, IdentityRiskMetrics>;
  onNavigateTab: (tab: TabKey) => void;
  onSelectPrincipalForRemediation: (principalId: string) => void;
  onSelectPrincipalForSimulation: (principalId: string) => void;
}

export const ExecutiveDashboard: React.FC<ExecutiveDashboardProps> = ({
  dataset,
  riskMetrics,
  onNavigateTab,
  onSelectPrincipalForRemediation,
  onSelectPrincipalForSimulation,
}) => {
  // Aggregate calculations
  const principals = dataset.principals;
  const metricsList = principals.map((p) => riskMetrics.get(p.id)!);

  const avgRiskScore =
    metricsList.length > 0
      ? Math.round(metricsList.reduce((acc, m) => acc + (m?.compositeRiskScore || 0), 0) / metricsList.length)
      : 0;

  const criticalIdentities = metricsList.filter((m) => m?.riskCategory === 'CRITICAL');
  const highRiskIdentities = metricsList.filter((m) => m?.riskCategory === 'HIGH');
  const staleAccounts = principals.filter((p) => p.daysInactive > 90);
  const overPrivilegedCount = metricsList.filter((m) => m?.overPrivilegeScore > 0.6).length;
  const crownJewels = dataset.resources.filter((r) => r.isCrownJewel);

  // Total permissions granted vs used
  let totalGranted = 0;
  let totalUsed = 0;
  principals.forEach((p) => {
    p.grantedPermissions.forEach((perm) => {
      totalGranted++;
      if (perm.isUsed) totalUsed++;
    });
  });
  const totalUnused = totalGranted - totalUsed;
  const unusedPercent = totalGranted > 0 ? Math.round((totalUnused / totalGranted) * 100) : 0;

  // Sorted riskiest identities
  const topRiskiest = [...principals].sort((a, b) => {
    const scoreA = riskMetrics.get(a.id)?.compositeRiskScore || 0;
    const scoreB = riskMetrics.get(b.id)?.compositeRiskScore || 0;
    return scoreB - scoreA;
  }).slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Top Banner / Problem Statement Resolution */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 p-6">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 text-xs font-mono">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>Principle of Least Privilege (PoLP) Risk Evaluation</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Cloud Identity Risk & Entitlement Posture
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              Continuous graph analysis mapping multi-cloud access paths, quantifying temporal trust decay, and simulating multi-hop privilege escalation attacks before compromise occurs.
            </p>
          </div>

          {/* Radial Organization Score Card */}
          <div className="flex items-center gap-4 bg-slate-950/80 border border-slate-800 rounded-xl p-4 min-w-[240px]">
            <div className="relative w-20 h-20 flex items-center justify-center">
              <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`${
                    avgRiskScore > 65
                      ? 'text-rose-500'
                      : avgRiskScore > 40
                      ? 'text-amber-500'
                      : 'text-emerald-500'
                  } transition-all duration-1000 ease-out`}
                  strokeDasharray={`${avgRiskScore}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute text-center">
                <span className="text-xl font-bold font-mono text-white">{avgRiskScore}</span>
                <span className="block text-[9px] text-slate-400 font-sans">/ 100</span>
              </div>
            </div>
            <div>
              <div className="text-xs uppercase font-mono text-slate-400 font-medium">Org Risk Index</div>
              <div className="text-base font-bold text-white">
                {avgRiskScore > 65 ? 'High Exposure' : avgRiskScore > 40 ? 'Moderate Risk' : 'Healthy Posture'}
              </div>
              <span className="text-xs text-rose-400 font-medium">
                {criticalIdentities.length} Critical Accounts Flagged
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Identities */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono">Monitored Principals</span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-white font-mono">{principals.length}</div>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
            <span className="text-blue-400 font-semibold">{principals.filter((p) => p.type === 'User').length} Users</span>
            <span>•</span>
            <span className="text-purple-400 font-semibold">{principals.filter((p) => p.type === 'Role').length} Roles</span>
            <span>•</span>
            <span className="text-cyan-400 font-semibold">{principals.filter((p) => p.type === 'ServiceAccount').length} SAs</span>
          </div>
        </div>

        {/* KPI 2: Critical Identities */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono">Critical Identities</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{criticalIdentities.length}</div>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-rose-400 font-semibold">{highRiskIdentities.length} High</span>
            <span>•</span>
            <span className="text-slate-400">{principals.length - criticalIdentities.length - highRiskIdentities.length} Moderate/Low</span>
          </div>
        </div>

        {/* KPI 3: Over-Privileged */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono">Excessive Permissions</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{overPrivilegedCount}</div>
          <div className="text-xs text-slate-400 mt-1">
            <span className="text-rose-400 font-semibold">{unusedPercent}%</span> of granted permissions unused
          </div>
        </div>

        {/* KPI 4: Stale Identities */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono">Stale Accounts (&gt;90d)</span>
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <UserX className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-purple-300 font-mono">{staleAccounts.length}</div>
          <div className="text-xs text-slate-400 mt-1">
            High temporal trust decay violation
          </div>
        </div>
      </div>

      {/* Middle Grid: Top Riskiest Identities & Permission Utilization */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Riskiest Identities Table (2 cols) */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h2 className="font-semibold text-white">Top High-Risk Identities (Remediation Priority)</h2>
            </div>
            <button
              onClick={() => onNavigateTab('overprivilege')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition cursor-pointer"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                  <th className="pb-3 font-medium">Principal</th>
                  <th className="pb-3 font-medium">Type</th>
                  <th className="pb-3 font-medium">Inactivity</th>
                  <th className="pb-3 font-medium">Over-Privilege</th>
                  <th className="pb-3 font-medium">Composite Risk</th>
                  <th className="pb-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {topRiskiest.map((p) => {
                  const m = riskMetrics.get(p.id)!;
                  return (
                    <tr key={p.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3">
                        <div className="font-semibold text-slate-100">{p.name}</div>
                        <div className="text-[10px] text-slate-400 font-mono truncate max-w-[170px]">{p.arn}</div>
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                          {p.type}
                        </span>
                      </td>
                      <td className="py-3 font-mono">
                        <span className={p.daysInactive > 90 ? 'text-purple-400 font-bold' : 'text-slate-300'}>
                          {p.daysInactive} days
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className="bg-rose-500 h-1.5 rounded-full"
                              style={{ width: `${Math.round(m?.overPrivilegeScore * 100)}%` }}
                            />
                          </div>
                          <span className="font-mono text-slate-300">
                            {Math.round(m?.overPrivilegeScore * 100)}%
                          </span>
                        </div>
                      </td>
                      <td className="py-3">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            m?.riskCategory === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : m?.riskCategory === 'HIGH'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          }`}
                        >
                          {m?.compositeRiskScore} / 100
                        </span>
                      </td>
                      <td className="py-3 text-right space-x-1">
                        <button
                          onClick={() => {
                            onSelectPrincipalForSimulation(p.id);
                            onNavigateTab('simulation');
                          }}
                          title="Simulate Attack Path from this Identity"
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-750 text-cyan-300 border border-slate-700 text-[10px] font-medium transition cursor-pointer"
                        >
                          Simulate
                        </button>
                        <button
                          onClick={() => {
                            onSelectPrincipalForRemediation(p.id);
                            onNavigateTab('remediation');
                          }}
                          title="Generate Least-Privilege Policy"
                          className="px-2 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-200 border border-cyan-800 text-[10px] font-medium transition cursor-pointer"
                        >
                          Right-Size
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Permission Utilization & Blast Radius Card (1 col) */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            <h2 className="font-semibold text-white">Entitlement Distribution</h2>
          </div>

          {/* Entitlement breakdown */}
          <div className="space-y-4 pt-2">
            <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800 space-y-3">
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Total Granted Actions</span>
                <span className="font-mono font-bold text-white">{totalGranted}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-emerald-400 flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  Exercised in CloudTrail (Used)
                </span>
                <span className="font-mono text-emerald-300 font-semibold">{totalUsed}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-rose-400 flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-rose-400" />
                  Excessive / Unexercised (Unused)
                </span>
                <span className="font-mono text-rose-300 font-semibold">{totalUnused}</span>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-slate-800 h-3 rounded-full overflow-hidden flex mt-2">
                <div
                  className="bg-emerald-500 h-full transition-all duration-500"
                  style={{ width: `${100 - unusedPercent}%` }}
                />
                <div
                  className="bg-rose-500 h-full transition-all duration-500"
                  style={{ width: `${unusedPercent}%` }}
                />
              </div>

              <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex justify-between font-mono">
                <span>Unused Ratio: <strong className="text-rose-400">{unusedPercent}%</strong></span>
                <span>Used Ratio: <strong className="text-emerald-400">{100 - unusedPercent}%</strong></span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
