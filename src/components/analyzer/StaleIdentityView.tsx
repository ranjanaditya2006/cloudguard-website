import React, { useState, useMemo } from 'react';
import {
  Clock,
  UserX,
  Sliders,
  Calendar,
  Key,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  AlertOctagon,
} from 'lucide-react';
import { IAMDataSet, Principal, IdentityRiskMetrics } from '../../types/iam';
import { calculateStaleness } from '../../engine/riskScoring';
import { TabKey } from '../layout/Navbar';

interface StaleIdentityViewProps {
  dataset: IAMDataSet;
  riskMetrics: Map<string, IdentityRiskMetrics>;
  onNavigateTab: (tab: TabKey) => void;
  onSelectPrincipalForRemediation: (principalId: string) => void;
}

export const StaleIdentityView: React.FC<StaleIdentityViewProps> = ({
  dataset,
  riskMetrics,
  onNavigateTab,
  onSelectPrincipalForRemediation,
}) => {
  const [lambda, setLambda] = useState(0.02);
  const [inactivityFilter, setInactivityFilter] = useState<'ALL' | '30' | '60' | '90'>('ALL');
  const [selectedForDeactivation, setSelectedForDeactivation] = useState<string[]>([]);

  // Compute curve points for 0 to 180 days based on live lambda
  const curvePoints = useMemo(() => {
    const points: { day: number; score: number }[] = [];
    for (let day = 0; day <= 180; day += 4) {
      points.push({ day, score: calculateStaleness(day, lambda) });
    }
    return points;
  }, [lambda]);

  // SVG dimensions for curve
  const svgWidth = 760;
  const svgHeight = 240;
  const paddingX = 45;
  const paddingY = 35;

  const getSvgX = (day: number) => paddingX + (day / 180) * (svgWidth - paddingX * 2);
  const getSvgY = (score: number) => svgHeight - paddingY - score * (svgHeight - paddingY * 2);

  // SVG path string for the curve
  const curvePathD = useMemo(() => {
    return curvePoints.reduce((acc, p, idx) => {
      const x = getSvgX(p.day);
      const y = getSvgY(p.score);
      return idx === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`;
    }, '');
  }, [curvePoints]);

  // Filter principals based on selected inactivity filter
  const filteredPrincipals = useMemo(() => {
    return dataset.principals.filter((p) => {
      if (inactivityFilter === '30') return p.daysInactive >= 30;
      if (inactivityFilter === '60') return p.daysInactive >= 60;
      if (inactivityFilter === '90') return p.daysInactive >= 90;
      return true;
    });
  }, [dataset.principals, inactivityFilter]);

  const toggleSelect = (id: string) => {
    setSelectedForDeactivation((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  // Explanation parameters for each filter toggle
  const filterExplanation = useMemo(() => {
    const score90d = Math.round(calculateStaleness(90, lambda) * 100);
    const score60d = Math.round(calculateStaleness(60, lambda) * 100);
    const score30d = Math.round(calculateStaleness(30, lambda) * 100);

    switch (inactivityFilter) {
      case 'ALL':
        return {
          title: 'Displaying All Monitored Identities (0 to 180+ Days)',
          desc: `Visualizing the complete organizational identity footprint across all activity stages. Identities plotted below 30 days are healthy, while those past 90 days exceed the critical decay threshold.`,
          cutoffScore: '0% - 100% Decay Spectrum',
          badgeColor: 'bg-slate-800 text-slate-300 border-slate-700',
        };
      case '30':
        return {
          title: 'Filtered: Inactivity > 30 Days (Moderate Trust Degradation)',
          desc: `Isolates identities unverified for over 30 days. Under current calibration (λ=${lambda.toFixed(3)}), identities in this tier experience a decay score cutoff ≥ ${score30d}%. Routine credentials should be audited.`,
          cutoffScore: `Decay Risk Score ≥ ${score30d}%`,
          badgeColor: 'bg-amber-950 text-amber-300 border-amber-800',
        };
      case '60':
        return {
          title: 'Filtered: Inactivity > 60 Days (Substantial Trust Erosion)',
          desc: `Isolates identities unverified for over 60 days. Trust decay has degraded past ${score60d}%. Unused privileges in this tier pose serious risk of undetected credential compromise.`,
          cutoffScore: `Decay Risk Score ≥ ${score60d}%`,
          badgeColor: 'bg-amber-950 text-amber-300 border-amber-800',
        };
      case '90':
        return {
          title: 'Filtered: Inactivity > 90 Days (CRITICAL POLICY VIOLATION)',
          desc: `Isolates dormant identities in direct breach of enterprise 90-day access governance policies. Trust decay has reached ~${score90d}%. These forgotten accounts represent unmonitored shadow doors that should be quarantined immediately.`,
          cutoffScore: `Decay Risk Score ≥ ${score90d}% (Critical Breach)`,
          badgeColor: 'bg-rose-950 text-rose-300 border-rose-800',
        };
    }
  }, [inactivityFilter, lambda]);

  return (
    <div className="space-y-6">
      {/* 1. DETAILED EXPLANATION PANEL: WHAT THIS PAGE DOES */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">
              Temporal Decay of Trust & Stale Account Governance
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Continuous mathematical quantification of credential aging and dormancy under NIST SP 800-207 Zero Trust principles.
            </p>
          </div>
        </div>

        <div className="text-xs text-slate-300 leading-relaxed space-y-2 bg-slate-950/80 p-4 rounded-xl border border-slate-850">
          <p>
            <strong>What this slide / page does:</strong> In cloud security, access credentials and permissions granted to a user, service account, or role should not be trusted indefinitely. When an account remains inactive for extended periods without authentication, re-verification, or active API calls, its <strong>temporal trust decays exponentially</strong>. Dormant accounts represent forgotten entry doors: former employees, finished contractor engagements, or decommissioned microservices that attackers seek out to establish persistent, undetected footholds.
          </p>
          <p>
            This engine models this risk dynamically using an exponential decay model: identities inactive for longer durations receive elevated staleness risk scores. Security engineers use this interactive view to calibrate the organization's decay tolerance (<code className="text-purple-300 font-mono">λ</code>), visually plot where active identities fall along the decay curve, filter accounts breaching inactivity thresholds (such as 30, 60, or 90 days), and trigger batch deactivation or access key revocation.
          </p>
        </div>
      </div>

      {/* 2. LIVE LAMBDA CONTROLLER & DYNAMIC SVG DECAY CURVE */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-purple-400" />
              <span>Live Lambda (λ) Calibration Controller</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Calibrate the decay constant λ from 0.005 (lenient) to 0.05 (strict). Calculates the 90-day policy breach score in real time.
            </p>
          </div>

          {/* Slider */}
          <div className="flex items-center gap-3 bg-slate-950 px-4 py-2.5 rounded-xl border border-slate-800">
            <span className="text-xs text-slate-400 font-mono">λ =</span>
            <input
              type="range"
              min="0.005"
              max="0.05"
              step="0.005"
              value={lambda}
              onChange={(e) => setLambda(parseFloat(e.target.value))}
              className="w-36 accent-purple-500 cursor-pointer"
            />
            <span className="text-xs font-mono font-bold text-purple-300">{lambda.toFixed(3)}</span>
            <span className="text-[11px] text-cyan-300 font-mono bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
              Score at 90 days: <strong>{Math.round(calculateStaleness(90, lambda) * 100)}%</strong>
            </span>
          </div>
        </div>

        {/* 3. CLICKABLE INACTIVITY FILTER BUTTONS */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase text-slate-400 font-semibold">
                Inactivity Filter Toggles (Click to filter graph & table):
              </span>
            </div>

            {/* Clickable Filter Buttons */}
            <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-mono">
              {(['ALL', '30', '60', '90'] as const).map((filter) => {
                const isSelected = inactivityFilter === filter;
                return (
                  <button
                    key={filter}
                    onClick={() => setInactivityFilter(filter)}
                    className={`px-3.5 py-1.5 rounded transition cursor-pointer ${
                      isSelected
                        ? filter === '90'
                          ? 'bg-rose-950 text-rose-300 font-bold border border-rose-800'
                          : 'bg-purple-950 text-purple-300 font-bold border border-purple-800'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {filter === 'ALL' ? 'All Identities' : `>${filter}d Inactive`}
                    {filter === '90' && ' (Policy Violation)'}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Explanation of Score Parameter for the active Toggle */}
          <div className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${filterExplanation.badgeColor}`}>
            <div>
              <div className="font-bold text-white text-xs">{filterExplanation.title}</div>
              <p className="text-[11px] text-slate-300 mt-0.5">{filterExplanation.desc}</p>
            </div>
            <div className="shrink-0 font-mono text-[11px] bg-slate-950 px-3 py-1 rounded border border-slate-800">
              Active Parameter Cutoff: <strong className="text-cyan-300">{filterExplanation.cutoffScore}</strong>
            </div>
          </div>
        </div>

        {/* 4. DYNAMIC SVG DECAY GRAPH */}
        <div className="w-full overflow-x-auto bg-slate-950 rounded-xl border border-slate-850 p-3">
          <svg className="w-full max-w-4xl mx-auto h-[240px]" viewBox={`0 0 ${svgWidth} ${svgHeight}`}>
            {/* Background Zones */}
            {/* Green Zone (<30d) */}
            <rect
              x={paddingX}
              y={paddingY}
              width={getSvgX(30) - paddingX}
              height={svgHeight - paddingY * 2}
              fill="#064e3b"
              fillOpacity="0.15"
            />
            {/* Amber Zone (30d - 90d) */}
            <rect
              x={getSvgX(30)}
              y={paddingY}
              width={getSvgX(90) - getSvgX(30)}
              height={svgHeight - paddingY * 2}
              fill="#78350f"
              fillOpacity="0.12"
            />
            {/* Red Zone (>=90d) */}
            <rect
              x={getSvgX(90)}
              y={paddingY}
              width={svgWidth - paddingX - getSvgX(90)}
              height={svgHeight - paddingY * 2}
              fill="#881337"
              fillOpacity="0.18"
            />

            {/* Grid & Axis Lines */}
            <line
              x1={paddingX}
              y1={svgHeight - paddingY}
              x2={svgWidth - paddingX}
              y2={svgHeight - paddingY}
              stroke="#334155"
              strokeWidth="1.5"
            />
            <line
              x1={paddingX}
              y1={paddingY}
              x2={paddingX}
              y2={svgHeight - paddingY}
              stroke="#334155"
              strokeWidth="1.5"
            />

            {/* Threshold Vertical Lines (30d, 90d) */}
            <line
              x1={getSvgX(30)}
              y1={paddingY}
              x2={getSvgX(30)}
              y2={svgHeight - paddingY}
              stroke="#10b981"
              strokeDasharray="4,4"
              strokeWidth="1.2"
            />
            <text
              x={getSvgX(30)}
              y={paddingY - 8}
              fill="#10b981"
              fontSize="9"
              fontFamily="monospace"
              textAnchor="middle"
            >
              30d Low Risk Threshold
            </text>

            <line
              x1={getSvgX(90)}
              y1={paddingY}
              x2={getSvgX(90)}
              y2={svgHeight - paddingY}
              stroke="#f43f5e"
              strokeDasharray="4,4"
              strokeWidth="1.5"
            />
            <text
              x={getSvgX(90)}
              y={paddingY - 8}
              fill="#f43f5e"
              fontSize="9"
              fontFamily="monospace"
              fontWeight="bold"
              textAnchor="middle"
            >
              90d Policy Violation Breach
            </text>

            {/* Plotted Exponential Decay Curve */}
            <path d={curvePathD} fill="none" stroke="#c084fc" strokeWidth="3" />

            {/* Plot identities matching the active filter */}
            {filteredPrincipals.map((p) => {
              const clampedDay = Math.min(180, p.daysInactive);
              const score = calculateStaleness(p.daysInactive, lambda);
              const cx = getSvgX(clampedDay);
              const cy = getSvgY(score);
              const isViolation = p.daysInactive > 90;

              return (
                <g key={p.id} className="cursor-pointer group">
                  <circle
                    cx={cx}
                    cy={cy}
                    r={isViolation ? 6.5 : 4.5}
                    fill={isViolation ? '#ef4444' : p.daysInactive > 30 ? '#eab308' : '#10b981'}
                    stroke="#ffffff"
                    strokeWidth="1.5"
                    className="transition-transform group-hover:scale-150"
                  />
                  <text
                    x={cx}
                    y={cy - 10}
                    fill="#f1f5f9"
                    fontSize="8.5"
                    fontFamily="monospace"
                    textAnchor="middle"
                    className="opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none drop-shadow font-semibold"
                  >
                    {p.name} ({p.daysInactive}d • {Math.round(score * 100)}%)
                  </text>
                </g>
              );
            })}

            {/* Axis Labels */}
            <text
              x={svgWidth - paddingX}
              y={svgHeight - paddingY + 20}
              fill="#94a3b8"
              fontSize="10"
              fontFamily="sans-serif"
              textAnchor="end"
            >
              Inactivity Duration (Days) →
            </text>
            <text
              x={paddingX + 6}
              y={paddingY + 12}
              fill="#94a3b8"
              fontSize="10"
              fontFamily="sans-serif"
            >
              ↑ Staleness Risk Score (0.0 to 1.0)
            </text>
          </svg>
        </div>

        {/* 5. CLEAR EXPLANATION OF GRAPH AXES & LEGENDS */}
        <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
          <div className="text-xs uppercase font-mono font-bold text-slate-300 flex items-center gap-1.5">
            <Info className="w-4 h-4 text-cyan-400" />
            <span>Detailed Guide: Graph Axes, Color Zones & Legend Meaning</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-slate-300">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-850 space-y-1">
              <span className="font-semibold text-white font-mono text-[11px] block">X-Axis & Y-Axis</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                <strong>X-Axis (Horizontal):</strong> Days since the identity last authenticated or recorded an API event in CloudTrail (0 to 180+ days).
              </p>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                <strong>Y-Axis (Vertical):</strong> Calculated Staleness Decay Score (0.0 to 1.0 / 0% to 100%), representing probability of unmonitored credential decay.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-850 space-y-1">
              <span className="font-semibold text-white font-mono text-[11px] block">Threshold Zones</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                <span className="text-emerald-400 font-bold">&lt; 30 Days (Green Zone):</span> Active credentials under continuous operational monitoring.
              </p>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                <span className="text-amber-400 font-bold">30 - 89 Days (Amber Zone):</span> Degraded trust. Requires review of active privileges.
              </p>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                <span className="text-rose-400 font-bold">≥ 90 Days (Red Zone):</span> Zero-Trust Breach. Mandatory credential rotation or account quarantine.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-850 space-y-1">
              <span className="font-semibold text-white font-mono text-[11px] block">Plotted Identity Dots</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Each dot represents an actual user or service account in your uploaded dataset. Currently showing <strong>{filteredPrincipals.length}</strong> identities matching your selected filter. Hovering reveals the identity name, exact inactive days, and decay score.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* 6. DORMANT ACCOUNTS REVIEW & REVOCATION TABLE */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <UserX className="w-5 h-5 text-purple-400" />
            <h2 className="font-semibold text-white">
              Dormant Accounts Review & Revocation ({filteredPrincipals.length} Identities)
            </h2>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                <th className="py-3 px-3 w-8">Select</th>
                <th className="py-3 px-3">Identity Name</th>
                <th className="py-3 px-3">Type & Provider</th>
                <th className="py-3 px-3">Inactivity Duration</th>
                <th className="py-3 px-3">Calculated Staleness</th>
                <th className="py-3 px-3">Credential Exposure</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredPrincipals.map((p) => {
                const isSelected = selectedForDeactivation.includes(p.id);
                const score = calculateStaleness(p.daysInactive, lambda);
                const isViolation = p.daysInactive > 90;

                return (
                  <tr key={p.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-3">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleSelect(p.id)}
                        className="rounded bg-slate-950 border-slate-800 accent-purple-500 cursor-pointer"
                      />
                    </td>
                    <td className="py-3 px-3 font-sans">
                      <div className="font-semibold text-slate-100">{p.name}</div>
                      <div className="text-[10px] text-slate-500 font-mono truncate max-w-[200px]">{p.arn}</div>
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                        {p.type} • {p.provider}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={isViolation ? 'text-rose-400 font-bold' : p.daysInactive > 30 ? 'text-amber-300' : 'text-slate-300'}>
                        {p.daysInactive} days
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isViolation
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : p.daysInactive > 30
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {(score * 100).toFixed(1)}% (λ={lambda.toFixed(3)})
                      </span>
                    </td>
                    <td className="py-3 px-3 font-sans">
                      {p.unrotatedKeysCount > 0 ? (
                        <span className="text-amber-400 text-xs flex items-center gap-1">
                          <Key className="w-3.5 h-3.5" />
                          <span>{p.unrotatedKeysCount} unrotated keys</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 text-xs">Credentials rotated</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right font-sans">
                      <button
                        onClick={() => {
                          onSelectPrincipalForRemediation(p.id);
                          onNavigateTab('remediation');
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs transition cursor-pointer"
                      >
                        Review Access
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Batch Action Footer */}
        {selectedForDeactivation.length > 0 && (
          <div className="p-3.5 bg-purple-950/40 border border-purple-800/80 rounded-xl flex items-center justify-between text-xs">
            <span className="text-purple-200">
              <strong>{selectedForDeactivation.length}</strong> dormant identities selected for quarantine.
            </span>
            <button
              onClick={() => {
                alert(`Quarantine simulated for ${selectedForDeactivation.length} accounts.`);
                setSelectedForDeactivation([]);
              }}
              className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold transition cursor-pointer"
            >
              Simulate Account Quarantine
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
