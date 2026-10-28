import React, { useState } from 'react';
import {
  KeyRound,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Lock,
  Bot,
  User,
  Clock,
  AlertOctagon,
  X,
  FileText,
} from 'lucide-react';
import { IAMDataSet, Principal, IdentityRiskMetrics } from '../../types/iam';
import { TabKey } from '../layout/Navbar';

interface OverPrivilegeViewProps {
  dataset: IAMDataSet;
  riskMetrics: Map<string, IdentityRiskMetrics>;
  onSelectPrincipalForRemediation: (principalId: string) => void;
  onNavigateTab: (tab: TabKey) => void;
}

export const OverPrivilegeView: React.FC<OverPrivilegeViewProps> = ({
  dataset,
  riskMetrics,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [inspectPrincipal, setInspectPrincipal] = useState<Principal | null>(null);

  // Show all identities from dataset, with optional search and provider filter
  const displayedPrincipals = dataset.principals.filter((p) => {
    const matchSearch =
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.arn.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (p.department && p.department.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchType = filterType === 'ALL' || p.type === filterType;
    return matchSearch && matchType;
  });

  // Calculate detailed inspection metrics for inspectPrincipal
  const inspectData = React.useMemo(() => {
    if (!inspectPrincipal) return null;

    const m = riskMetrics.get(inspectPrincipal.id);
    const totalGranted = inspectPrincipal.grantedPermissions.length;
    const totalUsed = inspectPrincipal.grantedPermissions.filter((p) => p.isUsed).length;
    const totalUnused = totalGranted - totalUsed;
    const unusedPct = totalGranted > 0 ? Math.round((totalUnused / totalGranted) * 100) : 0;
    const riskScore = m?.compositeRiskScore || 0;

    // Check if secure or dangerous
    const isDangerous =
      riskScore >= 50 ||
      inspectPrincipal.daysInactive >= 90 ||
      unusedPct >= 60 ||
      inspectPrincipal.grantedPermissions.some((p) => p.isDangerous || p.action.includes('PassRole') || p.action.includes('*'));

    // Check if overprivileged vs underprivileged
    // Overprivileged: granted significantly more than used
    // Underprivileged / Right-Sized: uses >= 75% of granted
    const entitlementStatus: 'OVERPRIVILEGED' | 'RIGHT_SIZED' | 'UNDERPRIVILEGED' =
      unusedPct >= 40
        ? 'OVERPRIVILEGED'
        : unusedPct <= 10 && totalGranted > 0
        ? 'RIGHT_SIZED'
        : 'RIGHT_SIZED';

    // Threat to other identities evaluation
    const escalationPerms = inspectPrincipal.grantedPermissions.filter(
      (p) =>
        p.action.toLowerCase().includes('passrole') ||
        p.action.toLowerCase().includes('assumerole') ||
        p.action.toLowerCase().includes('attachrole') ||
        p.action.toLowerCase().includes('createaccesskey') ||
        p.action.toLowerCase().includes('putuserpolicy') ||
        p.action.toLowerCase().includes('updateassumerole') ||
        p.action === '*' ||
        p.action.endsWith(':*')
    );

    const canPoseThreatToOthers = escalationPerms.length > 0 || isDangerous;

    let threatExplanation = '';
    if (escalationPerms.some((p) => p.action.includes('PassRole'))) {
      threatExplanation = `Direct Privilege Escalation: This identity holds "iam:PassRole", allowing it to pass high-privilege service roles to EC2 instances, Lambda functions, or ECS tasks, effectively executing arbitrary code with full cloud administrative rights.`;
    } else if (escalationPerms.some((p) => p.action.includes('AssumeRole'))) {
      threatExplanation = `Lateral Pivoting & Trust Chain Hijacking: Contains "sts:AssumeRole" trust relationships allowing this identity to impersonate other elevated service roles and pivot laterally toward sensitive database tiers.`;
    } else if (escalationPerms.some((p) => p.action.includes('*'))) {
      threatExplanation = `Administrative Blast Radius: Contains wildcard (*) actions granting unrestricted API control across cloud services, capable of overriding security controls of other users.`;
    } else if (inspectPrincipal.daysInactive >= 90) {
      threatExplanation = `Dormant Backdoor Risk: Dormant for ${inspectPrincipal.daysInactive} days with static credentials, allowing an adversary to establish persistent unmonitored footholds to target peer accounts.`;
    } else {
      threatExplanation = `Low Lateral Threat: Current permissions are scoped without administrative role assignment or cross-account trust escalation capabilities.`;
    }

    return {
      principal: inspectPrincipal,
      metrics: m,
      totalGranted,
      totalUsed,
      totalUnused,
      unusedPct,
      riskScore,
      isDangerous,
      entitlementStatus,
      escalationPerms,
      canPoseThreatToOthers,
      threatExplanation,
    };
  }, [inspectPrincipal, riskMetrics]);

  return (
    <div className="space-y-6">
      {/* Page Title & Context Header */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <KeyRound className="w-6 h-6 text-rose-400" />
          <span>CIEM & Over-Privilege Analyzer</span>
        </h1>
        <p className="text-sm text-slate-400">
          Comprehensive inventory of all cloud identities, assigned roles, and granted vs. verified used permissions. Inspect any identity for full entitlement balance, lateral threat propagation, and AI remediation.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center gap-3 flex-wrap flex-1">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search by identity name, ARN, or department..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Type Filter */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Principal Types</option>
            <option value="User">Users</option>
            <option value="Role">Roles</option>
            <option value="ServiceAccount">Service Accounts</option>
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <strong className="text-white">{displayedPrincipals.length}</strong> Identities in Dataset
        </div>
      </div>

      {/* Main Table Showing All Identities, Permissions, and Roles */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                <th className="py-3 px-4">Identity Name / ARN</th>
                <th className="py-3 px-4">Type & Provider</th>
                <th className="py-3 px-4">Assigned Roles & Policies</th>
                <th className="py-3 px-4">Granted Permissions</th>
                <th className="py-3 px-4">Verified Used</th>
                <th className="py-3 px-4">Unused Ratio</th>
                <th className="py-3 px-4 text-right">Inspection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {displayedPrincipals.map((p) => {
                const m = riskMetrics.get(p.id);
                const totalGranted = p.grantedPermissions.length;
                const totalUsed = p.grantedPermissions.filter((x) => x.isUsed).length;
                const unusedPct = totalGranted > 0 ? Math.round(((totalGranted - totalUsed) / totalGranted) * 100) : 0;

                return (
                  <tr key={p.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-sans">
                      <div className="font-semibold text-slate-100">{p.name}</div>
                      <div className="text-[10px] text-slate-500 font-mono truncate max-w-[210px]">
                        {p.arn}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                        {p.type} • {p.provider}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <div className="flex flex-wrap gap-1 max-w-[180px]">
                        {p.attachedPolicies && p.attachedPolicies.length > 0 ? (
                          p.attachedPolicies.map((pol, idx) => (
                            <span
                              key={idx}
                              className="text-[10px] px-1.5 py-0.2 rounded bg-purple-950/80 text-purple-300 border border-purple-900/60 font-mono"
                            >
                              {pol}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 text-[10px]">Inline Only</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      {totalGranted} Actions
                    </td>
                    <td className="py-3 px-4 text-emerald-400 font-semibold">
                      {totalUsed} Actions
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-1.5 rounded-full ${
                              unusedPct > 60 ? 'bg-rose-500' : 'bg-amber-500'
                            }`}
                            style={{ width: `${unusedPct}%` }}
                          />
                        </div>
                        <span className={unusedPct > 60 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                          {unusedPct}%
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => setInspectPrincipal(p)}
                        className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold transition cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* INSPECT MODAL: FULL ENTITLEMENT, RISK SCORE, DANGEROUS/SECURE, LATERAL THREAT & AI TEXT GENERATOR */}
      {inspectData && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <KeyRound className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <span>Identity Entitlement & Threat Inspection: {inspectData.principal.name}</span>
                  </h3>
                  <p className="text-xs text-cyan-300 font-mono mt-0.5">{inspectData.principal.arn}</p>
                </div>
              </div>
              <button
                onClick={() => setInspectPrincipal(null)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-200">
              {/* Row 1: 4 Core Identity Factors (Risk Score, Active/Unused Days, Secure vs Dangerous, Over vs Underprivileged) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {/* 1. Risk Score */}
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-slate-400 font-semibold">Risk Score</div>
                  <div className="text-2xl font-bold font-mono text-white flex items-baseline gap-1">
                    <span
                      className={
                        inspectData.riskScore >= 75
                          ? 'text-rose-400'
                          : inspectData.riskScore >= 50
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }
                    >
                      {inspectData.riskScore}
                    </span>
                    <span className="text-slate-500 text-xs">/ 100</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Category: <strong className="text-white">{inspectData.metrics?.riskCategory}</strong>
                  </div>
                </div>

                {/* 2. Days Active vs Unused */}
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-slate-400 font-semibold">Activity Duration</div>
                  <div className="text-xl font-bold font-mono text-white mt-1">
                    <span className={inspectData.principal.daysInactive > 90 ? 'text-purple-400' : 'text-emerald-400'}>
                      {inspectData.principal.daysInactive} Days Inactive
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {inspectData.principal.daysInactive > 90 ? 'Dormant Account Violation' : 'Active Account'}
                  </div>
                </div>

                {/* 3. Secure vs Dangerous Status */}
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-slate-400 font-semibold">Security Posture</div>
                  <div className="mt-1">
                    {inspectData.isDangerous ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold font-mono bg-rose-950 text-rose-300 border border-rose-800">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>DANGEROUS</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>SECURE</span>
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {inspectData.isDangerous ? 'High attack surface detected' : 'Acceptable trust state'}
                  </div>
                </div>

                {/* 4. Overprivileged vs Underprivileged */}
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-slate-400 font-semibold">Entitlement Balance</div>
                  <div className="mt-1">
                    {inspectData.entitlementStatus === 'OVERPRIVILEGED' ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold font-mono bg-rose-950 text-rose-300 border border-rose-800">
                        <span>OVERPRIVILEGED</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                        <span>RIGHT-SIZED</span>
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    <strong className="text-rose-400">{inspectData.unusedPct}%</strong> unused permissions
                  </div>
                </div>
              </div>

              {/* Row 2: Can Permissions Pose Threat to Other Identities? (HOW?) */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs uppercase font-mono font-bold text-amber-400">
                    <AlertOctagon className="w-4 h-4 text-amber-400" />
                    <span>Can this identity pose a threat to other identities?</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      inspectData.canPoseThreatToOthers
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}
                  >
                    {inspectData.canPoseThreatToOthers ? 'YES (CRITICAL VECTOR)' : 'NO (RESTRICTED SCOPE)'}
                  </span>
                </div>

                <div className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-850">
                  <p className="font-semibold text-white mb-1">
                    Lateral Threat & Privilege Escalation Analysis:
                  </p>
                  <p className="text-slate-300 leading-relaxed">{inspectData.threatExplanation}</p>
                  {inspectData.escalationPerms.length > 0 && (
                    <div className="pt-2 flex flex-wrap gap-1.5">
                      <span className="text-[10px] text-slate-400 font-mono self-center">Escalation Actions:</span>
                      {inspectData.escalationPerms.map((ep) => (
                        <span
                          key={ep.id}
                          className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-900 text-[10px] font-mono"
                        >
                          {ep.action}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Row 3: AI TEXT GENERATOR: Detailed narrative and HOW TO SOLVE */}
              <div className="p-5 rounded-xl bg-gradient-to-r from-slate-950 to-slate-900 border border-cyan-800/60 space-y-3">
                <div className="flex items-center gap-2 text-cyan-300 font-bold text-xs uppercase font-mono">
                  <Bot className="w-4 h-4 text-cyan-400" />
                  <span>AI Security Assessment & Step-by-Step Remediation Plan</span>
                </div>

                <div className="text-xs text-slate-300 leading-relaxed space-y-3 font-sans">
                  <p>
                    <strong>Automated AI Evaluation:</strong> Principal <code className="text-cyan-300 font-mono">{inspectData.principal.name}</code> ({inspectData.principal.type}) is evaluated as <strong className={inspectData.isDangerous ? 'text-rose-400' : 'text-emerald-400'}>{inspectData.isDangerous ? 'DANGEROUS' : 'SECURE'}</strong> under Zero Trust NIST SP 800-207 guidelines. It possesses <strong>{inspectData.totalGranted}</strong> total granted permissions, but CloudTrail records verify that only <strong>{inspectData.totalUsed}</strong> actions have ever been exercised, rendering it <strong>{inspectData.unusedPct}% overprivileged</strong>.
                  </p>

                  <div>
                    <h4 className="font-bold text-white uppercase text-[11px] font-mono mb-1.5 text-cyan-400">
                      Step-by-Step Detailed Solution:
                    </h4>
                    <ol className="list-decimal list-inside space-y-1.5 text-slate-300 pl-1">
                      <li>
                        <strong>Strip Unexercised Actions:</strong> Detach existing high-privilege managed policies (e.g., {inspectData.principal.attachedPolicies.join(', ') || 'AdministratorAccess'}) and replace them with a least-privilege policy containing solely the verified actions [{inspectData.principal.grantedPermissions.filter((p) => p.isUsed).map((p) => p.action).join(', ') || 'ReadOnly'}].
                      </li>
                      {inspectData.escalationPerms.length > 0 && (
                        <li>
                          <strong>Revoke Privilege Escalation Vectors:</strong> Sever permissions such as <code className="text-rose-300 font-mono">{inspectData.escalationPerms.map((p) => p.action).join(', ')}</code> to neutralize lateral attack chains leading to database and secret resources.
                        </li>
                      )}
                      {inspectData.principal.daysInactive >= 90 && (
                        <li>
                          <strong>Quarantine Dormant Credential:</strong> Inactivity duration ({inspectData.principal.daysInactive} days) violates the 90-day organizational credential retention policy. Deactivate active access keys and disable console sign-in immediately.
                        </li>
                      )}
                      {!inspectData.principal.mfaEnabled && inspectData.principal.type === 'User' && (
                        <li>
                          <strong>Enforce Mandatory Hardware MFA:</strong> Apply IAM conditional access requiring <code className="text-cyan-300 font-mono">aws:MultiFactorAuthPresent: "true"</code> before granting any API invocation capability.
                        </li>
                      )}
                      <li>
                        <strong>Continuous Audit Telemetry:</strong> Subscribe this identity's ARN to Amazon EventBridge alerts for unexpected CloudTrail API calls outside normal baseline operational hours.
                      </li>
                    </ol>
                  </div>
                </div>
              </div>

              {/* Row 4: Side-by-side Granted vs. Used Matrix */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                {/* Granted */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-mono font-semibold text-slate-300 uppercase">
                    <span>Configured IAM Permissions ({inspectData.totalGranted})</span>
                    <span className="text-slate-500">IAM Policy</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto space-y-1 pr-1">
                    {inspectData.principal.grantedPermissions.map((perm) => (
                      <div
                        key={perm.id}
                        className={`p-2 rounded-lg border text-xs font-mono flex items-center justify-between ${
                          perm.isUsed
                            ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
                            : 'bg-rose-950/20 border-rose-800/40 text-rose-200'
                        }`}
                      >
                        <div className="flex items-center gap-1.5">
                          {perm.isUsed ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                          )}
                          <span>{perm.action}</span>
                        </div>
                        {perm.isDangerous && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-900/60 text-rose-200 font-sans">
                            PrivEsc
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Used */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-mono font-semibold text-slate-300 uppercase">
                    <span>CloudTrail Invocations ({inspectData.totalUsed})</span>
                    <span className="text-emerald-400">Active Usage</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto space-y-1 pr-1">
                    {inspectData.principal.grantedPermissions.filter((p) => p.isUsed).length > 0 ? (
                      inspectData.principal.grantedPermissions
                        .filter((p) => p.isUsed)
                        .map((perm) => (
                          <div
                            key={`used-${perm.id}`}
                            className="p-2 rounded-lg bg-emerald-950/30 border border-emerald-800 text-xs font-mono text-emerald-300 flex items-center justify-between"
                          >
                            <span>{perm.action}</span>
                            <span className="text-[10px] text-emerald-400/80">Active</span>
                          </div>
                        ))
                    ) : (
                      <div className="p-6 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                        Zero recorded API invocations in CloudTrail audit logs.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
              <span className="text-xs text-slate-400">
                Identity status: <strong className="text-white font-mono">{inspectData.entitlementStatus}</strong> (
                {inspectData.unusedPct}% unexercised).
              </span>
              <button
                onClick={() => setInspectPrincipal(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer"
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
