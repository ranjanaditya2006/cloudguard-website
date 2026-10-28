import React, { useState, useMemo } from 'react';
import {
  FileCheck2,
  Copy,
  Check,
  Download,
  Terminal,
  FileCode,
  FileText,
  Printer,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  X,
  Layers,
  ArrowRight,
  ListOrdered,
  Key,
  Lock,
} from 'lucide-react';
import { IAMDataSet, Principal, IdentityRiskMetrics } from '../../types/iam';
import { generateLeastPrivilegePolicy, RemediationPackage } from '../../engine/policyGenerator';

interface RemediationViewProps {
  dataset: IAMDataSet;
  riskMetrics: Map<string, IdentityRiskMetrics>;
  preselectedPrincipalId?: string;
}

export const RemediationView: React.FC<RemediationViewProps> = ({
  dataset,
  riskMetrics,
  preselectedPrincipalId,
}) => {
  const [selectedId, setSelectedId] = useState<string>(
    preselectedPrincipalId || dataset.principals[0]?.id || ''
  );
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showAuditReportModal, setShowAuditReportModal] = useState(false);

  // If preselectedPrincipalId changes, update selectedId
  React.useEffect(() => {
    if (preselectedPrincipalId && dataset.principals.some((p) => p.id === preselectedPrincipalId)) {
      setSelectedId(preselectedPrincipalId);
    }
  }, [preselectedPrincipalId, dataset.principals]);

  // Keep selectedId valid if dataset changes
  React.useEffect(() => {
    if (!dataset.principals.some((p) => p.id === selectedId)) {
      setSelectedId(dataset.principals[0]?.id || '');
    }
  }, [dataset.principals]);

  const selectedPrincipal = dataset.principals.find((p) => p.id === selectedId);
  const selectedMetrics = selectedPrincipal ? riskMetrics.get(selectedPrincipal.id) : null;

  // Generate dynamic remediation package for selected identity
  const remediationPackage: RemediationPackage | null = useMemo(() => {
    if (!selectedPrincipal) return null;
    return generateLeastPrivilegePolicy(selectedPrincipal);
  }, [selectedPrincipal]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadJsonPolicy = () => {
    if (!remediationPackage || !selectedPrincipal) return;
    const blob = new Blob([remediationPackage.leastPrivilegePolicyJson], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedPrincipal.name}-least-privilege-policy.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Specific dynamic steps to right-size this identity
  const rightSizeSteps = useMemo(() => {
    if (!selectedPrincipal || !remediationPackage) return [];

    const unusedPerms = selectedPrincipal.grantedPermissions.filter((p) => !p.isUsed);
    const usedPerms = selectedPrincipal.grantedPermissions.filter((p) => p.isUsed);
    const steps: { title: string; instruction: string; detail: string; command?: string }[] = [];

    // Step 1: Baseline Entitlement Pruning
    steps.push({
      title: 'Step 1: Audit & Prune Unexercised Permissions',
      instruction: `Retain strictly the ${usedPerms.length} verified actions exercised in audit telemetry and strip all ${unusedPerms.length} unexercised actions.`,
      detail: `Unused actions identified: [${unusedPerms.slice(0, 4).map((u) => u.action).join(', ')}${unusedPerms.length > 4 ? ` + ${unusedPerms.length - 4} more` : ''}]. These permissions have zero recorded invocations in audit logs.`,
    });

    // Step 2: Policy Detachment / Replacement
    steps.push({
      title: 'Step 2: Replace Broad Policies with Least-Privilege Document',
      instruction: `Detach existing managed policies (${selectedPrincipal.attachedPolicies.join(', ') || 'AdministratorAccess'}) and attach the right-sized JSON policy.`,
      detail: `Applying the least-privilege document reduces the attack blast radius by ${Math.round((remediationPackage.removedPermissionsCount / Math.max(1, selectedPrincipal.grantedPermissions.length)) * 100)}%.`,
      command: `aws iam put-${selectedPrincipal.type === 'Role' ? 'role' : 'user'}-policy --${selectedPrincipal.type === 'Role' ? 'role' : 'user'}-name ${selectedPrincipal.name} --policy-name ${selectedPrincipal.name}-LeastPrivilege --policy-document file://policy.json`,
    });

    // Step 3: Neutralize Escalation Backdoors (if PassRole / AssumeRole exists)
    if (selectedPrincipal.grantedPermissions.some((p) => p.action.includes('PassRole') || p.action.includes('AssumeRole'))) {
      steps.push({
        title: 'Step 3: Restrict Role Assumption & PassRole Trust Boundary',
        instruction: `Place explicit Resource ARN constraints on "iam:PassRole" and "sts:AssumeRole" to prevent privilege escalation to Crown Jewels.`,
        detail: `Wildcard PassRole grants allow passing arbitrary roles to compute instances. Constrain target role ARNs to only designated worker roles.`,
      });
    }

    // Step 4: Credential Rotation / Dormancy Handling
    if (selectedPrincipal.daysInactive >= 90) {
      steps.push({
        title: 'Step 4: Quarantine Dormant Account & Revoke Active Sessions',
        instruction: `Account has been dormant for ${selectedPrincipal.daysInactive} days (exceeds 90-day Zero Trust threshold). Deactivate active access keys immediately.`,
        detail: `Execute immediate credential revocation to eliminate unmonitored shadow access vectors.`,
        command: `aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name ${selectedPrincipal.name}`,
      });
    } else if (selectedPrincipal.unrotatedKeysCount > 0) {
      steps.push({
        title: 'Step 4: Rotate Static Access Keys',
        instruction: `Identity holds ${selectedPrincipal.unrotatedKeysCount} access keys exceeding the 90-day rotation cycle.`,
        detail: `Generate a new keypair, update consuming applications, and delete the legacy unrotated access key.`,
      });
    }

    // Step 5: Multi-Factor Authentication (MFA)
    if (!selectedPrincipal.mfaEnabled && selectedPrincipal.type === 'User') {
      steps.push({
        title: 'Step 5: Enforce Mandatory Hardware/TOTP MFA',
        instruction: `Enable multi-factor authentication and attach a conditional Deny policy for API actions when MFA is not active.`,
        detail: `Add condition {"Bool": {"aws:MultiFactorAuthPresent": "true"}} to block non-MFA sessions.`,
      });
    }

    // Step 6: Continuous Telemetry Monitoring
    steps.push({
      title: 'Step 6: Monitor CloudTrail Telemetry for Access Regressions',
      instruction: `Monitor CloudWatch Alarms for "AccessDenied" events for 72 hours post-remediation to confirm uninterrupted operations.`,
      detail: `If legitimate operational traffic requires additional actions, incrementally add scoped permissions following strict change management.`,
    });

    return steps;
  }, [selectedPrincipal, remediationPackage]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1 max-w-2xl">
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileCheck2 className="w-6 h-6 text-emerald-400" />
            <span>Remediation & Least-Privilege Right-Sizing</span>
          </h1>
          <p className="text-xs text-slate-400 leading-relaxed">
            Dynamic right-sizing engine synthesizing fine-grained, Zero-Trust IAM policies, Terraform infrastructure-as-code, and AWS CLI commands based on verified CloudTrail audit history.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAuditReportModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/20 transition cursor-pointer"
          >
            <Printer className="w-4 h-4" />
            <span>Print Executive Audit Report</span>
          </button>
        </div>
      </div>

      {/* Identity Selector Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <span className="text-xs font-mono text-slate-300 font-semibold uppercase">
            Select Identity to Right-Size:
          </span>
          <select
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {dataset.principals.map((p) => {
              const unusedCount = p.grantedPermissions.filter((x) => !x.isUsed).length;
              return (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.type} • {unusedCount} unused actions • {p.provider})
                </option>
              );
            })}
          </select>
        </div>

        {remediationPackage && (
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-800">
              - {remediationPackage.removedPermissionsCount} Unused Actions Pruned
            </span>
            <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
              + {remediationPackage.retainedPermissionsCount} Active Actions Retained
            </span>
          </div>
        )}
      </div>

      {selectedPrincipal && remediationPackage && (
        <div className="space-y-6">
          {/* DETAILED INFORMATION: WHAT DATA SHOULD BE CHANGED & HOW */}
          <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <h2 className="text-base font-bold text-white">
                  Target Identity Change Specification: {selectedPrincipal.name}
                </h2>
              </div>
              <span className="text-xs font-mono text-slate-400">{selectedPrincipal.arn}</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              {/* Box 1: What Data Should Be Changed */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-850 space-y-2.5">
                <div className="text-rose-400 font-bold font-mono text-xs uppercase flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  <span>1. What Data Must Be Changed</span>
                </div>
                <ul className="space-y-1.5 text-slate-300 leading-relaxed font-sans">
                  <li>
                    <strong>Excessive Unexercised Privileges:</strong> Strip <strong>{remediationPackage.removedPermissionsCount}</strong> granted actions with 0 CloudTrail invocations.
                  </li>
                  {selectedPrincipal.grantedPermissions.some((p) => p.action.includes('*')) && (
                    <li className="text-rose-300">
                      <strong>Wildcard Actions:</strong> Eliminate wildcard (*) grants that allow unrestricted cross-service control.
                    </li>
                  )}
                  {selectedPrincipal.grantedPermissions.some((p) => p.action.includes('PassRole')) && (
                    <li className="text-rose-300">
                      <strong>Privilege Escalation Vector:</strong> Remove unrestricted <code className="text-amber-300">iam:PassRole</code> enabling lateral traversal.
                    </li>
                  )}
                  {selectedPrincipal.attachedPolicies.length > 0 && (
                    <li>
                      <strong>Attached Policies:</strong> Detach vendor/broad policies: <code className="text-purple-300 font-mono">{selectedPrincipal.attachedPolicies.join(', ')}</code>.
                    </li>
                  )}
                  {selectedPrincipal.daysInactive >= 90 && (
                    <li className="text-purple-300">
                      <strong>Dormant Credentials:</strong> Inactive for <strong>{selectedPrincipal.daysInactive} days</strong>. Access keys must be deactivated.
                    </li>
                  )}
                </ul>
              </div>

              {/* Box 2: How It Should Be Changed */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-850 space-y-2.5">
                <div className="text-emerald-400 font-bold font-mono text-xs uppercase flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>2. How To Change It (Target State)</span>
                </div>
                <ul className="space-y-1.5 text-slate-300 leading-relaxed font-sans">
                  <li>
                    <strong>Scoped Action Allowlist:</strong> Generate fine-grained policy retaining strictly the <strong>{remediationPackage.retainedPermissionsCount}</strong> active verified actions.
                  </li>
                  <li>
                    <strong>Resource-Level ARN Scoping:</strong> Replace global wildcard <code className="text-slate-400">Resource: "*"</code> with explicit resource ARNs.
                  </li>
                  <li>
                    <strong>Least-Privilege Policy Attachment:</strong> Deploy the generated policy document via Terraform HCL or AWS CLI.
                  </li>
                  {!selectedPrincipal.mfaEnabled && selectedPrincipal.type === 'User' && (
                    <li>
                      <strong>Enforce Multi-Factor Authentication:</strong> Inject IAM condition block requiring valid MFA token.
                    </li>
                  )}
                  <li>
                    <strong>Automate Drift Detection:</strong> Establish daily CloudTrail comparison to catch newly required entitlements before granting.
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* SPECIFIC STEP-BY-STEP PROCEDURE FOR RIGHT-SIZING THIS IDENTITY */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-2">
              <ListOrdered className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white">
                Step-by-Step Right-Sizing Procedure for {selectedPrincipal.name}
              </h3>
            </div>
            <p className="text-xs text-slate-400">
              Follow these sequential steps to safely transition this identity to a verifiable least-privilege state without operational breakage.
            </p>

            <div className="space-y-3 pt-1">
              {rightSizeSteps.map((step, idx) => (
                <div
                  key={idx}
                  className="bg-slate-950 p-4 rounded-xl border border-slate-850 space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="font-bold text-white text-xs flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center justify-center font-mono text-[11px]">
                        {idx + 1}
                      </span>
                      <span>{step.title}</span>
                    </div>
                  </div>

                  <p className="text-slate-200 font-medium">{step.instruction}</p>
                  <p className="text-slate-400 text-[11px] leading-relaxed">{step.detail}</p>

                  {step.command && (
                    <div className="pt-1">
                      <div className="flex items-center justify-between bg-slate-900 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-amber-300 overflow-x-auto">
                        <code>{step.command}</code>
                        <button
                          onClick={() => copyToClipboard(step.command!, `step-${idx}`)}
                          className="ml-2 text-slate-400 hover:text-white shrink-0 cursor-pointer"
                        >
                          {copiedKey === `step-${idx}` ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* VISUAL POLICY DIFF & EXPORTERS */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left Column: Visual Git-Style Policy Diff */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <h3 className="font-semibold text-white text-sm">Visual Policy Diff (PoLP Right-Sizing)</h3>
                </div>
                <span className="text-[10px] font-mono text-slate-400">Git Line Diff</span>
              </div>

              <div className="bg-slate-950 rounded-xl p-4 font-mono text-xs max-h-[460px] overflow-y-auto space-y-0.5 border border-slate-850">
                {remediationPackage.diffHtml.map((item, idx) => (
                  <div
                    key={idx}
                    className={`py-0.5 px-2 rounded ${
                      item.type === 'removed'
                        ? 'bg-rose-950/40 text-rose-300 line-through decoration-rose-500/80'
                        : item.type === 'added'
                        ? 'bg-emerald-950/40 text-emerald-300 font-bold'
                        : 'text-slate-400'
                    }`}
                  >
                    {item.line}
                  </div>
                ))}
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  onClick={downloadJsonPolicy}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-medium transition cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Least-Privilege JSON</span>
                </button>
              </div>
            </div>

            {/* Right Column: Multi-Format Infrastructure-as-Code Exporters */}
            <div className="space-y-4">
              {/* Terraform Snippet */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-purple-400" />
                    <h3 className="font-semibold text-white text-sm">Terraform (HCL) Infrastructure-as-Code</h3>
                  </div>
                  <button
                    onClick={() => copyToClipboard(remediationPackage.terraformCode, 'terraform')}
                    className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition cursor-pointer"
                  >
                    {copiedKey === 'terraform' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span>{copiedKey === 'terraform' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-850 text-purple-300 font-mono text-xs max-h-52 overflow-y-auto leading-relaxed">
                  {remediationPackage.terraformCode}
                </pre>
              </div>

              {/* AWS CLI One-Liner */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-amber-400" />
                    <h3 className="font-semibold text-white text-sm">AWS CLI Immediate Remediation Command</h3>
                  </div>
                  <button
                    onClick={() => copyToClipboard(remediationPackage.awsCliCommand, 'cli')}
                    className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition cursor-pointer"
                  >
                    {copiedKey === 'cli' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span>{copiedKey === 'cli' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-850 text-amber-300 font-mono text-xs max-h-36 overflow-y-auto leading-relaxed">
                  {remediationPackage.awsCliCommand}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Executive Security Audit Report Printable Modal */}
      {showAuditReportModal && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto p-6 sm:p-8 space-y-6 shadow-2xl text-slate-200">
            {/* Modal Controls */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 print:hidden">
              <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                <FileText className="w-5 h-5" />
                <span>Executive Cloud Identity Risk & Remediation Audit Report</span>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => window.print()}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold transition cursor-pointer"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Print / Save PDF</span>
                </button>
                <button
                  onClick={() => setShowAuditReportModal(false)}
                  className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Header */}
            <div className="text-center space-y-1 pb-4 border-b border-slate-800">
              <h2 className="text-xl font-bold text-white pt-1">
                Cloud Identity Risk & Entitlement Audit Report
              </h2>
              <div className="text-xs text-cyan-400 font-mono">
                Continuous PoLP & Zero Trust Governance Analysis • Active Dataset: {dataset.name}
              </div>
            </div>

            {/* Executive Summary */}
            <div className="space-y-2 text-xs leading-relaxed text-slate-300">
              <h3 className="font-bold text-white uppercase font-mono text-sm">1. Executive Summary</h3>
              <p>
                An automated access graph evaluation was conducted on dataset <strong>"{dataset.name}"</strong> to identify over-privileged accounts, evaluate temporal trust decay on dormant credentials, and simulate multi-hop privilege escalation pathways.
              </p>
            </div>

            {/* Findings Summary Table */}
            <div className="space-y-2">
              <h3 className="font-bold text-white uppercase font-mono text-sm">2. Core Risk Assessment</h3>
              <table className="w-full text-left text-xs border border-slate-800">
                <thead className="bg-slate-950 font-mono text-[11px] text-slate-400">
                  <tr>
                    <th className="p-2 border-b border-slate-800">Principal</th>
                    <th className="p-2 border-b border-slate-800">Type</th>
                    <th className="p-2 border-b border-slate-800">Inactivity</th>
                    <th className="p-2 border-b border-slate-800">Over-Privilege</th>
                    <th className="p-2 border-b border-slate-800">Composite Risk</th>
                    <th className="p-2 border-b border-slate-800">Category</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {dataset.principals.map((p) => {
                    const m = riskMetrics.get(p.id)!;
                    return (
                      <tr key={p.id}>
                        <td className="p-2 font-semibold text-slate-200">{p.name}</td>
                        <td className="p-2">{p.type}</td>
                        <td className="p-2">{p.daysInactive} days</td>
                        <td className="p-2">{Math.round((m?.overPrivilegeScore || 0) * 100)}%</td>
                        <td className="p-2 font-bold">{m?.compositeRiskScore || 0} / 100</td>
                        <td className="p-2 text-rose-400 font-bold">{m?.riskCategory || 'LOW'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Zero Trust Recommendation */}
            <div className="space-y-2 text-xs leading-relaxed bg-slate-950 p-4 rounded-xl border border-slate-800">
              <h3 className="font-bold text-white uppercase font-mono">3. Zero-Trust Action Items</h3>
              <p>
                <strong>Immediate Right-Sizing:</strong> Remove all unexercised privileges identified across the dataset to reduce the attack blast radius.
              </p>
              <p>
                <strong>Credential Quarantine:</strong> Deactivate access keys for all accounts inactive for 90 days or longer.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
