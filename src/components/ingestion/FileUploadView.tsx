import React, { useState, useRef, useMemo } from 'react';
import {
  UploadCloud,
  FileArchive,
  FileJson,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  FolderArchive,
  UserX,
  UserCheck,
  Lock,
  ArrowRight,
} from 'lucide-react';
import { IAMDataSet, Principal } from '../../types/iam';
import { parseUploadedFile, ParseResult } from '../../engine/fileParser';
import { computePrincipalRisk, DEFAULT_WEIGHTS } from '../../engine/riskScoring';
import { AccessGraphEngine } from '../../engine/graphEngine';

interface FileUploadViewProps {
  currentDataset: IAMDataSet;
  onDatasetLoaded: (newDataset: IAMDataSet) => void;
  onResetToDemo?: () => void;
}

export const FileUploadView: React.FC<FileUploadViewProps> = ({
  currentDataset,
  onDatasetLoaded,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [parseStatus, setParseStatus] = useState<ParseResult | null>(null);
  const [identityFilter, setIdentityFilter] = useState<'ALL' | 'CRITICAL' | 'VULNERABLE' | 'SECURED'>('ALL');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    setIsProcessing(true);
    setParseStatus(null);

    try {
      const result = await parseUploadedFile(file);
      setParseStatus(result);
      if (result.success && result.dataset) {
        onDatasetLoaded(result.dataset);
      }
    } catch (err: any) {
      setParseStatus({
        success: false,
        errorMessage: err.message || 'Failed to process file.',
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  // Graph engine and risk evaluation for active dataset
  const graphEngine = useMemo(() => {
    return new AccessGraphEngine(
      currentDataset.principals,
      currentDataset.resources,
      currentDataset.edges
    );
  }, [currentDataset]);

  // Risk metrics for all principals in current dataset
  const riskAnalysis = useMemo(() => {
    const principals = currentDataset.principals;
    let totalGranted = 0;
    let totalUsed = 0;

    const classified = principals.map((p) => {
      const reachableJewels = graphEngine.getReachableCrownJewels(p.id);
      const metrics = computePrincipalRisk(
        p,
        reachableJewels.length,
        reachableJewels.length,
        DEFAULT_WEIGHTS
      );

      p.grantedPermissions.forEach((perm) => {
        totalGranted++;
        if (perm.isUsed) totalUsed++;
      });

      const isUnused = p.daysInactive >= 90 || p.grantedPermissions.every((perm) => !perm.isUsed);
      const isCritical = metrics.compositeRiskScore >= 75 || metrics.riskCategory === 'CRITICAL';
      const isVulnerable = !isCritical && (metrics.compositeRiskScore >= 40 || metrics.overPrivilegeScore > 0.5 || isUnused);
      const isSecured = !isCritical && !isVulnerable;

      return {
        principal: p,
        metrics,
        isUnused,
        isCritical,
        isVulnerable,
        isSecured,
      };
    });

    const totalUnused = totalGranted - totalUsed;
    const unusedPermRatio = totalGranted > 0 ? (totalUnused / totalGranted) * 100 : 0;
    const usedPermRatio = totalGranted > 0 ? (totalUsed / totalGranted) * 100 : 0;

    const criticalList = classified.filter((c) => c.isCritical);
    const vulnerableList = classified.filter((c) => c.isVulnerable);
    const securedList = classified.filter((c) => c.isSecured);

    const unusedIdentities = classified.filter((c) => c.isUnused);
    const activeIdentities = classified.filter((c) => !c.isUnused);

    const avgRiskScore =
      classified.length > 0
        ? Math.round(
            classified.reduce((acc, c) => acc + c.metrics.compositeRiskScore, 0) /
              classified.length
          )
        : 0;

    return {
      classified,
      avgRiskScore,
      totalGranted,
      totalUsed,
      totalUnused,
      unusedPermRatio: Math.round(unusedPermRatio * 10) / 10,
      usedPermRatio: Math.round(usedPermRatio * 10) / 10,
      criticalList,
      vulnerableList,
      securedList,
      unusedIdentities,
      activeIdentities,
      vulnerableRatio: principals.length > 0 ? Math.round(((criticalList.length + vulnerableList.length) / principals.length) * 100) : 0,
      securedRatio: principals.length > 0 ? Math.round((securedList.length / principals.length) * 100) : 0,
    };
  }, [currentDataset, graphEngine]);

  const filteredIdentities = useMemo(() => {
    if (identityFilter === 'CRITICAL') return riskAnalysis.classified.filter((c) => c.isCritical);
    if (identityFilter === 'VULNERABLE') return riskAnalysis.classified.filter((c) => c.isVulnerable);
    if (identityFilter === 'SECURED') return riskAnalysis.classified.filter((c) => c.isSecured);
    return riskAnalysis.classified;
  }, [riskAnalysis, identityFilter]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Page Header */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <UploadCloud className="w-6 h-6 text-cyan-400" />
          <span>Data Ingestion & Archive Risk Analyzer</span>
        </h1>
        <p className="text-sm text-slate-400">
          Upload any cloud IAM archive (.zip containing users, roles, and cloudtrail JSONs) or standalone export (.json). Instant client-side decompression with real-time risk synthesis.
        </p>
      </div>

      {/* Drag & Drop Upload Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-2xl p-8 sm:p-10 text-center transition cursor-pointer relative overflow-hidden ${
          isDragging
            ? 'border-cyan-400 bg-cyan-950/30'
            : 'border-slate-800 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900/90'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip,.json,.tar.gz"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              handleFile(e.target.files[0]);
            }
          }}
        />

        <div className="flex flex-col items-center justify-center space-y-3 max-w-md mx-auto">
          <div className="p-4 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            {isProcessing ? (
              <RefreshCw className="w-8 h-8 animate-spin" />
            ) : (
              <FolderArchive className="w-8 h-8" />
            )}
          </div>

          <div className="space-y-1">
            <div className="text-base font-semibold text-white">
              {isProcessing ? 'Decompressing & Computing File Risk Score...' : 'Upload or Drag & Drop Cloud IAM Archive'}
            </div>
            <p className="text-xs text-slate-400">
              Drop a <code className="text-cyan-300 font-mono">.zip</code> archive or <code className="text-cyan-300 font-mono">.json</code> file to recompute the entire dashboard.
            </p>
          </div>

          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-950 text-slate-400 text-[11px] font-mono border border-slate-800">
            <span>Client-side in-memory extraction • Zero data leaves your browser</span>
          </div>
        </div>
      </div>

      {/* Ingestion Feedback Banner */}
      {parseStatus && (
        <div
          className={`p-4 rounded-xl border flex items-start gap-3 ${
            parseStatus.success
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
              : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
          }`}
        >
          {parseStatus.success ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          )}

          <div className="space-y-1 text-xs">
            <div className="font-semibold text-sm">
              {parseStatus.success ? 'Archive Successfully Ingested & Dashboard Recalculated' : 'Ingestion Error'}
            </div>
            <p>
              {parseStatus.success
                ? `Loaded "${currentDataset.name}" containing ${parseStatus.stats?.principalsCount} Principals, ${parseStatus.stats?.resourcesCount} Cloud Resources, and ${parseStatus.stats?.edgesCount} Relationship Edges.`
                : parseStatus.errorMessage}
            </p>
            {parseStatus.filesFound && (
              <div className="font-mono text-[11px] text-slate-300 pt-1">
                Extracted Files: {parseStatus.filesFound.join(', ')}
              </div>
            )}
          </div>
        </div>
      )}

      {/* CORE FILE RISK & RATIO SUMMARY CARD */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                Active Ingested File
              </span>
              <span className="text-xs font-mono text-slate-400">{currentDataset.name}</span>
            </div>
            <h2 className="text-xl font-bold text-white mt-1">
              File Security Posture & Entitlement Ratio Breakdown
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              All metrics and simulation graphs across this dashboard are dynamically calculated from this dataset.
            </p>
          </div>

          {/* Radial / Score Badge for the File */}
          <div className="flex items-center gap-4 bg-slate-950 p-4 rounded-xl border border-slate-800 shrink-0">
            <div className="relative w-16 h-16 flex items-center justify-center">
              <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`${
                    riskAnalysis.avgRiskScore > 65
                      ? 'text-rose-500'
                      : riskAnalysis.avgRiskScore > 40
                      ? 'text-amber-500'
                      : 'text-emerald-500'
                  } transition-all duration-1000 ease-out`}
                  strokeDasharray={`${riskAnalysis.avgRiskScore}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute text-center">
                <span className="text-lg font-bold font-mono text-white">{riskAnalysis.avgRiskScore}</span>
                <span className="block text-[8px] text-slate-400 font-sans">/ 100</span>
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase font-mono text-slate-400 font-semibold">File Risk Score</div>
              <div className="text-sm font-bold text-white">
                {riskAnalysis.avgRiskScore > 65
                  ? 'CRITICAL RISK'
                  : riskAnalysis.avgRiskScore > 40
                  ? 'MODERATE RISK'
                  : 'SECURED / LOW RISK'}
              </div>
              <div className="text-[11px] text-rose-400 font-mono mt-0.5">
                {riskAnalysis.criticalList.length} Critical Identities
              </div>
            </div>
          </div>
        </div>

        {/* 4 Quantitative Breakdown KPI Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Critical Identities */}
          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono uppercase font-semibold text-[10px]">Critical Risk Identities</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-rose-400">
              {riskAnalysis.criticalList.length}
            </div>
            <div className="text-[11px] text-slate-400">
              Score ≥ 75 or lateral Crown Jewel access
            </div>
          </div>

          {/* Card 2: Used vs Unused Permissions Ratio */}
          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono uppercase font-semibold text-[10px]">Used vs Unused Ratio</span>
              <Lock className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white flex items-baseline gap-1.5">
              <span className="text-emerald-400">{riskAnalysis.totalUsed}</span>
              <span className="text-slate-500 font-sans text-xs">used /</span>
              <span className="text-rose-400">{riskAnalysis.totalUnused}</span>
              <span className="text-slate-500 font-sans text-xs">unused</span>
            </div>
            <div className="text-[11px] text-slate-400">
              <span className="text-rose-400 font-bold">{riskAnalysis.unusedPermRatio}%</span> permissions unexercised
            </div>
          </div>

          {/* Card 3: Vulnerable vs Secured Ratio */}
          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono uppercase font-semibold text-[10px]">Vulnerable vs Secured</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white flex items-baseline gap-1.5">
              <span className="text-amber-400">{riskAnalysis.criticalList.length + riskAnalysis.vulnerableList.length}</span>
              <span className="text-slate-500 font-sans text-xs">vuln /</span>
              <span className="text-emerald-400">{riskAnalysis.securedList.length}</span>
              <span className="text-slate-500 font-sans text-xs">secure</span>
            </div>
            <div className="text-[11px] text-slate-400">
              <span className="text-amber-400 font-bold">{riskAnalysis.vulnerableRatio}%</span> of identities vulnerable
            </div>
          </div>

          {/* Card 4: Active vs Unused (Stale) Identities */}
          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono uppercase font-semibold text-[10px]">Active vs Unused Accounts</span>
              <UserX className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-xl font-bold font-mono text-white flex items-baseline gap-1.5">
              <span className="text-cyan-400">{riskAnalysis.activeIdentities.length}</span>
              <span className="text-slate-500 font-sans text-xs">active /</span>
              <span className="text-purple-400">{riskAnalysis.unusedIdentities.length}</span>
              <span className="text-slate-500 font-sans text-xs">unused</span>
            </div>
            <div className="text-[11px] text-slate-400">
              <span className="text-purple-400 font-bold">{riskAnalysis.unusedIdentities.length}</span> dormant or zero-use accounts
            </div>
          </div>
        </div>

        {/* Visual Dual-Color Ratios Bars */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          {/* Permission Ratio Bar */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-emerald-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                Exercised Permissions: {riskAnalysis.totalUsed} ({riskAnalysis.usedPermRatio}%)
              </span>
              <span className="text-rose-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-400" />
                Unused Permissions: {riskAnalysis.totalUnused} ({riskAnalysis.unusedPermRatio}%)
              </span>
            </div>
            <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden flex">
              <div
                className="bg-emerald-500 h-full transition-all duration-700"
                style={{ width: `${riskAnalysis.usedPermRatio}%` }}
              />
              <div
                className="bg-rose-500 h-full transition-all duration-700"
                style={{ width: `${riskAnalysis.unusedPermRatio}%` }}
              />
            </div>
          </div>

          {/* Identity Security Ratio Bar */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-rose-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-400" />
                Vulnerable/Critical: {riskAnalysis.criticalList.length + riskAnalysis.vulnerableList.length} ({riskAnalysis.vulnerableRatio}%)
              </span>
              <span className="text-emerald-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                Secured: {riskAnalysis.securedList.length} ({riskAnalysis.securedRatio}%)
              </span>
            </div>
            <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden flex">
              <div
                className="bg-rose-500 h-full transition-all duration-700"
                style={{ width: `${riskAnalysis.vulnerableRatio}%` }}
              />
              <div
                className="bg-emerald-500 h-full transition-all duration-700"
                style={{ width: `${riskAnalysis.securedRatio}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* DETAILED IDENTITY CLASSIFICATION: CRITICAL, VULNERABLE, SECURED */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>Identity Risk Classification & Audit Registry</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Review which identities in this uploaded dataset are Critical, Vulnerable, or Secured.
            </p>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <button
              onClick={() => setIdentityFilter('ALL')}
              className={`px-3 py-1 rounded transition cursor-pointer ${
                identityFilter === 'ALL'
                  ? 'bg-slate-800 text-white font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              All ({riskAnalysis.classified.length})
            </button>
            <button
              onClick={() => setIdentityFilter('CRITICAL')}
              className={`px-3 py-1 rounded transition cursor-pointer ${
                identityFilter === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 font-bold border border-rose-800'
                  : 'text-slate-400 hover:text-rose-300'
              }`}
            >
              Critical ({riskAnalysis.criticalList.length})
            </button>
            <button
              onClick={() => setIdentityFilter('VULNERABLE')}
              className={`px-3 py-1 rounded transition cursor-pointer ${
                identityFilter === 'VULNERABLE'
                  ? 'bg-amber-950 text-amber-300 font-bold border border-amber-800'
                  : 'text-slate-400 hover:text-amber-300'
              }`}
            >
              Vulnerable ({riskAnalysis.vulnerableList.length})
            </button>
            <button
              onClick={() => setIdentityFilter('SECURED')}
              className={`px-3 py-1 rounded transition cursor-pointer ${
                identityFilter === 'SECURED'
                  ? 'bg-emerald-950 text-emerald-300 font-bold border border-emerald-800'
                  : 'text-slate-400 hover:text-emerald-300'
              }`}
            >
              Secured ({riskAnalysis.securedList.length})
            </button>
          </div>
        </div>

        {/* Identity Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                <th className="py-2.5 px-3">Identity Name / ARN</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Inactivity</th>
                <th className="py-2.5 px-3">Over-Privilege</th>
                <th className="py-2.5 px-3">Risk Classification</th>
                <th className="py-2.5 px-3">Threat Factors</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredIdentities.map(({ principal: p, metrics: m, isUnused, isCritical, isVulnerable }) => {
                const overPrivPct = Math.round(m.overPrivilegeScore * 100);

                return (
                  <tr key={p.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-3 font-sans">
                      <div className="font-semibold text-slate-200">{p.name}</div>
                      <div className="text-[10px] text-slate-500 font-mono truncate max-w-[200px]">{p.arn}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {p.type} • {p.provider}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      {isUnused ? (
                        <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                          <UserX className="w-3 h-3" />
                          <span>Unused / Dormant</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                          <UserCheck className="w-3 h-3" />
                          <span>Active</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={p.daysInactive > 90 ? 'text-purple-400 font-bold' : 'text-slate-300'}>
                        {p.daysInactive} days
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className={overPrivPct > 60 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                          {overPrivPct}%
                        </span>
                        <span className="text-[10px] text-slate-500">
                          ({p.grantedPermissions.length - p.grantedPermissions.filter((g) => g.isUsed).length} unused)
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      {isCritical ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">
                          CRITICAL ({m.compositeRiskScore})
                        </span>
                      ) : isVulnerable ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">
                          VULNERABLE ({m.compositeRiskScore})
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                          SECURED ({m.compositeRiskScore})
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-sans">
                      <div className="flex flex-wrap gap-1 text-[9px] font-mono">
                        {m.wildcardPermissions.length > 0 && (
                          <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-900">
                            Wildcard (*)
                          </span>
                        )}
                        {p.grantedPermissions.some((g) => g.action.includes('PassRole')) && (
                          <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-900">
                            PassRole
                          </span>
                        )}
                        {!p.mfaEnabled && p.type === 'User' && (
                          <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-900">
                            No MFA
                          </span>
                        )}
                        {p.unrotatedKeysCount > 0 && (
                          <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-900">
                            Unrotated Keys
                          </span>
                        )}
                        {p.daysInactive > 90 && (
                          <span className="px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-900">
                            &gt;90d Dormant
                          </span>
                        )}
                        {m.wildcardPermissions.length === 0 && !p.grantedPermissions.some((g) => g.action.includes('PassRole')) && p.mfaEnabled && p.daysInactive <= 30 && (
                          <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-900">
                            Least-Privilege Compliant
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
