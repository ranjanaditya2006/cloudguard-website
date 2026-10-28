import React from 'react';
import {
  ShieldAlert,
  BarChart3,
  Network,
  KeyRound,
  Clock,
  GitFork,
  FileCheck2,
  UploadCloud,
  Globe2,
} from 'lucide-react';
import { IAMDataSet } from '../../types/iam';

export type TabKey =
  | 'overview'
  | 'ingestion'
  | 'graph'
  | 'overprivilege'
  | 'staleness'
  | 'simulation'
  | 'remediation';

interface NavbarProps {
  currentTab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  dataset: IAMDataSet;
  onResetToDemo: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  dataset,
  onResetToDemo,
}) => {
  const navItems: { key: TabKey; label: string; icon: React.ReactNode; badge?: string }[] = [
    { key: 'overview', label: 'Posture Overview', icon: <BarChart3 className="w-4 h-4" /> },
    { key: 'ingestion', label: 'Data Ingestion', icon: <UploadCloud className="w-4 h-4" /> },
    { key: 'graph', label: 'Access Graph', icon: <Network className="w-4 h-4" /> },
    { key: 'overprivilege', label: 'CIEM / Over-Privilege', icon: <KeyRound className="w-4 h-4" /> },
    { key: 'staleness', label: 'Temporal Decay', icon: <Clock className="w-4 h-4" /> },
    { key: 'simulation', label: 'Attack Simulator', icon: <GitFork className="w-4 h-4" />, badge: 'BFS' },
    { key: 'remediation', label: 'Policy Diff & Fixes', icon: <FileCheck2 className="w-4 h-4" /> },
  ];

  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-slate-100 tracking-tight">
                  Cloud<span className="text-cyan-400 font-mono">Guard</span>
                </span>
                <span className="px-1.5 py-0.5 text-[10px] uppercase font-mono font-bold rounded bg-cyan-950 text-cyan-400 border border-cyan-800/80">
                  PoLP Engine
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Graph-Based Entitlement Risk & Privilege Escalation Detection
              </p>
            </div>
          </div>

          {/* Right Header Status */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-1.5 text-xs">
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-mono text-slate-300 text-[11px]">Zero-Trust Analyzer Active</span>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex overflow-x-auto space-x-1 py-1 no-scrollbar border-t border-slate-800/70">
          {navItems.map((item) => {
            const isActive = currentTab === item.key;
            return (
              <button
                key={item.key}
                onClick={() => onSelectTab(item.key)}
                className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs sm:text-sm font-medium whitespace-nowrap transition cursor-pointer ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
                {item.badge && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-900/80 text-cyan-200 border border-cyan-700/60 font-mono">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
