import React, { useState, useMemo } from 'react';
import { Navbar, TabKey } from './components/layout/Navbar';
import { ExecutiveDashboard } from './components/dashboard/ExecutiveDashboard';
import { FileUploadView } from './components/ingestion/FileUploadView';
import { AccessGraphCanvas } from './components/graph/AccessGraphCanvas';
import { OverPrivilegeView } from './components/analyzer/OverPrivilegeView';
import { StaleIdentityView } from './components/analyzer/StaleIdentityView';
import { AttackSimulatorView } from './components/simulation/AttackSimulatorView';
import { RemediationView } from './components/remediation/RemediationView';
import { SYNTHETIC_DATASET } from './data/syntheticDataset';
import { IAMDataSet, IdentityRiskMetrics } from './types/iam';
import { computePrincipalRisk, DEFAULT_WEIGHTS } from './engine/riskScoring';
import { AccessGraphEngine } from './engine/graphEngine';

export function App() {
  const [dataset, setDataset] = useState<IAMDataSet>(SYNTHETIC_DATASET);
  const [currentTab, setCurrentTab] = useState<TabKey>('overview');

  // Cross-view state links
  const [selectedPrincipalForRemediation, setSelectedPrincipalForRemediation] = useState<string>('');
  const [selectedPrincipalForSimulation, setSelectedPrincipalForSimulation] = useState<string>('');
  const [highlightedPathNodeIds, setHighlightedPathNodeIds] = useState<string[]>([]);

  // Instantiated Access Graph Engine
  const graphEngine = useMemo(() => {
    return new AccessGraphEngine(dataset.principals, dataset.resources, dataset.edges);
  }, [dataset]);

  // Compute Risk Metrics for all Principals
  const riskMetrics = useMemo(() => {
    const map = new Map<string, IdentityRiskMetrics>();

    for (const p of dataset.principals) {
      const reachableJewels = graphEngine.getReachableCrownJewels(p.id);
      const metrics = computePrincipalRisk(
        p,
        reachableJewels.length,
        reachableJewels.length,
        DEFAULT_WEIGHTS
      );
      metrics.reachableCrownJewels = reachableJewels.map((j) => j.jewelName);
      map.set(p.id, metrics);
    }

    return map;
  }, [dataset, graphEngine]);

  const handleResetToDemo = () => {
    setDataset(SYNTHETIC_DATASET);
    setHighlightedPathNodeIds([]);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* 1. Top Navigation & Operational Status */}
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        dataset={dataset}
        onResetToDemo={handleResetToDemo}
      />

      {/* 2. Main View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentTab === 'overview' && (
          <ExecutiveDashboard
            dataset={dataset}
            riskMetrics={riskMetrics}
            onNavigateTab={setCurrentTab}
            onSelectPrincipalForRemediation={setSelectedPrincipalForRemediation}
            onSelectPrincipalForSimulation={setSelectedPrincipalForSimulation}
          />
        )}

        {currentTab === 'ingestion' && (
          <FileUploadView
            currentDataset={dataset}
            onDatasetLoaded={(newDs) => {
              setDataset(newDs);
              setHighlightedPathNodeIds([]);
            }}
            onResetToDemo={handleResetToDemo}
          />
        )}

        {currentTab === 'graph' && (
          <AccessGraphCanvas
            dataset={dataset}
            riskMetrics={riskMetrics}
            highlightedPathNodeIds={highlightedPathNodeIds}
            onSelectPrincipalForSimulation={setSelectedPrincipalForSimulation}
            onSelectPrincipalForRemediation={setSelectedPrincipalForRemediation}
            onNavigateTab={setCurrentTab}
          />
        )}

        {currentTab === 'overprivilege' && (
          <OverPrivilegeView
            dataset={dataset}
            riskMetrics={riskMetrics}
            onSelectPrincipalForRemediation={setSelectedPrincipalForRemediation}
            onNavigateTab={setCurrentTab}
          />
        )}

        {currentTab === 'staleness' && (
          <StaleIdentityView
            dataset={dataset}
            riskMetrics={riskMetrics}
            onNavigateTab={setCurrentTab}
            onSelectPrincipalForRemediation={setSelectedPrincipalForRemediation}
          />
        )}

        {currentTab === 'simulation' && (
          <AttackSimulatorView
            dataset={dataset}
            graphEngine={graphEngine}
            preselectedSourceId={selectedPrincipalForSimulation}
            onHighlightPathInGraph={setHighlightedPathNodeIds}
            onNavigateTab={setCurrentTab}
            onSelectPrincipalForRemediation={setSelectedPrincipalForRemediation}
          />
        )}

        {currentTab === 'remediation' && (
          <RemediationView
            dataset={dataset}
            riskMetrics={riskMetrics}
            preselectedPrincipalId={selectedPrincipalForRemediation}
          />
        )}
      </main>

      {/* 3. Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-500 font-mono">
        <p>
          CloudGuard • Continuous Least-Privilege & Entitlement Governance Engine
        </p>
      </footer>
    </div>
  );
}
export default App;
