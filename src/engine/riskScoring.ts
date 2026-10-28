import { Principal, IdentityRiskMetrics, RiskLevel } from '../types/iam';

export interface ScoringWeights {
  w1: number; // Over-Privilege weight (e.g., 0.35)
  w2: number; // Staleness / Decay weight (e.g., 0.35)
  w3: number; // Escalation Exposure weight (e.g., 0.30)
  lambda: number; // Decay constant (e.g., 0.02)
}

export const DEFAULT_WEIGHTS: ScoringWeights = {
  w1: 0.35,
  w2: 0.35,
  w3: 0.30,
  lambda: 0.02,
};

/**
 * Calculates OverPrivilegeScore(i) = |P_unused(i)| / |P_granted(i)|
 * Section 6.3 of Synopsis
 */
export function calculateOverPrivilege(principal: Principal): {
  score: number;
  totalGranted: number;
  totalUsed: number;
  unusedCount: number;
  wildcards: string[];
} {
  const granted = principal.grantedPermissions || [];
  if (granted.length === 0) {
    return { score: 0, totalGranted: 0, totalUsed: 0, unusedCount: 0, wildcards: [] };
  }

  const unused = granted.filter((p) => !p.isUsed);
  const wildcards = granted
    .filter((p) => p.action.includes('*') || p.action === '*' || p.action.endsWith(':*'))
    .map((p) => p.action);

  const rawScore = unused.length / granted.length;
  // Wildcard penalty boost if admin wildcards are present
  const wildcardPenalty = wildcards.length > 0 ? 0.15 : 0;
  const score = Math.min(1.0, rawScore + wildcardPenalty);

  return {
    score,
    totalGranted: granted.length,
    totalUsed: granted.length - unused.length,
    unusedCount: unused.length,
    wildcards,
  };
}

/**
 * Calculates StalenessScore(i) = 1 - e^(-lambda * delta_t(i))
 * Section 6.4 of Synopsis (Temporal Decay of Trust)
 */
export function calculateStaleness(daysInactive: number, lambda: number = DEFAULT_WEIGHTS.lambda): number {
  if (daysInactive <= 0) return 0;
  // Exponential decay model
  const score = 1 - Math.exp(-lambda * daysInactive);
  return Math.min(1.0, Math.max(0.0, score));
}

/**
 * Computes Composite Risk:
 * Risk(i) = w1 * OverPrivilegeScore(i) + w2 * StalenessScore(i) + w3 * EscalationExposure(i)
 * Section 6.6 of Synopsis
 */
export function computePrincipalRisk(
  principal: Principal,
  reachableCrownJewelCount: number,
  attackPathCount: number,
  weights: ScoringWeights = DEFAULT_WEIGHTS
): IdentityRiskMetrics {
  const overPriv = calculateOverPrivilege(principal);
  const staleness = calculateStaleness(principal.daysInactive, weights.lambda);
  
  // Escalation exposure normalized: 1 crown jewel reached = 0.5, >=2 = 1.0, weighted by path count
  const exposureRaw = Math.min(1.0, (reachableCrownJewelCount * 0.45) + (attackPathCount > 0 ? 0.25 : 0));

  // Weighted composite score (0 to 1 scale)
  const compositeUnit = (weights.w1 * overPriv.score) + (weights.w2 * staleness) + (weights.w3 * exposureRaw);
  const compositeRiskScore = Math.round(compositeUnit * 100);

  let riskCategory: RiskLevel = 'LOW';
  if (compositeRiskScore >= 75) {
    riskCategory = 'CRITICAL';
  } else if (compositeRiskScore >= 50) {
    riskCategory = 'HIGH';
  } else if (compositeRiskScore >= 25) {
    riskCategory = 'MEDIUM';
  } else {
    riskCategory = 'LOW';
  }

  return {
    principalId: principal.id,
    overPrivilegeScore: Number(overPriv.score.toFixed(3)),
    stalenessScore: Number(staleness.toFixed(3)),
    escalationExposure: Number(exposureRaw.toFixed(3)),
    compositeRiskScore,
    riskCategory,
    totalGranted: overPriv.totalGranted,
    totalUsed: overPriv.totalUsed,
    unusedActionsCount: overPriv.unusedCount,
    reachableCrownJewels: [],
    attackPathCount,
    wildcardPermissions: overPriv.wildcards,
  };
}
