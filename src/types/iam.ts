export type CloudProvider = 'AWS' | 'Azure' | 'GCP' | 'Multi-Cloud';

export type PrincipalType = 'User' | 'Role' | 'ServiceAccount' | 'Group';

export interface Permission {
  id: string;
  service: string;
  action: string;
  isUsed: boolean;
  lastUsedTimestamp?: string;
  isDangerous?: boolean;
  resourcePattern?: string;
  description?: string;
}

export interface Principal {
  id: string;
  name: string;
  type: PrincipalType;
  provider: CloudProvider;
  department?: string;
  email?: string;
  arn: string;
  lastActiveTimestamp: string;
  daysInactive: number;
  accessKeysCount: number;
  unrotatedKeysCount: number;
  mfaEnabled: boolean;
  grantedPermissions: Permission[];
  attachedPolicies: string[];
}

export type ResourceSensitivity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Resource {
  id: string;
  name: string;
  type: 'RDSInstance' | 'SecretsManager' | 'S3Bucket' | 'KMSKey' | 'EC2Instance' | 'IAMRole' | 'KubernetesCluster';
  provider: CloudProvider;
  sensitivity: ResourceSensitivity;
  isCrownJewel: boolean;
  arn: string;
  description?: string;
}

export type EdgeType = 'MEMBER_OF' | 'CAN_ASSUME' | 'ATTACHES_POLICY' | 'CAN_ACCESS' | 'CROSS_ACCOUNT_TRUST';

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  label?: string;
  permissions?: string[];
  isEscalationVector?: boolean;
}

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface IdentityRiskMetrics {
  principalId: string;
  overPrivilegeScore: number; // 0.0 to 1.0 (|P_unused| / |P_granted|)
  stalenessScore: number;     // 0.0 to 1.0 (1 - e^(-lambda * dt))
  escalationExposure: number; // 0.0 to 1.0
  compositeRiskScore: number; // 0 to 100
  riskCategory: RiskLevel;
  totalGranted: number;
  totalUsed: number;
  unusedActionsCount: number;
  reachableCrownJewels: string[];
  attackPathCount: number;
  wildcardPermissions: string[];
}

export interface AttackHop {
  nodeId: string;
  nodeName: string;
  nodeType: PrincipalType | 'Resource';
  edgeLabel: string;
  transitionPermission?: string;
}

export interface AttackPath {
  id: string;
  sourceId: string;
  sourceName: string;
  targetId: string;
  targetName: string;
  hopCount: number;
  hops: AttackHop[];
  chokepoint: {
    fromNode: string;
    toNode: string;
    vulnerablePermission: string;
    recommendation: string;
  };
  narrative: string[];
  severity: RiskLevel;
}

export interface CloudTrailEvent {
  eventId: string;
  principalId: string;
  action: string;
  service: string;
  timestamp: string;
  sourceIp: string;
  userAgent?: string;
}

export interface IAMDataSet {
  name: string;
  sourceType: 'synthetic' | 'uploaded';
  cloudProvider: CloudProvider;
  principals: Principal[];
  resources: Resource[];
  edges: GraphEdge[];
  cloudTrailEvents: CloudTrailEvent[];
  loadedAt: string;
}
