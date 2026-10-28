import JSZip from 'jszip';
import { IAMDataSet, Principal, Resource, GraphEdge, CloudTrailEvent, Permission } from '../types/iam';

export interface ParseResult {
  success: boolean;
  dataset?: IAMDataSet;
  errorMessage?: string;
  filesFound?: string[];
  stats?: {
    principalsCount: number;
    resourcesCount: number;
    edgesCount: number;
    eventsCount: number;
  };
}

/**
 * Parses user-uploaded files (ZIP archives, JSON files)
 */
export async function parseUploadedFile(file: File): Promise<ParseResult> {
  const fileName = file.name.toLowerCase();

  try {
    if (fileName.endsWith('.zip')) {
      return await parseZipArchive(file);
    } else if (fileName.endsWith('.json')) {
      return await parseJsonFile(file);
    } else {
      return {
        success: false,
        errorMessage: `Unsupported file format "${file.name}". Please upload a .zip archive or .json IAM export.`,
      };
    }
  } catch (err: any) {
    return {
      success: false,
      errorMessage: `Error processing file: ${err.message || 'Unknown parsing error'}`,
    };
  }
}

/**
 * Decompresses and parses a ZIP archive in-memory using JSZip
 */
async function parseZipArchive(file: File): Promise<ParseResult> {
  const zip = new JSZip();
  const loadedZip = await zip.loadAsync(file);
  const filesFound = Object.keys(loadedZip.files).filter((k) => !loadedZip.files[k].dir);

  let rawDatasetJson: any = null;
  let rawUsers: any[] = [];
  let rawRoles: any[] = [];
  let rawResources: any[] = [];
  let rawEdges: any[] = [];
  let rawCloudTrail: any[] = [];

  for (const filename of filesFound) {
    const lowerName = filename.toLowerCase();
    const zipEntry = loadedZip.files[filename];
    const textContent = await zipEntry.async('string');

    try {
      const parsed = JSON.parse(textContent);

      if (lowerName.includes('dataset') || lowerName.includes('iam_export') || (parsed.principals && parsed.resources)) {
        rawDatasetJson = parsed;
        break;
      } else if (lowerName.includes('user')) {
        rawUsers = Array.isArray(parsed) ? parsed : (parsed.Users || parsed.users || []);
      } else if (lowerName.includes('role')) {
        rawRoles = Array.isArray(parsed) ? parsed : (parsed.Roles || parsed.roles || []);
      } else if (lowerName.includes('resource')) {
        rawResources = Array.isArray(parsed) ? parsed : (parsed.Resources || parsed.resources || []);
      } else if (lowerName.includes('edge') || lowerName.includes('relationship')) {
        rawEdges = Array.isArray(parsed) ? parsed : (parsed.Edges || parsed.edges || []);
      } else if (lowerName.includes('cloudtrail') || lowerName.includes('event')) {
        rawCloudTrail = Array.isArray(parsed) ? parsed : (parsed.Events || parsed.events || []);
      }
    } catch {
      // Ignore non-JSON files inside the archive (e.g. README.txt)
    }
  }

  if (rawDatasetJson) {
    return normalizeAndPackageDataset(rawDatasetJson, file.name);
  }

  // If separate files were found in zip
  if (rawUsers.length > 0 || rawRoles.length > 0 || rawResources.length > 0) {
    const combinedPrincipals = [...rawUsers, ...rawRoles];
    const normalized = normalizeRawData(
      combinedPrincipals,
      rawResources,
      rawEdges,
      rawCloudTrail,
      file.name
    );
    return {
      success: true,
      dataset: normalized,
      filesFound,
      stats: {
        principalsCount: normalized.principals.length,
        resourcesCount: normalized.resources.length,
        edgesCount: normalized.edges.length,
        eventsCount: normalized.cloudTrailEvents.length,
      },
    };
  }

  return {
    success: false,
    errorMessage: `No valid IAM data found inside "${file.name}". Expected files such as users.json, roles.json, or a combined iam_export.json.`,
    filesFound,
  };
}

/**
 * Parses a standalone JSON file
 */
async function parseJsonFile(file: File): Promise<ParseResult> {
  const text = await file.text();
  const parsed = JSON.parse(text);

  return normalizeAndPackageDataset(parsed, file.name);
}

/**
 * Normalizes generic raw JSON into strict IAMDataSet format
 */
function normalizeAndPackageDataset(raw: any, sourceFileName: string): ParseResult {
  // If it's already in our schema
  if (raw.principals && Array.isArray(raw.principals)) {
    const dataset: IAMDataSet = {
      name: raw.name || sourceFileName.replace(/\.(json|zip)$/i, ''),
      sourceType: 'uploaded',
      cloudProvider: raw.cloudProvider || 'Multi-Cloud',
      principals: raw.principals.map(normalizePrincipal),
      resources: (raw.resources || []).map(normalizeResource),
      edges: raw.edges || [],
      cloudTrailEvents: raw.cloudTrailEvents || [],
      loadedAt: new Date().toISOString(),
    };

    return {
      success: true,
      dataset,
      stats: {
        principalsCount: dataset.principals.length,
        resourcesCount: dataset.resources.length,
        edgesCount: dataset.edges.length,
        eventsCount: dataset.cloudTrailEvents.length,
      },
    };
  }

  // Handle AWS IAM Credential Report JSON format
  if (Array.isArray(raw)) {
    const dataset = normalizeRawData(raw, [], [], [], sourceFileName);
    return {
      success: true,
      dataset,
      stats: {
        principalsCount: dataset.principals.length,
        resourcesCount: dataset.resources.length,
        edgesCount: dataset.edges.length,
        eventsCount: 0,
      },
    };
  }

  return {
    success: false,
    errorMessage: 'Uploaded JSON does not contain principals array or recognized cloud credential report structure.',
  };
}

function normalizePrincipal(p: any): Principal {
  const grantedPermissions: Permission[] = (p.grantedPermissions || p.permissions || []).map((perm: any, idx: number) => {
    if (typeof perm === 'string') {
      const [service, action] = perm.includes(':') ? perm.split(':') : ['custom', perm];
      return {
        id: `perm-${idx}`,
        service: service || 'aws',
        action: perm,
        isUsed: false,
      };
    }
    return {
      id: perm.id || `perm-${idx}`,
      service: perm.service || perm.action?.split(':')[0] || 'custom',
      action: perm.action || 'read',
      isUsed: Boolean(perm.isUsed),
      lastUsedTimestamp: perm.lastUsedTimestamp,
      isDangerous: Boolean(perm.isDangerous),
      resourcePattern: perm.resourcePattern || '*',
    };
  });

  return {
    id: p.id || p.user_id || p.UserName || `principal-${Math.random().toString(36).substring(7)}`,
    name: p.name || p.user_name || p.UserName || 'unnamed-identity',
    type: p.type || (p.arn?.includes(':role/') ? 'Role' : 'User'),
    provider: p.provider || 'AWS',
    department: p.department || 'Engineering',
    email: p.email || `${p.name || 'user'}@enterprise.cloud`,
    arn: p.arn || `arn:aws:iam::123456789012:user/${p.name || 'user'}`,
    lastActiveTimestamp: p.lastActiveTimestamp || p.password_last_used || new Date(Date.now() - 30 * 86400000).toISOString(),
    daysInactive: typeof p.daysInactive === 'number' ? p.daysInactive : (p.days_inactive || 14),
    accessKeysCount: p.accessKeysCount ?? 1,
    unrotatedKeysCount: p.unrotatedKeysCount ?? 0,
    mfaEnabled: p.mfaEnabled ?? (p.mfa_active === 'true' || p.mfa_active === true),
    grantedPermissions,
    attachedPolicies: p.attachedPolicies || p.policies || ['AdministratorAccess'],
  };
}

function normalizeResource(r: any): Resource {
  return {
    id: r.id || r.resource_id || `res-${Math.random().toString(36).substring(7)}`,
    name: r.name || r.resource_name || 'unnamed-resource',
    type: r.type || 'S3Bucket',
    provider: r.provider || 'AWS',
    sensitivity: r.sensitivity || 'MEDIUM',
    isCrownJewel: Boolean(r.isCrownJewel),
    arn: r.arn || `arn:aws:s3:::${r.name || 'bucket'}`,
    description: r.description,
  };
}

function normalizeRawData(
  principalsRaw: any[],
  resourcesRaw: any[],
  edgesRaw: any[],
  cloudTrailRaw: any[],
  name: string
): IAMDataSet {
  const principals = principalsRaw.map(normalizePrincipal);
  const resources = resourcesRaw.map(normalizeResource);
  const edges: GraphEdge[] = edgesRaw.map((e, idx) => ({
    id: e.id || `edge-${idx}`,
    source: e.source || e.from,
    target: e.target || e.to,
    type: e.type || 'CAN_ACCESS',
    label: e.label,
    permissions: e.permissions || [],
  }));

  const cloudTrailEvents: CloudTrailEvent[] = cloudTrailRaw.map((ev, idx) => ({
    eventId: ev.eventId || `evt-${idx}`,
    principalId: ev.principalId || ev.userIdentity?.userName || 'unknown',
    action: ev.action || ev.eventName || 'DescribeInstances',
    service: ev.service || ev.eventSource?.split('.')[0] || 'ec2',
    timestamp: ev.timestamp || ev.eventTime || new Date().toISOString(),
    sourceIp: ev.sourceIp || ev.sourceIPAddress || '127.0.0.1',
  }));

  // Cross-reference CloudTrail events with granted permissions to mark P_used
  if (cloudTrailEvents.length > 0) {
    for (const p of principals) {
      const pEvents = cloudTrailEvents.filter((ev) => ev.principalId === p.id || ev.principalId === p.name);
      const usedActionNames = new Set(pEvents.map((ev) => ev.action.toLowerCase()));

      for (const perm of p.grantedPermissions) {
        const actionShort = perm.action.includes(':') ? perm.action.split(':')[1].toLowerCase() : perm.action.toLowerCase();
        if (usedActionNames.has(actionShort) || usedActionNames.has(perm.action.toLowerCase())) {
          perm.isUsed = true;
        }
      }
    }
  }

  return {
    name: name.replace(/\.(json|zip)$/i, ''),
    sourceType: 'uploaded',
    cloudProvider: 'Multi-Cloud',
    principals,
    resources,
    edges,
    cloudTrailEvents,
    loadedAt: new Date().toISOString(),
  };
}

/**
 * Creates a downloadable sample ZIP file containing mock IAM metadata
 */
export async function generateSampleZipArchive(): Promise<Blob> {
  const zip = new JSZip();

  const sampleUsers = [
    {
      id: 'usr-intern-01',
      name: 'intern-aditya',
      type: 'User',
      provider: 'AWS',
      daysInactive: 12,
      grantedPermissions: [
        { action: 'ec2:DescribeInstances', isUsed: true },
        { action: 's3:ListBucket', isUsed: true },
        { action: 'iam:PassRole', isUsed: false, isDangerous: true },
      ],
      attachedPolicies: ['DevTierReadOnly', 'TemporaryEC2Access'],
    },
    {
      id: 'usr-contractor-99',
      name: 'legacy-contractor-ankit',
      type: 'User',
      provider: 'AWS',
      daysInactive: 145,
      grantedPermissions: [
        { action: 'rds:*', isUsed: false, isDangerous: true },
        { action: 'secretsmanager:GetSecretValue', isUsed: false, isDangerous: true },
        { action: 'iam:*', isUsed: false, isDangerous: true },
      ],
      attachedPolicies: ['AdministratorAccess'],
    },
  ];

  const sampleResources = [
    {
      id: 'res-rds-prod',
      name: 'prod-finance-db',
      type: 'RDSInstance',
      provider: 'AWS',
      sensitivity: 'CRITICAL',
      isCrownJewel: true,
      arn: 'arn:aws:rds:us-east-1:123456789012:db:prod-finance-db',
    },
    {
      id: 'res-s3-backup',
      name: 'customer-vault-backups',
      type: 'S3Bucket',
      provider: 'AWS',
      sensitivity: 'HIGH',
      isCrownJewel: true,
      arn: 'arn:aws:s3:::customer-vault-backups',
    },
  ];

  const sampleEdges = [
    {
      id: 'edge-1',
      source: 'usr-intern-01',
      target: 'role-dev-support',
      type: 'CAN_ASSUME',
      permissions: ['sts:AssumeRole'],
    },
    {
      id: 'edge-2',
      source: 'role-dev-support',
      target: 'res-rds-prod',
      type: 'CAN_ACCESS',
      permissions: ['rds:Connect'],
    },
  ];

  zip.file('iam_users.json', JSON.stringify(sampleUsers, null, 2));
  zip.file('cloud_resources.json', JSON.stringify(sampleResources, null, 2));
  zip.file('iam_edges.json', JSON.stringify(sampleEdges, null, 2));
  zip.file(
    'README.txt',
    'Bharati Vidyapeeth Cloud Identity Risk Analysis\nSample IAM dump for testing archive ingestion.'
  );

  return await zip.generateAsync({ type: 'blob' });
}
