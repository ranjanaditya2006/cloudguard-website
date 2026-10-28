import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const sampleDataDir = path.join(rootDir, 'sample-data');
const publicSampleDataDir = path.join(rootDir, 'public', 'sample-data');

// Ensure directories exist
fs.mkdirSync(sampleDataDir, { recursive: true });
fs.mkdirSync(publicSampleDataDir, { recursive: true });

// 1. DATASET: FinTech Multi-Cloud IAM Export
const fintechDataset = {
  name: "FinTech Enterprise Production Cloud IAM",
  cloudProvider: "Multi-Cloud",
  sourceType: "uploaded",
  loadedAt: new Date().toISOString(),
  principals: [
    {
      id: "usr-intern-rahul",
      name: "intern-rahul-sharma",
      type: "User",
      provider: "AWS",
      department: "Engineering Interns",
      email: "rahul.intern@fintech-global.com",
      arn: "arn:aws:iam::884920192841:user/intern-rahul-sharma",
      lastActiveTimestamp: new Date(Date.now() - 3 * 86400000).toISOString(),
      daysInactive: 3,
      accessKeysCount: 1,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["InternDeveloperPolicy", "DevEC2ReadOnly"],
      grantedPermissions: [
        { id: "p-1", service: "ec2", action: "ec2:DescribeInstances", isUsed: true, lastUsedTimestamp: "2026-09-25T14:30:00Z" },
        { id: "p-2", service: "s3", action: "s3:ListBucket", isUsed: true, lastUsedTimestamp: "2026-09-25T14:35:00Z" },
        { id: "p-3", service: "s3", action: "s3:GetObject", isUsed: true, lastUsedTimestamp: "2026-09-25T14:36:00Z" },
        { id: "p-4", service: "iam", action: "iam:PassRole", isUsed: false, isDangerous: true, description: "Privilege Escalation Vector: Passes arbitrary roles to compute services" },
        { id: "p-5", service: "lambda", action: "lambda:CreateFunction", isUsed: false, isDangerous: true },
        { id: "p-6", service: "lambda", action: "lambda:InvokeFunction", isUsed: false },
        { id: "p-7", service: "cloudwatch", action: "cloudwatch:GetMetricData", isUsed: true }
      ]
    },
    {
      id: "usr-contractor-steve",
      name: "contractor-steve-legacy",
      type: "User",
      provider: "AWS",
      department: "External QA Vendors",
      email: "steve.vendor@legacy-partner.io",
      arn: "arn:aws:iam::884920192841:user/contractor-steve-legacy",
      lastActiveTimestamp: new Date(Date.now() - 154 * 86400000).toISOString(),
      daysInactive: 154,
      accessKeysCount: 2,
      unrotatedKeysCount: 2,
      mfaEnabled: false,
      attachedPolicies: ["AdministratorAccess", "FullS3AdminAccess"],
      grantedPermissions: [
        { id: "p-10", service: "iam", action: "iam:*", isUsed: false, isDangerous: true },
        { id: "p-11", service: "s3", action: "s3:*", isUsed: false, isDangerous: true },
        { id: "p-12", service: "rds", action: "rds:*", isUsed: false, isDangerous: true },
        { id: "p-13", service: "secretsmanager", action: "secretsmanager:GetSecretValue", isUsed: false, isDangerous: true },
        { id: "p-14", service: "kms", action: "kms:Decrypt", isUsed: false, isDangerous: true },
        { id: "p-15", service: "ec2", action: "ec2:*", isUsed: false, isDangerous: true }
      ]
    },
    {
      id: "usr-data-priya",
      name: "priya-verma-dataops",
      type: "User",
      provider: "AWS",
      department: "Big Data & BI Analytics",
      email: "priya.verma@fintech-global.com",
      arn: "arn:aws:iam::884920192841:user/priya-verma-dataops",
      lastActiveTimestamp: new Date(Date.now() - 6 * 86400000).toISOString(),
      daysInactive: 6,
      accessKeysCount: 1,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["DataLakeFullAccess", "AthenaQueryRunner"],
      grantedPermissions: [
        { id: "p-20", service: "s3", action: "s3:GetObject", isUsed: true },
        { id: "p-21", service: "s3", action: "s3:PutObject", isUsed: true },
        { id: "p-22", service: "s3", action: "s3:DeleteBucket", isUsed: false, isDangerous: true },
        { id: "p-23", service: "glue", action: "glue:StartJobRun", isUsed: true },
        { id: "p-24", service: "athena", action: "athena:StartQueryExecution", isUsed: true },
        { id: "p-25", service: "dynamodb", action: "dynamodb:*", isUsed: false, isDangerous: true }
      ]
    },
    {
      id: "usr-devops-vikram",
      name: "vikram-singh-sre",
      type: "User",
      provider: "AWS",
      department: "Site Reliability Engineering",
      email: "vikram.singh@fintech-global.com",
      arn: "arn:aws:iam::884920192841:user/vikram-singh-sre",
      lastActiveTimestamp: new Date(Date.now() - 1 * 86400000).toISOString(),
      daysInactive: 1,
      accessKeysCount: 1,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["InfraManagementAdmin", "AssumeDBAPolicy"],
      grantedPermissions: [
        { id: "p-30", service: "ec2", action: "ec2:DescribeInstances", isUsed: true },
        { id: "p-31", service: "ec2", action: "ec2:StartInstances", isUsed: true },
        { id: "p-32", service: "sts", action: "sts:AssumeRole", isUsed: true, isDangerous: true },
        { id: "p-33", service: "iam", action: "iam:CreateRole", isUsed: false, isDangerous: true },
        { id: "p-34", service: "route53", action: "route53:ChangeResourceRecordSets", isUsed: true }
      ]
    },
    {
      id: "role-lambda-worker",
      name: "DataIngestion-LambdaRole",
      type: "Role",
      provider: "AWS",
      department: "Data Platform",
      arn: "arn:aws:iam::884920192841:role/DataIngestion-LambdaRole",
      lastActiveTimestamp: new Date(Date.now() - 5 * 86400000).toISOString(),
      daysInactive: 5,
      accessKeysCount: 0,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["AWSLambdaBasicExecutionRole", "CrossAccountTrustAssumption"],
      grantedPermissions: [
        { id: "p-40", service: "logs", action: "logs:CreateLogStream", isUsed: true },
        { id: "p-41", service: "logs", action: "logs:PutLogEvents", isUsed: true },
        { id: "p-42", service: "sts", action: "sts:AssumeRole", isUsed: true, isDangerous: true },
        { id: "p-43", service: "s3", action: "s3:GetObject", isUsed: true }
      ]
    },
    {
      id: "role-prod-dba",
      name: "ProdBanking-DatabaseAdminRole",
      type: "Role",
      provider: "AWS",
      department: "Financial Core Infrastructure",
      arn: "arn:aws:iam::884920192841:role/ProdBanking-DatabaseAdminRole",
      lastActiveTimestamp: new Date(Date.now() - 2 * 86400000).toISOString(),
      daysInactive: 2,
      accessKeysCount: 0,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["AmazonRDSFullAccess", "SecretsManagerCoreVault"],
      grantedPermissions: [
        { id: "p-50", service: "rds", action: "rds:DescribeDBInstances", isUsed: true },
        { id: "p-51", service: "rds", action: "rds:ModifyDBInstance", isUsed: false, isDangerous: true },
        { id: "p-52", service: "secretsmanager", action: "secretsmanager:GetSecretValue", isUsed: true, isDangerous: true },
        { id: "p-53", service: "kms", action: "kms:Decrypt", isUsed: true, isDangerous: true }
      ]
    },
    {
      id: "sa-azure-backup",
      name: "azure-sp-nightly-backup",
      type: "ServiceAccount",
      provider: "Azure",
      department: "Cloud Governance",
      email: "sp-backup@fintech.onmicrosoft.com",
      arn: "azure://subscriptions/sub-991204/servicePrincipals/sp-nightly-backup",
      lastActiveTimestamp: new Date(Date.now() - 98 * 86400000).toISOString(),
      daysInactive: 98,
      accessKeysCount: 1,
      unrotatedKeysCount: 1,
      mfaEnabled: false,
      attachedPolicies: ["StorageBlobDataContributor", "KeyVaultSecretsUser"],
      grantedPermissions: [
        { id: "p-60", service: "storage", action: "Microsoft.Storage/storageAccounts/blobServices/read", isUsed: false },
        { id: "p-61", service: "keyvault", action: "Microsoft.KeyVault/vaults/secrets/read", isUsed: false, isDangerous: true }
      ]
    }
  ],
  resources: [
    {
      id: "res-aurora-postgres-prod",
      name: "prod-aurora-core-banking-db",
      type: "RDSInstance",
      provider: "AWS",
      sensitivity: "CRITICAL",
      isCrownJewel: true,
      arn: "arn:aws:rds:ap-south-1:884920192841:cluster:prod-aurora-core-banking-db",
      description: "Core banking SQL cluster containing ledger accounts, real-time transaction history, and PCI-DSS PAN records."
    },
    {
      id: "res-vault-secrets-prod",
      name: "fintech-vault-master-secrets",
      type: "SecretsManager",
      provider: "AWS",
      sensitivity: "CRITICAL",
      isCrownJewel: true,
      arn: "arn:aws:secretsmanager:ap-south-1:884920192841:secret:prod/fintech_master_secrets",
      description: "Master database root passwords, payment processor HMAC signing keys, and Swift payment tokens."
    },
    {
      id: "res-customer-kyc-bucket",
      name: "customer-kyc-pan-aadhaar-vault",
      type: "S3Bucket",
      provider: "AWS",
      sensitivity: "CRITICAL",
      isCrownJewel: true,
      arn: "arn:aws:s3:::customer-kyc-pan-aadhaar-vault",
      description: "Encrypted repository storing verified user identity documents (Aadhaar, Passport scans, PAN cards)."
    },
    {
      id: "res-kms-payment-key",
      name: "kms-payment-encryption-cmk",
      type: "KMSKey",
      provider: "AWS",
      sensitivity: "CRITICAL",
      isCrownJewel: true,
      arn: "arn:aws:kms:ap-south-1:884920192841:key/f9a8b7c6-1234-5678-abcd-0987654321fe",
      description: "Hardware-backed Customer Managed Key for envelope encryption across all databases."
    },
    {
      id: "res-s3-app-frontend",
      name: "fintech-portal-web-static",
      type: "S3Bucket",
      provider: "AWS",
      sensitivity: "LOW",
      isCrownJewel: false,
      arn: "arn:aws:s3:::fintech-portal-web-static",
      description: "Public React bundles, marketing images, and CSS files."
    }
  ],
  edges: [
    {
      id: "fe-1",
      source: "usr-intern-rahul",
      target: "role-lambda-worker",
      type: "CAN_ASSUME",
      label: "iam:PassRole Privilege Escalation",
      permissions: ["iam:PassRole"],
      isEscalationVector: true
    },
    {
      id: "fe-2",
      source: "role-lambda-worker",
      target: "role-prod-dba",
      type: "CAN_ASSUME",
      label: "sts:AssumeRole Trust Boundary",
      permissions: ["sts:AssumeRole"],
      isEscalationVector: true
    },
    {
      id: "fe-3",
      source: "role-prod-dba",
      target: "res-aurora-postgres-prod",
      type: "CAN_ACCESS",
      label: "Direct Database Modify",
      permissions: ["rds:Connect", "rds:ModifyDBInstance"],
      isEscalationVector: true
    },
    {
      id: "fe-4",
      source: "role-prod-dba",
      target: "res-vault-secrets-prod",
      type: "CAN_ACCESS",
      label: "Reads Banking Master Secrets",
      permissions: ["secretsmanager:GetSecretValue"],
      isEscalationVector: true
    },
    {
      id: "fe-5",
      source: "usr-contractor-steve",
      target: "res-vault-secrets-prod",
      type: "CAN_ACCESS",
      label: "Direct Wildcard Access (Over-Privileged)",
      permissions: ["secretsmanager:*", "iam:*"],
      isEscalationVector: true
    },
    {
      id: "fe-6",
      source: "usr-contractor-steve",
      target: "res-customer-kyc-bucket",
      type: "CAN_ACCESS",
      label: "Unrestricted S3 Read/Write",
      permissions: ["s3:*"],
      isEscalationVector: true
    },
    {
      id: "fe-7",
      source: "usr-devops-vikram",
      target: "role-prod-dba",
      type: "CAN_ASSUME",
      label: "On-Call Emergency Escalation",
      permissions: ["sts:AssumeRole"],
      isEscalationVector: true
    },
    {
      id: "fe-8",
      source: "usr-intern-rahul",
      target: "res-s3-app-frontend",
      type: "CAN_ACCESS",
      label: "Deploy Web Assets",
      permissions: ["s3:ListBucket", "s3:GetObject"]
    },
    {
      id: "fe-9",
      source: "usr-data-priya",
      target: "res-customer-kyc-bucket",
      type: "CAN_ACCESS",
      label: "Data Ingestion Pipeline",
      permissions: ["s3:GetObject", "s3:PutObject"]
    }
  ],
  cloudTrailEvents: [
    {
      eventId: "trail-001",
      principalId: "usr-intern-rahul",
      action: "DescribeInstances",
      service: "ec2",
      timestamp: "2026-09-25T14:30:00Z",
      sourceIp: "103.21.244.10"
    },
    {
      eventId: "trail-002",
      principalId: "usr-intern-rahul",
      action: "ListBucket",
      service: "s3",
      timestamp: "2026-09-25T14:35:00Z",
      sourceIp: "103.21.244.10"
    },
    {
      eventId: "trail-003",
      principalId: "usr-devops-vikram",
      action: "AssumeRole",
      service: "sts",
      timestamp: "2026-09-27T11:00:00Z",
      sourceIp: "49.207.180.5"
    }
  ]
};

// 2. DATASET: Healthcare HIPAA Compliance Cloud IAM
const healthcareDataset = {
  name: "HealthCare Cloud Electronic Health Records (HIPAA)",
  cloudProvider: "AWS",
  sourceType: "uploaded",
  loadedAt: new Date().toISOString(),
  principals: [
    {
      id: "usr-dr-sharma",
      name: "dr-arun-sharma-cardio",
      type: "User",
      provider: "AWS",
      department: "Clinical Cardiology",
      arn: "arn:aws:iam::552199201940:user/dr-arun-sharma",
      lastActiveTimestamp: new Date(Date.now() - 1 * 86400000).toISOString(),
      daysInactive: 1,
      accessKeysCount: 1,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["DoctorEHRReadOnly"],
      grantedPermissions: [
        { id: "hp-1", service: "dynamodb", action: "dynamodb:GetItem", isUsed: true },
        { id: "hp-2", service: "s3", action: "s3:GetObject", isUsed: true }
      ]
    },
    {
      id: "usr-telehealth-temp",
      name: "telehealth-consultant-dormant",
      type: "User",
      provider: "AWS",
      department: "Remote Telehealth Contractors",
      arn: "arn:aws:iam::552199201940:user/telehealth-consultant-dormant",
      lastActiveTimestamp: new Date(Date.now() - 110 * 86400000).toISOString(),
      daysInactive: 110,
      accessKeysCount: 1,
      unrotatedKeysCount: 1,
      mfaEnabled: false,
      attachedPolicies: ["TelehealthFullAccess", "DatabaseFullAccess"],
      grantedPermissions: [
        { id: "hp-10", service: "rds", action: "rds:*", isUsed: false, isDangerous: true },
        { id: "hp-11", service: "s3", action: "s3:*", isUsed: false, isDangerous: true },
        { id: "hp-12", service: "iam", action: "iam:PassRole", isUsed: false, isDangerous: true }
      ]
    },
    {
      id: "role-radiology-sync",
      name: "RadiologyPACS-SyncRole",
      type: "Role",
      provider: "AWS",
      department: "Imaging Diagnostic Systems",
      arn: "arn:aws:iam::552199201940:role/RadiologyPACS-SyncRole",
      lastActiveTimestamp: new Date(Date.now() - 4 * 86400000).toISOString(),
      daysInactive: 4,
      accessKeysCount: 0,
      unrotatedKeysCount: 0,
      mfaEnabled: true,
      attachedPolicies: ["ImagingStoragePolicy"],
      grantedPermissions: [
        { id: "hp-20", service: "s3", action: "s3:PutObject", isUsed: true },
        { id: "hp-21", service: "s3", action: "s3:GetObject", isUsed: true },
        { id: "hp-22", service: "sts", action: "sts:AssumeRole", isUsed: true, isDangerous: true }
      ]
    }
  ],
  resources: [
    {
      id: "res-ehr-patient-db",
      name: "hipaa-patient-records-sql",
      type: "RDSInstance",
      provider: "AWS",
      sensitivity: "CRITICAL",
      isCrownJewel: true,
      arn: "arn:aws:rds:us-east-1:552199201940:db:hipaa-patient-records-sql",
      description: "Electronic Health Records (EHR) containing patient medical histories and diagnosis reports (HIPAA/HITECH)."
    },
    {
      id: "res-mri-dicom-bucket",
      name: "hospital-dicom-mri-scans",
      type: "S3Bucket",
      provider: "AWS",
      sensitivity: "CRITICAL",
      isCrownJewel: true,
      arn: "arn:aws:s3:::hospital-dicom-mri-scans",
      description: "High-resolution DICOM MRI/CT scan archive."
    }
  ],
  edges: [
    {
      id: "he-1",
      source: "usr-telehealth-temp",
      target: "res-ehr-patient-db",
      type: "CAN_ACCESS",
      label: "Direct Wildcard RDS Access",
      permissions: ["rds:*"],
      isEscalationVector: true
    },
    {
      id: "he-2",
      source: "role-radiology-sync",
      target: "res-mri-dicom-bucket",
      type: "CAN_ACCESS",
      label: "Store DICOM Scans",
      permissions: ["s3:PutObject", "s3:GetObject"]
    }
  ],
  cloudTrailEvents: [
    {
      eventId: "hev-1",
      principalId: "usr-dr-sharma",
      action: "GetItem",
      service: "dynamodb",
      timestamp: "2026-09-27T09:15:00Z",
      sourceIp: "10.0.12.44"
    }
  ]
};

// Write individual JSON files
const fintechJsonPath = path.join(sampleDataDir, 'fintech_production_iam.json');
fs.writeFileSync(fintechJsonPath, JSON.stringify(fintechDataset, null, 2));
fs.writeFileSync(path.join(publicSampleDataDir, 'fintech_production_iam.json'), JSON.stringify(fintechDataset, null, 2));

const healthcareJsonPath = path.join(sampleDataDir, 'healthcare_hipaa_iam.json');
fs.writeFileSync(healthcareJsonPath, JSON.stringify(healthcareDataset, null, 2));
fs.writeFileSync(path.join(publicSampleDataDir, 'healthcare_hipaa_iam.json'), JSON.stringify(healthcareDataset, null, 2));

// 3. Create Multi-File Folder & ZIP Archive
const zip = new JSZip();

// Split fintech dataset into individual standard cloud dump files
const usersOnly = fintechDataset.principals.filter(p => p.type === 'User');
const rolesOnly = fintechDataset.principals.filter(p => p.type === 'Role' || p.type === 'ServiceAccount');

zip.file('iam_users.json', JSON.stringify(usersOnly, null, 2));
zip.file('iam_roles.json', JSON.stringify(rolesOnly, null, 2));
zip.file('cloud_resources.json', JSON.stringify(fintechDataset.resources, null, 2));
zip.file('iam_edges.json', JSON.stringify(fintechDataset.edges, null, 2));
zip.file('cloudtrail_events.json', JSON.stringify(fintechDataset.cloudTrailEvents, null, 2));
zip.file(
  'README.txt',
  `BHARATI VIDYAPEETH'S COLLEGE OF ENGINEERING, NEW DELHI
Department of Computer Science & Engineering
Micro Project: Cloud Identity Risk Analysis (Cloud Security)
Authors: Aditya Ranjan, Ankit Kuhar, Hari Saini | Guide: Ms. Lakshmi Kumari

DUMMY DEMO DATASET: FinTech Multi-Cloud IAM Snapshot
This archive contains:
- iam_users.json: 4 users (Intern with PassRole escalation vector, stale contractor, data engineer, SRE)
- iam_roles.json: Roles and service accounts (Lambda worker, Database admin, Azure SP)
- cloud_resources.json: 5 Cloud resources including Aurora RDS, Secrets Manager, and Customer KYC buckets
- iam_edges.json: Graph edges connecting identities to roles and crown jewels
- cloudtrail_events.json: Audit events indicating active vs unused actions`
);

// Save extracted folder for inspection
const multiFolderDir = path.join(sampleDataDir, 'multi_cloud_iam_bundle');
fs.mkdirSync(multiFolderDir, { recursive: true });
fs.writeFileSync(path.join(multiFolderDir, 'iam_users.json'), JSON.stringify(usersOnly, null, 2));
fs.writeFileSync(path.join(multiFolderDir, 'iam_roles.json'), JSON.stringify(rolesOnly, null, 2));
fs.writeFileSync(path.join(multiFolderDir, 'cloud_resources.json'), JSON.stringify(fintechDataset.resources, null, 2));
fs.writeFileSync(path.join(multiFolderDir, 'iam_edges.json'), JSON.stringify(fintechDataset.edges, null, 2));
fs.writeFileSync(path.join(multiFolderDir, 'cloudtrail_events.json'), JSON.stringify(fintechDataset.cloudTrailEvents, null, 2));
fs.writeFileSync(
  path.join(multiFolderDir, 'README.txt'),
  `BHARATI VIDYAPEETH CSE MICRO PROJECT - DUMMY ARCHIVE BUNDLE`
);

// Generate .zip file
zip.generateAsync({ type: 'nodebuffer' }).then((buffer) => {
  const zipPath = path.join(sampleDataDir, 'fintech_multi_cloud_iam.zip');
  fs.writeFileSync(zipPath, buffer);
  fs.writeFileSync(path.join(publicSampleDataDir, 'fintech_multi_cloud_iam.zip'), buffer);

  console.log('✅ Successfully generated all dummy demonstration files:');
  console.log(`📁 1. Single JSON (FinTech): ${fintechJsonPath}`);
  console.log(`📁 2. Single JSON (Healthcare HIPAA): ${healthcareJsonPath}`);
  console.log(`📁 3. Multi-File ZIP Archive: ${zipPath}`);
  console.log(`📁 4. Public Web Assets Folder: ${publicSampleDataDir}`);
});
