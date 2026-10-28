import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';

const projectRoot = path.resolve('.');
const zip = new JSZip();

// Folders and files to include
const includeItems = [
  'src',
  'public',
  'sample-data',
  'scripts',
  'index.html',
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'tsconfig.app.json',
  'tsconfig.node.json',
  'vite.config.ts',
  'README.md',
  '.gitignore',
  '.oxlintrc.json',
];

function addFileToZip(zipFolder, fullPath, relativePath) {
  const stat = fs.statSync(fullPath);
  if (stat.isDirectory()) {
    const dir = zipFolder.folder(relativePath);
    const files = fs.readdirSync(fullPath);
    for (const file of files) {
      if (file === 'node_modules' || file === '.git' || file === 'dist' || file.endsWith('.zip')) {
        continue;
      }
      addFileToZip(dir, path.join(fullPath, file), file);
    }
  } else {
    // Exclude zip files themselves
    if (!relativePath.endsWith('.zip')) {
      const content = fs.readFileSync(fullPath);
      zipFolder.file(relativePath, content);
    }
  }
}

console.log('Archiving CloudGuard project files...');
for (const item of includeItems) {
  const itemPath = path.join(projectRoot, item);
  if (fs.existsSync(itemPath)) {
    console.log(`Adding ${item}...`);
    addFileToZip(zip, itemPath, item);
  }
}

zip
  .generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 },
  })
  .then((buffer) => {
    // 1. Save in scratch root
    const outPathRoot = path.resolve('..', 'cloudguard-website.zip');
    fs.writeFileSync(outPathRoot, buffer);
    console.log(`Successfully created zip at: ${outPathRoot} (${(buffer.length / 1024).toFixed(1)} KB)`);

    // 2. Save in public folder for browser download
    const outPathPublic = path.join(projectRoot, 'public', 'cloudguard-website.zip');
    fs.writeFileSync(outPathPublic, buffer);
    console.log(`Saved in public directory for browser download: ${outPathPublic}`);
  })
  .catch((err) => {
    console.error('Error generating zip archive:', err);
    process.exit(1);
  });
