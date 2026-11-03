import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

const BASELINE_COMMIT = 'd7a6df6cb580905280dec5b1e09c0174c9599cc2';
const SCHEMA_VERSION = 1;
const TEST_METADATA_FILE = '.policy-snapshot-test.json';
const POLICY_FILES = Object.freeze([
  'src/decider.mjs',
  'src/resource-access.mjs',
  'aleph.config.json',
  'docs/DECIDER_REQUEST.md',
]);

function usage() {
  return [
    'Usage:',
    '  node scripts/policy-snapshot.mjs backup <absolute-destination>',
    '  node scripts/policy-snapshot.mjs simulate <absolute-backup-directory>',
    '  node scripts/policy-snapshot.mjs prepare <absolute-backup-directory> <absolute-test-directory>',
    '  node scripts/policy-snapshot.mjs preview <absolute-backup-directory> <absolute-test-directory>',
    '  node scripts/policy-snapshot.mjs apply <absolute-backup-directory> <absolute-test-directory> <preview-approval-sha256>',
    '  node scripts/policy-snapshot.mjs --help',
    '',
    'Creates and verifies a byte-for-byte policy snapshot from commit:',
    `  ${BASELINE_COMMIT}`,
    '',
    'The destination must not exist, its parent must exist, and it must be outside the Git repository.',
    'simulate verifies the backup, changes one temporary test copy, prints a unified diff, and verifies originals again.',
    'prepare creates a new isolated test directory with one intentionally changed policy copy.',
    'preview verifies that test directory and prints a read-only restoration preview; it never applies changes.',
    'apply requires an explicit command and the current test-file SHA-256 printed by preview.',
    'Example (PowerShell):',
    '  node scripts/policy-snapshot.mjs backup "C:\\Users\\User\\AppData\\Local\\DefenseR5\\policy-snapshots\\r5-step-9"',
    '  node scripts/policy-snapshot.mjs prepare "C:\\path\\to\\backup" "C:\\path\\outside-repo\\r5-restore-test"',
    '  node scripts/policy-snapshot.mjs preview "C:\\path\\to\\backup" "C:\\path\\outside-repo\\r5-restore-test"',
  ].join('\n');
}

function runGit(args, encoding) {
  try {
    return execFileSync('git', args, {
      cwd: process.cwd(),
      encoding,
      maxBuffer: 16 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const stderr = Buffer.isBuffer(error.stderr)
      ? error.stderr.toString('utf8').trim()
      : '';
    throw new Error(`Git command failed (${args[0]}): ${stderr || error.message}`);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isWithinOrEqual(parent, candidate) {
  const pathFromParent = relative(parent, candidate);
  return pathFromParent === ''
    || (pathFromParent !== '..'
      && !pathFromParent.startsWith(`..${sep}`)
      && !isAbsolute(pathFromParent));
}

async function findRepositoryRoot() {
  const gitRoot = String(runGit(['rev-parse', '--show-toplevel'], 'utf8')).trim();
  return realpath(gitRoot);
}

function getVerifiedBaselineCommit() {
  const resolvedCommit = String(runGit([
    'rev-parse',
    '--verify',
    `${BASELINE_COMMIT}^{commit}`,
  ], 'utf8')).trim();
  if (resolvedCommit !== BASELINE_COMMIT) {
    throw new Error('The resolved baseline commit does not match the pinned SHA.');
  }

  const objectType = String(runGit(['cat-file', '-t', resolvedCommit], 'utf8')).trim();
  if (objectType !== 'commit') {
    throw new Error('The pinned baseline SHA is not a commit.');
  }
  return resolvedCommit;
}

async function validateDestination(inputPath, repositoryRoot) {
  if (!isAbsolute(inputPath)) {
    throw new Error('Destination must be an absolute path.');
  }

  const requestedPath = resolve(inputPath);
  const destinationName = basename(requestedPath);
  if (!destinationName || destinationName === '.' || destinationName === '..') {
    throw new Error('Destination must name a new directory.');
  }

  const parentPath = await realpath(dirname(requestedPath));
  const destinationPath = resolve(parentPath, destinationName);
  if (isWithinOrEqual(repositoryRoot, destinationPath)) {
    throw new Error('Destination must be outside the Git repository.');
  }

  try {
    await lstat(destinationPath);
    throw new Error('Destination already exists; refusing to overwrite it.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  return destinationPath;
}

async function validateExistingSnapshotDirectory(inputPath, repositoryRoot) {
  if (!isAbsolute(inputPath)) {
    throw new Error('Backup directory must be an absolute path.');
  }

  const requestedPath = resolve(inputPath);
  const info = await lstat(requestedPath);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('Backup path must be an existing, non-symlink directory.');
  }

  const backupPath = await realpath(requestedPath);
  if (isWithinOrEqual(repositoryRoot, backupPath)) {
    throw new Error('Backup directory must be outside the Git repository.');
  }
  return backupPath;
}

function assertIsolatedFrom(repositoryRoot, backupPath, candidatePath, label) {
  if (isWithinOrEqual(repositoryRoot, candidatePath)
      || isWithinOrEqual(backupPath, candidatePath)
      || isWithinOrEqual(candidatePath, backupPath)) {
    throw new Error(`${label} must be outside both the Git repository and backup directory.`);
  }
}

async function validateNewTestDirectory(inputPath, repositoryRoot, backupPath) {
  if (!isAbsolute(inputPath)) {
    throw new Error('Test directory must be an absolute path.');
  }

  const requestedPath = resolve(inputPath);
  const destinationName = basename(requestedPath);
  if (!destinationName || destinationName === '.' || destinationName === '..') {
    throw new Error('Test directory must name a new directory.');
  }

  const parentPath = await realpath(dirname(requestedPath));
  const destinationPath = resolve(parentPath, destinationName);
  assertIsolatedFrom(repositoryRoot, backupPath, destinationPath, 'Test directory');
  try {
    await lstat(destinationPath);
    throw new Error('Test directory already exists; refusing to overwrite it.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return destinationPath;
}

async function validateExistingTestDirectory(inputPath, repositoryRoot, backupPath) {
  if (!isAbsolute(inputPath)) {
    throw new Error('Test directory must be an absolute path.');
  }

  const requestedPath = resolve(inputPath);
  const info = await lstat(requestedPath);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('Test path must be an existing, non-symlink directory.');
  }
  const testPath = await realpath(requestedPath);
  assertIsolatedFrom(repositoryRoot, backupPath, testPath, 'Test directory');
  return testPath;
}

function readCommitBlob(commit, filePath) {
  const treeOutput = runGit(['ls-tree', '-z', commit, '--', filePath]);
  const entries = treeOutput.toString('utf8').split('\0').filter(Boolean);
  if (entries.length !== 1) {
    throw new Error(`Expected exactly one tracked file at ${filePath}.`);
  }

  const entry = /^(\d{6}) (blob) ([0-9a-f]+)\t(.+)$/u.exec(entries[0]);
  if (!entry || !['100644', '100755'].includes(entry[1]) || entry[4] !== filePath) {
    throw new Error(`Expected a regular Git blob at ${filePath}.`);
  }

  return runGit(['cat-file', 'blob', `${commit}:${filePath}`]);
}

async function readRegularSnapshotFile(snapshotRoot, filePath) {
  const segments = filePath.split('/');
  let currentPath = snapshotRoot;
  for (const [index, segment] of segments.entries()) {
    currentPath = join(currentPath, segment);
    const info = await lstat(currentPath);
    const isLeaf = index === segments.length - 1;
    if (info.isSymbolicLink()
        || (isLeaf ? !info.isFile() : !info.isDirectory())) {
      throw new Error(`Snapshot path is not a regular file or directory: ${filePath}`);
    }

    const resolvedPath = await realpath(currentPath);
    if (!isWithinOrEqual(snapshotRoot, resolvedPath)) {
      throw new Error(`Snapshot path escapes its directory: ${filePath}`);
    }
  }
  return readFile(currentPath);
}

async function listTreeEntries(rootPath, currentPath = rootPath) {
  const entries = [];
  for (const name of await readdir(currentPath)) {
    const entryPath = join(currentPath, name);
    const info = await lstat(entryPath);
    const relativePath = relative(rootPath, entryPath).split(sep).join('/');
    if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) {
      throw new Error(`Test directory contains a symlink or unsupported entry: ${relativePath}`);
    }
    entries.push({ path: relativePath, type: info.isDirectory() ? 'directory' : 'file' });
    if (info.isDirectory()) {
      entries.push(...await listTreeEntries(rootPath, entryPath));
    }
  }
  return entries;
}

async function writeExclusive(filePath, bytes) {
  await writeFile(filePath, bytes, { flag: 'wx', mode: 0o600 });
}

function parseAndValidateManifest(manifestBytes, commit) {
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    throw new Error(`Snapshot manifest is not valid JSON: ${error.message}`);
  }

  if (!manifest || manifest.schemaVersion !== SCHEMA_VERSION
      || manifest.commitSha !== commit
      || !Array.isArray(manifest.files)
      || manifest.files.length !== POLICY_FILES.length) {
    throw new Error('The saved manifest does not match the expected snapshot.');
  }

  const entries = new Map();
  for (const entry of manifest.files) {
    if (!entry || typeof entry.path !== 'string'
        || !Number.isSafeInteger(entry.byteLength) || entry.byteLength < 0
        || typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(entry.sha256)
        || entries.has(entry.path)) {
      throw new Error('The saved manifest contains an invalid or duplicate entry.');
    }
    entries.set(entry.path, entry);
  }
  if (POLICY_FILES.some(filePath => !entries.has(filePath))
      || entries.size !== POLICY_FILES.length) {
    throw new Error('The saved manifest does not list exactly the four policy files.');
  }
  return manifest;
}

async function verifySnapshot(destinationPath, commit, sourceFiles, manifest) {
  const diskManifestBytes = await readRegularSnapshotFile(destinationPath, 'manifest.json');
  const diskManifest = parseAndValidateManifest(diskManifestBytes, commit);

  const results = [];
  for (const source of sourceFiles) {
    const manifestEntry = diskManifest.files.find(item => item.path === source.path);
    const expectedEntry = manifest.files.find(item => item.path === source.path);
    if (!manifestEntry || !expectedEntry
        || manifestEntry.byteLength !== expectedEntry.byteLength
        || manifestEntry.sha256 !== expectedEntry.sha256) {
      throw new Error(`Saved manifest entry mismatch for ${source.path}.`);
    }

    const snapshotPath = join(destinationPath, ...source.path.split('/'));
    const diskBytes = await readRegularSnapshotFile(destinationPath, source.path);
    const diskHash = sha256(diskBytes);
    if (diskBytes.length !== source.bytes.length
        || diskBytes.length !== manifestEntry.byteLength
        || diskHash !== source.sha256
        || diskHash !== manifestEntry.sha256
        || !diskBytes.equals(source.bytes)) {
      throw new Error(`Snapshot verification failed for ${source.path}.`);
    }
    results.push({ path: source.path, snapshotPath, sha256: diskHash });
  }

  return results;
}

function createTamperedResourceCopy(sourceBytes) {
  const beforeText = sourceBytes.toString('utf8');
  const originalMarker = 'local_proposal_not_engine_verified';
  const replacementMarker = 'local_proposal_simulation_only';
  const markerIndex = beforeText.indexOf(originalMarker);
  if (markerIndex < 0 || beforeText.indexOf(originalMarker, markerIndex + 1) >= 0) {
    throw new Error('Expected exactly one synthetic policy marker in the snapshot copy.');
  }
  const afterText = beforeText.replace(originalMarker, replacementMarker);
  const afterBytes = Buffer.from(afterText, 'utf8');
  const diff = createUnifiedDiff('src/resource-access.mjs', beforeText, afterText);
  return { afterBytes, afterText, beforeText, diff };
}

async function readVerifiedBackup(backupArgument, repositoryRoot) {
  const commit = getVerifiedBaselineCommit();
  const backupPath = await validateExistingSnapshotDirectory(
    backupArgument,
    repositoryRoot,
  );
  const manifestBytes = await readRegularSnapshotFile(backupPath, 'manifest.json');
  const manifest = parseAndValidateManifest(manifestBytes, commit);
  const baselineFiles = POLICY_FILES.map(filePath => {
    const bytes = readCommitBlob(commit, filePath);
    return { path: filePath, bytes, byteLength: bytes.length, sha256: sha256(bytes) };
  });
  const verifiedFiles = await verifySnapshot(
    backupPath,
    commit,
    baselineFiles,
    manifest,
  );
  const manifestBytesAfter = await readRegularSnapshotFile(backupPath, 'manifest.json');
  if (!manifestBytesAfter.equals(manifestBytes)) {
    throw new Error('Backup manifest changed while it was being verified.');
  }
  const snapshotFiles = [];
  for (const filePath of POLICY_FILES) {
    const bytes = await readRegularSnapshotFile(backupPath, filePath);
    const baseline = baselineFiles.find(file => file.path === filePath);
    const entry = manifest.files.find(file => file.path === filePath);
    if (!baseline || !entry || !bytes.equals(baseline.bytes)
        || bytes.length !== entry.byteLength || sha256(bytes) !== entry.sha256) {
      throw new Error(`Backup policy changed while it was being verified: ${filePath}`);
    }
    snapshotFiles.push({ path: filePath, bytes, sha256: sha256(bytes) });
  }
  return {
    backupPath,
    commit,
    manifest,
    manifestBytes,
    manifestSha256: sha256(manifestBytes),
    snapshotFiles,
    verifiedFiles,
  };
}

function expectedTestTreeEntries() {
  return [
    ...POLICY_FILES.map(path => ({ path, type: 'file' })),
    { path: TEST_METADATA_FILE, type: 'file' },
    { path: 'src', type: 'directory' },
    { path: 'docs', type: 'directory' },
  ].sort((left, right) => left.path.localeCompare(right.path));
}

async function validatePreparedTestDirectory(testPath, backup) {
  const actualEntries = (await listTreeEntries(testPath))
    .sort((left, right) => left.path.localeCompare(right.path));
  const expectedEntries = expectedTestTreeEntries();
  if (JSON.stringify(actualEntries) !== JSON.stringify(expectedEntries)) {
    throw new Error('Test directory structure is incomplete or contains unexpected entries.');
  }

  const metadataBytes = await readRegularSnapshotFile(testPath, TEST_METADATA_FILE);
  let metadata;
  try {
    metadata = JSON.parse(metadataBytes.toString('utf8'));
  } catch (error) {
    throw new Error(`Test metadata is not valid JSON: ${error.message}`);
  }

  const expectedTargetPath = 'src/resource-access.mjs';
  const targetSource = backup.snapshotFiles.find(file => file.path === expectedTargetPath);
  const mutation = createTamperedResourceCopy(targetSource.bytes);
  const expectedMetadata = {
    schemaVersion: SCHEMA_VERSION,
    commitSha: backup.commit,
    backupManifestSha256: backup.manifestSha256,
    restoreTarget: expectedTargetPath,
    tamperedSha256: sha256(mutation.afterBytes),
  };
  if (JSON.stringify(metadata) !== JSON.stringify(expectedMetadata)
      || !metadataBytes.equals(Buffer.from(`${JSON.stringify(expectedMetadata, null, 2)}\n`, 'utf8'))) {
    throw new Error('Test metadata does not match the verified backup and expected test copy.');
  }

  for (const file of backup.snapshotFiles) {
    const testBytes = await readRegularSnapshotFile(testPath, file.path);
    if (file.path === expectedTargetPath) {
      if (!testBytes.equals(mutation.afterBytes)
          || sha256(testBytes) !== metadata.tamperedSha256) {
        throw new Error('Test restoration target has an unexpected change.');
      }
    } else if (!testBytes.equals(file.bytes)) {
      throw new Error(`Test policy copy unexpectedly changed: ${file.path}`);
    }
  }

  const targetEntry = backup.manifest.files.find(entry => entry.path === expectedTargetPath);
  const targetBytes = await readRegularSnapshotFile(testPath, expectedTargetPath);
  return {
    commit: backup.commit,
    diff: mutation.diff,
    originalHash: targetEntry.sha256,
    targetPath: expectedTargetPath,
    testPath,
    currentHash: sha256(targetBytes),
  };
}

async function prepareTestDirectory(backupArgument, testDirectoryArgument) {
  const repositoryRoot = await findRepositoryRoot();
  const backup = await readVerifiedBackup(backupArgument, repositoryRoot);
  const testPath = await validateNewTestDirectory(
    testDirectoryArgument,
    repositoryRoot,
    backup.backupPath,
  );
  let directoryCreated = false;
  try {
    await mkdir(testPath, { recursive: false, mode: 0o700 });
    directoryCreated = true;
    for (const file of backup.snapshotFiles) {
      const targetPath = join(testPath, ...file.path.split('/'));
      await mkdir(dirname(targetPath), { recursive: true, mode: 0o700 });
      const bytes = file.path === 'src/resource-access.mjs'
        ? createTamperedResourceCopy(file.bytes).afterBytes
        : file.bytes;
      await writeExclusive(targetPath, bytes);
    }

    const target = backup.snapshotFiles.find(
      file => file.path === 'src/resource-access.mjs',
    );
    const mutation = createTamperedResourceCopy(target.bytes);
    const metadata = {
      schemaVersion: SCHEMA_VERSION,
      commitSha: backup.commit,
      backupManifestSha256: backup.manifestSha256,
      restoreTarget: 'src/resource-access.mjs',
      tamperedSha256: sha256(mutation.afterBytes),
    };
    await writeExclusive(
      join(testPath, TEST_METADATA_FILE),
      Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8'),
    );

    const prepared = await validatePreparedTestDirectory(testPath, backup);
    return { ...prepared, backupPath: backup.backupPath };
  } catch (error) {
    if (directoryCreated) {
      error.message = `${error.message}\nIncomplete test directory: ${testPath}`;
    }
    throw error;
  }
}

async function previewTestRestoration(backupArgument, testDirectoryArgument) {
  const repositoryRoot = await findRepositoryRoot();
  const backup = await readVerifiedBackup(backupArgument, repositoryRoot);
  const testPath = await validateExistingTestDirectory(
    testDirectoryArgument,
    repositoryRoot,
    backup.backupPath,
  );
  return validatePreparedTestDirectory(testPath, backup);
}

async function applyTestRestoration(
  backupArgument,
  testDirectoryArgument,
  approvalSha256,
) {
  if (!/^[0-9a-f]{64}$/u.test(approvalSha256)) {
    throw new Error('A valid preview approval SHA-256 is required; no files were changed.');
  }

  const repositoryRoot = await findRepositoryRoot();
  const backup = await readVerifiedBackup(backupArgument, repositoryRoot);
  const testPath = await validateExistingTestDirectory(
    testDirectoryArgument,
    repositoryRoot,
    backup.backupPath,
  );
  const preview = await validatePreparedTestDirectory(testPath, backup);
  if (preview.currentHash !== approvalSha256) {
    throw new Error('Approval SHA-256 does not match the current test target; no files were changed.');
  }

  const targetRelativePath = 'src/resource-access.mjs';
  const canonicalTestPath = await realpath(testPath);
  const targetDirectory = join(canonicalTestPath, 'src');
  const targetDirectoryInfo = await lstat(targetDirectory);
  if (!targetDirectoryInfo.isDirectory() || targetDirectoryInfo.isSymbolicLink()
      || await realpath(join(testPath, 'src')) !== targetDirectory) {
    throw new Error('Restore target directory is not a regular directory inside the test folder.');
  }
  const targetPath = join(targetDirectory, 'resource-access.mjs');
  const original = backup.snapshotFiles.find(file => file.path === targetRelativePath);
  const manifestEntry = backup.manifest.files.find(
    entry => entry.path === targetRelativePath,
  );
  if (!original || !manifestEntry
      || original.bytes.length !== manifestEntry.byteLength
      || original.sha256 !== manifestEntry.sha256) {
    throw new Error('Verified backup target does not match its manifest.');
  }

  const testRootEntries = await listTreeEntries(testPath);
  const unchangedTestFiles = [];
  for (const entry of testRootEntries) {
    if (entry.type !== 'file'
        || entry.path === targetRelativePath) {
      continue;
    }
    unchangedTestFiles.push({
      path: entry.path,
      bytes: await readRegularSnapshotFile(testPath, entry.path),
    });
  }
  const workingFilesBefore = await readWorkingPolicyFiles(repositoryRoot);
  const manifestBytesBefore = backup.manifestBytes;
  const tempPath = join(
    targetDirectory,
    `.resource-access.restore-${randomUUID()}.tmp`,
  );
  let tempCreated = false;

  try {
    await writeExclusive(tempPath, original.bytes);
    tempCreated = true;
    const stagedBytes = await readRegularSnapshotFile(testPath, relative(testPath, tempPath).split(sep).join('/'));
    if (!stagedBytes.equals(original.bytes)
        || stagedBytes.length !== manifestEntry.byteLength
        || sha256(stagedBytes) !== manifestEntry.sha256) {
      throw new Error('Staged restore file failed backup length or SHA-256 verification.');
    }

    const testPathNow = await realpath(testPath);
    if (testPathNow !== canonicalTestPath
        || await realpath(join(testPath, 'src')) !== targetDirectory) {
      throw new Error('Test directory path changed during apply.');
    }
    const targetInfo = await lstat(targetPath);
    if (!targetInfo.isFile() || targetInfo.isSymbolicLink()
        || await realpath(dirname(targetPath)) !== targetDirectory) {
      throw new Error('Restore target path changed or is not a regular test file.');
    }
    const targetBytesBeforeReplace = await readRegularSnapshotFile(
      testPath,
      targetRelativePath,
    );
    if (sha256(targetBytesBeforeReplace) !== approvalSha256) {
      throw new Error('Test target changed after preview approval; no restoration was applied.');
    }

    process.stdout.write(`Apply approval SHA-256: ${approvalSha256}\n`);
    process.stdout.write(`Baseline commit: ${backup.commit}\n`);
    process.stdout.write(`Restore target: ${targetRelativePath}\n`);
    process.stdout.write(`Change scope: ${preview.diff.split('\n')[2]}\n`);
    process.stdout.write(`Unified diff (test copy only):\n${preview.diff}\n`);

    const finalTargetBytesBeforeReplace = await readRegularSnapshotFile(
      testPath,
      targetRelativePath,
    );
    if (sha256(finalTargetBytesBeforeReplace) !== approvalSha256
        || !finalTargetBytesBeforeReplace.equals(targetBytesBeforeReplace)) {
      throw new Error('Test target changed immediately before replacement; restoration was refused.');
    }
    await rename(tempPath, targetPath);
    tempCreated = false;

    const restoredBytes = await readRegularSnapshotFile(testPath, targetRelativePath);
    if (!restoredBytes.equals(original.bytes)
        || restoredBytes.length !== manifestEntry.byteLength
        || sha256(restoredBytes) !== manifestEntry.sha256) {
      throw new Error('Restored test target failed post-apply length or SHA-256 verification.');
    }

    for (const file of unchangedTestFiles) {
      const afterBytes = await readRegularSnapshotFile(testPath, file.path);
      if (!afterBytes.equals(file.bytes)) {
        throw new Error(`Unexpected test metadata or policy change after apply: ${file.path}`);
      }
    }

    const backupAfter = await readVerifiedBackup(backupArgument, repositoryRoot);
    if (!backupAfter.manifestBytes.equals(manifestBytesBefore)) {
      throw new Error('Backup manifest changed during apply.');
    }
    for (const file of backup.snapshotFiles) {
      const after = backupAfter.snapshotFiles.find(item => item.path === file.path);
      if (!after || !after.bytes.equals(file.bytes)) {
        throw new Error(`Backup policy changed during apply: ${file.path}`);
      }
    }
    const workingFilesAfter = await readWorkingPolicyFiles(repositoryRoot);
    assertUnchanged('working policy', workingFilesBefore, workingFilesAfter);

    return {
      commit: backup.commit,
      targetPath: targetRelativePath,
      restoredHash: sha256(restoredBytes),
      restoredByteLength: restoredBytes.length,
    };
  } finally {
    if (tempCreated) {
      await rm(tempPath, { force: true });
    }
  }
}

async function readWorkingPolicyFiles(repositoryRoot) {
  const files = [];
  for (const filePath of POLICY_FILES) {
    const absolutePath = join(repositoryRoot, ...filePath.split('/'));
    const bytes = await readFile(absolutePath);
    files.push({ path: filePath, bytes, sha256: sha256(bytes) });
  }
  return files;
}

function assertUnchanged(label, beforeFiles, afterFiles) {
  for (const before of beforeFiles) {
    const after = afterFiles.find(file => file.path === before.path);
    if (!after || after.sha256 !== before.sha256
        || (before.bytes && !after.bytes.equals(before.bytes))) {
      throw new Error(`Unexpected ${label} change detected for ${before.path}.`);
    }
  }
}

function createUnifiedDiff(filePath, beforeText, afterText) {
  const beforeLines = beforeText.split(/\r?\n/u);
  const afterLines = afterText.split(/\r?\n/u);
  const changedLines = [];
  for (let index = 0; index < beforeLines.length; index += 1) {
    if (beforeLines[index] !== afterLines[index]) {
      changedLines.push(index);
    }
  }
  if (changedLines.length !== 1 || beforeLines.length !== afterLines.length) {
    throw new Error('Simulation must change exactly one line.');
  }

  const lineNumber = changedLines[0] + 1;
  return [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -${lineNumber},1 +${lineNumber},1 @@`,
    `-${beforeLines[changedLines[0]]}`,
    `+${afterLines[changedLines[0]]}`,
  ].join('\n');
}

async function createSimulationCopies(tempRoot, snapshotFiles) {
  const beforeRoot = join(tempRoot, 'before');
  const afterRoot = join(tempRoot, 'after');
  await mkdir(beforeRoot, { mode: 0o700 });
  await mkdir(afterRoot, { mode: 0o700 });

  for (const file of snapshotFiles) {
    for (const root of [beforeRoot, afterRoot]) {
      const target = join(root, ...file.path.split('/'));
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeExclusive(target, file.bytes);
    }
  }

  return { beforeRoot, afterRoot };
}

async function simulateTampering(backupArgument) {
  const repositoryRoot = await findRepositoryRoot();
  const commit = getVerifiedBaselineCommit();
  const backupPath = await validateExistingSnapshotDirectory(
    backupArgument,
    repositoryRoot,
  );
  const manifestBytesBefore = await readRegularSnapshotFile(backupPath, 'manifest.json');
  const manifest = parseAndValidateManifest(manifestBytesBefore, commit);
  const baselineFiles = POLICY_FILES.map(filePath => {
    const bytes = readCommitBlob(commit, filePath);
    return { path: filePath, bytes, byteLength: bytes.length, sha256: sha256(bytes) };
  });
  const backupFilesBefore = await verifySnapshot(
    backupPath,
    commit,
    baselineFiles,
    manifest,
  );
  const workingFilesBefore = await readWorkingPolicyFiles(repositoryRoot);
  const snapshotFiles = [];
  for (const filePath of POLICY_FILES) {
    const bytes = await readRegularSnapshotFile(backupPath, filePath);
    snapshotFiles.push({ path: filePath, bytes, sha256: sha256(bytes) });
  }

  const tempBase = await realpath(tmpdir());
  if (isWithinOrEqual(repositoryRoot, tempBase)
      || isWithinOrEqual(backupPath, tempBase)
      || isWithinOrEqual(tempBase, backupPath)) {
    throw new Error('The operating-system temporary directory is not isolated from the repository and backup.');
  }

  let tempRoot;
  try {
    tempRoot = await mkdtemp(join(tempBase, 'defense-r5-policy-sim-'));
    tempRoot = await realpath(tempRoot);
    if (isWithinOrEqual(repositoryRoot, tempRoot)
        || isWithinOrEqual(backupPath, tempRoot)
        || isWithinOrEqual(tempBase, tempRoot) === false) {
      throw new Error('The simulation directory is not isolated from the repository and backup.');
    }

    const { beforeRoot, afterRoot } = await createSimulationCopies(tempRoot, snapshotFiles);
    const resourceFile = snapshotFiles.find(file => file.path === 'src/resource-access.mjs');
    let simulationResult;
    let simulationFailure;
    try {
      const beforePath = join(beforeRoot, 'src', 'resource-access.mjs');
      const beforeBytes = await readFile(beforePath);
      if (!beforeBytes.equals(resourceFile.bytes)
          || sha256(beforeBytes) !== resourceFile.sha256) {
        throw new Error('Temporary original copy does not match the verified backup.');
      }

      const mutation = createTamperedResourceCopy(beforeBytes);
      const afterPath = join(afterRoot, 'src', 'resource-access.mjs');
      await writeFile(afterPath, mutation.afterBytes, { flag: 'w', mode: 0o600 });

      const mutatedBytes = await readFile(afterPath);
      const mutatedHash = sha256(mutatedBytes);
      const manifestEntry = manifest.files.find(
        entry => entry.path === 'src/resource-access.mjs',
      );
      if (!manifestEntry || mutatedHash === manifestEntry.sha256) {
        throw new Error('Simulation did not produce the expected hash mismatch.');
      }

      simulationResult = {
        backupPath,
        diff: mutation.diff,
        originalHash: manifestEntry.sha256,
        mutatedHash,
      };
    } catch (error) {
      simulationFailure = error;
    }

    try {
      const backupFilesAfter = await verifySnapshot(
        backupPath,
        commit,
        baselineFiles,
        manifest,
      );
      const workingFilesAfter = await readWorkingPolicyFiles(repositoryRoot);
      assertUnchanged('working policy', workingFilesBefore, workingFilesAfter);
      assertUnchanged('backup policy', backupFilesBefore, backupFilesAfter);
      const manifestBytesAfter = await readRegularSnapshotFile(backupPath, 'manifest.json');
      if (!manifestBytesAfter.equals(manifestBytesBefore)) {
        throw new Error('Unexpected backup manifest change detected.');
      }
    } catch (error) {
      throw new Error(
        `${error.message}${simulationFailure ? `; simulation also failed: ${simulationFailure.message}` : ''}`,
      );
    }

    if (simulationFailure) throw simulationFailure;
    return simulationResult;
  } finally {
    if (tempRoot) {
      await rm(tempRoot, { recursive: true, force: false });
    }
  }
}

async function createBackup(destinationArgument) {
  const repositoryRoot = await findRepositoryRoot();
  const resolvedCommit = getVerifiedBaselineCommit();

  const destinationPath = await validateDestination(destinationArgument, repositoryRoot);
  const sourceFiles = POLICY_FILES.map(filePath => {
    const bytes = readCommitBlob(resolvedCommit, filePath);
    return { path: filePath, bytes, byteLength: bytes.length, sha256: sha256(bytes) };
  });
  const manifest = {
    schemaVersion: SCHEMA_VERSION,
    commitSha: resolvedCommit,
    files: sourceFiles.map(({ path, byteLength, sha256: digest }) => ({
      path,
      byteLength,
      sha256: digest,
    })),
  };
  let destinationCreated = false;

  try {
    await mkdir(destinationPath, { recursive: false, mode: 0o700 });
    destinationCreated = true;

    for (const source of sourceFiles) {
      const snapshotPath = join(destinationPath, ...source.path.split('/'));
      await mkdir(dirname(snapshotPath), { recursive: true, mode: 0o700 });
      await writeExclusive(snapshotPath, source.bytes);
    }
    await writeExclusive(
      join(destinationPath, 'manifest.json'),
      Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'),
    );

    const verifiedFiles = await verifySnapshot(
      destinationPath,
      resolvedCommit,
      sourceFiles,
      manifest,
    );
    return { destinationPath, verifiedFiles };
  } catch (error) {
    if (destinationCreated) {
      error.message = `${error.message}\nIncomplete backup location: ${destinationPath}`;
    }
    throw error;
  }
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  if (command === '--help' || command === '-h') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  if (command === 'backup') {
    if (arguments_.length !== 1) throw new Error(usage());
    const [destinationArgument] = arguments_;
    const backup = await createBackup(destinationArgument);
    process.stdout.write(`Backup verified: ${backup.destinationPath}\n`);
    for (const file of backup.verifiedFiles) {
      process.stdout.write(
        `${file.path} -> ${file.snapshotPath} | sha256=${file.sha256} | verified\n`,
      );
    }
    return;
  }
  if (command === 'simulate') {
    if (arguments_.length !== 1) throw new Error(usage());
    const [destinationArgument] = arguments_;
    const simulation = await simulateTampering(destinationArgument);
    process.stdout.write(`Simulation copy only; backup verified: ${simulation.backupPath}\n`);
    process.stdout.write(
      `Unified diff (temporary copy only):\n${simulation.diff}\n`,
    );
    process.stdout.write(`Original SHA-256: ${simulation.originalHash}\n`);
    process.stdout.write(`Mutated SHA-256: ${simulation.mutatedHash}\n`);
    process.stdout.write('SIMULATION PASS: expected hash mismatch detected; working files and backup are unchanged.\n');
    return;
  }
  if (command === 'prepare') {
    if (arguments_.length !== 2) throw new Error(usage());
    const prepared = await prepareTestDirectory(arguments_[0], arguments_[1]);
    process.stdout.write(`Prepared isolated policy test directory: ${prepared.testPath}\n`);
    process.stdout.write(`Verified backup: ${prepared.backupPath}\n`);
    process.stdout.write(`Baseline commit: ${prepared.commit}\n`);
    process.stdout.write(`Test-only changed file: ${prepared.targetPath} | sha256=${prepared.currentHash}\n`);
    process.stdout.write('PREPARE PASS: verified policy copies created; no restoration was applied.\n');
    return;
  }
  if (command === 'preview') {
    if (arguments_.length !== 2) throw new Error(usage());
    const preview = await previewTestRestoration(arguments_[0], arguments_[1]);
    process.stdout.write(`Baseline commit: ${preview.commit}\n`);
    process.stdout.write(`Test directory: ${preview.testPath}\n`);
    process.stdout.write(`Restore target: ${preview.targetPath}\n`);
    process.stdout.write(`Backup source SHA-256: ${preview.originalHash}\n`);
    process.stdout.write(`Current test SHA-256: ${preview.currentHash}\n`);
    process.stdout.write(`Approval confirmation SHA-256: ${preview.currentHash}\n`);
    process.stdout.write(`Unified diff (preview only):\n${preview.diff}\n`);
    process.stdout.write('PREVIEW PASS: test directory verified; no files were changed.\n');
    return;
  }
  if (command === 'apply') {
    if (arguments_.length !== 3) throw new Error(usage());
    const applied = await applyTestRestoration(
      arguments_[0],
      arguments_[1],
      arguments_[2],
    );
    process.stdout.write(`Restored test copy: ${applied.targetPath}\n`);
    process.stdout.write(`Baseline commit: ${applied.commit}\n`);
    process.stdout.write(`Restored byte length: ${applied.restoredByteLength}\n`);
    process.stdout.write(`Restored SHA-256: ${applied.restoredHash}\n`);
    process.stdout.write('APPLY PASS: isolated test target restored and all post-apply checks passed; working files and backup are unchanged.\n');
    return;
  }
  throw new Error(usage());
}

main().catch(error => {
  const commandName = ({
    simulate: 'simulation',
    prepare: 'preparation',
    preview: 'preview',
    apply: 'apply',
  })[process.argv[2]] || 'backup';
  process.stderr.write(`Policy ${commandName} failed: ${error.message}\n`);
  process.exitCode = 1;
});
