import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  lstat, mkdtemp, mkdir, readFile, readdir, rm, writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';

const BASELINE_COMMIT = 'd7a6df6cb580905280dec5b1e09c0174c9599cc2';
const REPOSITORY_ROOT = resolve(fileURLToPath(new URL('../', import.meta.url)));
const SCRIPT_PATH = fileURLToPath(new URL('../scripts/policy-snapshot.mjs', import.meta.url));
const POLICY_FILES = [
  'src/decider.mjs',
  'src/resource-access.mjs',
  'aleph.config.json',
  'docs/DECIDER_REQUEST.md',
];
const TEST_POLICY_FILES = [...POLICY_FILES, '.policy-snapshot-test.json'];

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function gitBlob(filePath) {
  return execFileSync('git', ['show', `${BASELINE_COMMIT}:${filePath}`], {
    cwd: REPOSITORY_ROOT,
    maxBuffer: 16 * 1024 * 1024,
  });
}

async function withTemporaryWorkspace(run) {
  const workspace = await mkdtemp(join(tmpdir(), 'policy-snapshot-test-'));
  try {
    return await run(workspace);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

async function runCli(command, backupPath, workspace, ...extraArguments) {
  const isolatedTemp = join(workspace, 'isolated-os-temp');
  await mkdir(isolatedTemp, { recursive: true });
  const result = spawnSync(
    process.execPath,
    [SCRIPT_PATH, command, backupPath, ...extraArguments],
    {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        TMPDIR: isolatedTemp,
        TMP: isolatedTemp,
        TEMP: isolatedTemp,
      },
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
    },
  );
  assert.ifError(result.error);
  return result;
}

async function snapshotPathList(root) {
  const paths = [];
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
      } else {
        paths.push(relative(root, path).split(sep).join('/'));
      }
    }
  }
  await visit(root);
  return paths.sort();
}

async function fileHashes(root, filePaths) {
  const entries = [];
  for (const filePath of filePaths) {
    const bytes = await readFile(join(root, ...filePath.split('/')));
    entries.push({ path: filePath, bytes, sha256: sha256(bytes) });
  }
  return entries;
}

async function assertHashesUnchanged(root, before) {
  for (const entry of before) {
    const after = await readFile(join(root, ...entry.path.split('/')));
    assert.equal(
      sha256(after),
      entry.sha256,
      `SHA-256 changed unexpectedly for ${entry.path}`,
    );
    assert.deepEqual(after, entry.bytes, `Bytes changed unexpectedly for ${entry.path}`);
  }
}

async function createTemporaryBackup(workspace) {
  const backupPath = join(workspace, 'snapshot');
  const result = await runCli('backup', backupPath, workspace);
  assert.equal(result.status, 0, `backup failed:\n${result.stderr || result.stdout}`);
  return { backupPath, output: result.stdout };
}

async function prepareAndPreview(workspace, backupPath, name) {
  const testPath = join(workspace, name);
  const prepareResult = await runCli('prepare', backupPath, workspace, testPath);
  assert.equal(
    prepareResult.status,
    0,
    `prepare failed for ${name}:\n${prepareResult.stderr || prepareResult.stdout}`,
  );
  assert.match(prepareResult.stdout, /PREPARE PASS:/);

  const previewResult = await runCli('preview', backupPath, workspace, testPath);
  assert.equal(
    previewResult.status,
    0,
    `preview failed for ${name}:\n${previewResult.stderr || previewResult.stdout}`,
  );
  assert.match(previewResult.stdout, /PREVIEW PASS: test directory verified/);
  const approvalSha256 = previewResult.stdout.match(
    /^Approval confirmation SHA-256: ([0-9a-f]{64})$/m,
  )?.[1];
  assert.ok(approvalSha256, `preview must print approval SHA-256 for ${name}`);
  return { approvalSha256, testPath };
}

async function workingPolicyHashes() {
  return fileHashes(REPOSITORY_ROOT, POLICY_FILES);
}

test('backup writes the four baseline policy files and verifies their manifest hashes', async () => {
  await withTemporaryWorkspace(async workspace => {
    const { backupPath, output } = await createTemporaryBackup(workspace);
    const expectedPaths = [...POLICY_FILES, 'manifest.json'].sort();
    assert.deepEqual(await snapshotPathList(backupPath), expectedPaths);

    const manifest = JSON.parse(await readFile(join(backupPath, 'manifest.json'), 'utf8'));
    assert.equal(manifest.schemaVersion, 1);
    assert.equal(manifest.commitSha, BASELINE_COMMIT);
    assert.deepEqual(
      manifest.files.map(entry => entry.path).sort(),
      [...POLICY_FILES].sort(),
    );

    for (const entry of manifest.files) {
      const bytes = await readFile(join(backupPath, ...entry.path.split('/')));
      const baselineBytes = gitBlob(entry.path);
      assert.equal(entry.byteLength, bytes.length, `${entry.path}: byte length`);
      assert.equal(entry.sha256, sha256(bytes), `${entry.path}: saved SHA-256`);
      assert.deepEqual(bytes, baselineBytes, `${entry.path}: baseline bytes`);
      assert.ok(output.includes(`${entry.sha256} | verified`));
    }
  });
});

test('simulate fails with a missing snapshot file and preserves remaining originals', async () => {
  await withTemporaryWorkspace(async workspace => {
    const { backupPath } = await createTemporaryBackup(workspace);
    const missingFile = 'docs/DECIDER_REQUEST.md';
    const missingPath = join(backupPath, ...missingFile.split('/'));
    const workingBefore = await workingPolicyHashes();
    const backupPaths = POLICY_FILES.filter(filePath => filePath !== missingFile);
    const backupBefore = await fileHashes(backupPath, backupPaths);
    await rm(missingPath);

    const result = await runCli('simulate', backupPath, workspace);
    assert.notEqual(result.status, 0, 'simulate should reject an incomplete backup');
    assert.match(result.stderr, /Policy simulation failed:/);
    assert.match(result.stderr, /ENOENT|no such file/i);
    assert.match(result.stderr, /DECIDER_REQUEST\.md/);
    await assert.rejects(lstat(missingPath), { code: 'ENOENT' });
    await assertHashesUnchanged(backupPath, backupBefore);
    await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
  });
});

test('simulate rejects a modified snapshot file and leaves the modified test backup unchanged', async () => {
  await withTemporaryWorkspace(async workspace => {
    const { backupPath } = await createTemporaryBackup(workspace);
    const changedFile = 'src/decider.mjs';
    const changedPath = join(backupPath, ...changedFile.split('/'));
    const original = await readFile(changedPath, 'utf8');
    const altered = `// temporary tamper fixture\n${original}`;
    await writeFile(changedPath, altered, { flag: 'w' });

    const workingBefore = await workingPolicyHashes();
    const backupBefore = await fileHashes(backupPath, POLICY_FILES);
    const result = await runCli('simulate', backupPath, workspace);
    assert.notEqual(result.status, 0, 'simulate should reject a hash mismatch');
    assert.match(result.stderr, /Policy simulation failed:/);
    assert.match(result.stderr, /Snapshot verification failed for src\/decider\.mjs/);
    await assertHashesUnchanged(backupPath, backupBefore);
    await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
  });
});

test('simulate detects its expected hash mismatch using only temporary copies', async () => {
  await withTemporaryWorkspace(async workspace => {
    const { backupPath } = await createTemporaryBackup(workspace);
    const workingBefore = await workingPolicyHashes();
    const backupBefore = await fileHashes(backupPath, POLICY_FILES);
    const manifestBefore = await readFile(join(backupPath, 'manifest.json'));

    const result = await runCli('simulate', backupPath, workspace);
    assert.equal(result.status, 0, `simulate failed:\n${result.stderr || result.stdout}`);
    assert.match(result.stdout, /SIMULATION PASS: expected hash mismatch detected/);
    assert.match(result.stdout, /Unified diff \(temporary copy only\):/);
    assert.match(result.stdout, /--- a\/src\/resource-access\.mjs/);
    assert.match(result.stdout, /\+\+\+ b\/src\/resource-access\.mjs/);
    assert.match(result.stdout, /^@@ -\d+,1 \+\d+,1 @@$/m);
    assert.match(result.stdout, /^-.*local_proposal_not_engine_verified.*$/m);
    assert.match(result.stdout, /^\+.*local_proposal_simulation_only.*$/m);

    const originalHash = result.stdout.match(/^Original SHA-256: ([0-9a-f]{64})$/m)?.[1];
    const mutatedHash = result.stdout.match(/^Mutated SHA-256: ([0-9a-f]{64})$/m)?.[1];
    assert.ok(originalHash, 'original manifest hash should be reported');
    assert.ok(mutatedHash, 'mutated temporary-copy hash should be reported');
    assert.notEqual(mutatedHash, originalHash, 'simulation must detect the expected mismatch');

    await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
    await assertHashesUnchanged(backupPath, backupBefore);
    assert.deepEqual(await readFile(join(backupPath, 'manifest.json')), manifestBefore);
  });
});

test('isolated restore preview and apply enforce approval and preserve protected files', async t => {
  await withTemporaryWorkspace(async workspace => {
    const { backupPath } = await createTemporaryBackup(workspace);
    const workingBefore = await workingPolicyHashes();
    const backupBefore = await fileHashes(backupPath, [...POLICY_FILES, 'manifest.json']);
    const backupManifestBefore = await readFile(join(backupPath, 'manifest.json'));

    await t.test('preview reports the single restore target without changing test files', async () => {
      const testPath = join(workspace, 'preview-read-only');
      const prepareResult = await runCli('prepare', backupPath, workspace, testPath);
      assert.equal(
        prepareResult.status,
        0,
        `prepare failed:\n${prepareResult.stderr || prepareResult.stdout}`,
      );
      assert.match(prepareResult.stdout, /PREPARE PASS:/);
      const testFilesBeforePreview = await fileHashes(testPath, TEST_POLICY_FILES);
      const preview = await runCli('preview', backupPath, workspace, testPath);

      assert.equal(preview.status, 0, `preview failed:\n${preview.stderr || preview.stdout}`);
      assert.match(preview.stdout, /Restore target: src\/resource-access\.mjs/);
      assert.match(preview.stdout, /^Approval confirmation SHA-256: [0-9a-f]{64}$/m);
      assert.match(preview.stdout, /--- a\/src\/resource-access\.mjs/);
      assert.match(preview.stdout, /\+\+\+ b\/src\/resource-access\.mjs/);
      assert.deepEqual(
        await snapshotPathList(testPath),
        [...TEST_POLICY_FILES].sort(),
        'preview must not add or remove test files',
      );
      await assertHashesUnchanged(testPath, testFilesBeforePreview);
      await assertHashesUnchanged(backupPath, backupBefore);
      await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
      assert.deepEqual(
        await readFile(join(backupPath, 'manifest.json')),
        backupManifestBefore,
        'preview must preserve the backup manifest bytes',
      );
    });

    await t.test('apply rejects a missing approval SHA-256 without changing files', async () => {
      const { testPath } = await prepareAndPreview(
        workspace,
        backupPath,
        'missing-approval',
      );
      const testFilesBefore = await fileHashes(testPath, TEST_POLICY_FILES);
      const result = await runCli('apply', backupPath, workspace, testPath);

      assert.notEqual(result.status, 0, 'apply without approval SHA-256 must fail');
      assert.match(result.stderr, /Policy apply failed:/);
      await assertHashesUnchanged(testPath, testFilesBefore);
      await assertHashesUnchanged(backupPath, backupBefore);
      await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
    });

    await t.test('apply rejects an incorrect approval SHA-256 without changing files', async () => {
      const { approvalSha256, testPath } = await prepareAndPreview(
        workspace,
        backupPath,
        'wrong-approval',
      );
      const testFilesBefore = await fileHashes(testPath, TEST_POLICY_FILES);
      const wrongApproval = approvalSha256 === '0'.repeat(64)
        ? '1'.repeat(64)
        : '0'.repeat(64);
      const result = await runCli(
        'apply',
        backupPath,
        workspace,
        testPath,
        wrongApproval,
      );

      assert.notEqual(result.status, 0, 'apply with an incorrect approval SHA-256 must fail');
      assert.match(result.stderr, /Approval SHA-256 does not match the current test target/);
      await assertHashesUnchanged(testPath, testFilesBefore);
      await assertHashesUnchanged(backupPath, backupBefore);
      await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
    });

    await t.test('apply rejects a test target changed after preview approval', async () => {
      const { approvalSha256, testPath } = await prepareAndPreview(
        workspace,
        backupPath,
        'changed-after-preview',
      );
      const targetPath = join(testPath, 'src', 'resource-access.mjs');
      const originalTestBytes = await readFile(targetPath);
      const changedTestBytes = Buffer.concat([originalTestBytes, Buffer.from('\n')]);
      await writeFile(targetPath, changedTestBytes, { flag: 'w' });
      const changedTestFiles = await fileHashes(testPath, TEST_POLICY_FILES);
      const result = await runCli(
        'apply',
        backupPath,
        workspace,
        testPath,
        approvalSha256,
      );

      assert.notEqual(result.status, 0, 'apply must reject a target changed after preview');
      assert.match(result.stderr, /Test restoration target has an unexpected change/);
      await assertHashesUnchanged(testPath, changedTestFiles);
      await assertHashesUnchanged(backupPath, backupBefore);
      await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
    });

    await t.test('apply restores one test policy file, preserves local classifications, and rejects replay', async () => {
      const { approvalSha256, testPath } = await prepareAndPreview(
        workspace,
        backupPath,
        'successful-apply',
      );
      const manifest = JSON.parse(
        await readFile(join(backupPath, 'manifest.json'), 'utf8'),
      );
      const targetRelativePath = 'src/resource-access.mjs';
      const manifestEntry = manifest.files.find(entry => entry.path === targetRelativePath);
      assert.ok(manifestEntry, 'backup manifest must include the test restoration target');
      const testFilesBeforeApply = await fileHashes(testPath, TEST_POLICY_FILES);

      const result = await runCli(
        'apply',
        backupPath,
        workspace,
        testPath,
        approvalSha256,
      );
      assert.equal(result.status, 0, `apply failed:\n${result.stderr || result.stdout}`);
      assert.match(result.stdout, /APPLY PASS: isolated test target restored/);
      assert.match(result.stdout, /Restore target: src\/resource-access\.mjs/);

      const restoredBytes = await readFile(join(testPath, 'src', 'resource-access.mjs'));
      assert.equal(restoredBytes.length, manifestEntry.byteLength, 'restored test file byte length');
      assert.equal(sha256(restoredBytes), manifestEntry.sha256, 'restored test file SHA-256');
      assert.deepEqual(
        restoredBytes,
        gitBlob(targetRelativePath),
        'restored test file must match the pinned baseline bytes',
      );

      for (const before of testFilesBeforeApply) {
        if (before.path !== targetRelativePath) {
          const after = await readFile(join(testPath, ...before.path.split('/')));
          assert.deepEqual(
            after,
            before.bytes,
            `apply must not change other test policy or metadata: ${before.path}`,
          );
        }
      }
      assert.deepEqual(
        await snapshotPathList(testPath),
        [...TEST_POLICY_FILES].sort(),
        'apply must not add or remove test files',
      );

      const { classifyResourceAccess } = await import(
        pathToFileURL(join(testPath, 'src', 'resource-access.mjs')).href
      );
      const allowedNote = classifyResourceAccess({
        service: 'notes',
        method: 'GET',
        path: '/notes/fixture-note-7',
        route: 'GET /notes/:id',
      });
      assert.equal(allowedNote.outcome, 'allow_candidate', 'individual note GET remains a local allow candidate');
      assert.equal(allowedNote.detail, 'route_matches_local_convention');
      assert.equal(allowedNote.contractStatus, 'local_proposal_not_engine_verified');
      const deniedNoteCollection = classifyResourceAccess({
        service: 'notes',
        method: 'GET',
        path: '/notes',
        route: 'GET /notes',
      });
      assert.equal(deniedNoteCollection.outcome, 'deny_candidate', 'note collection remains a local deny candidate');
      assert.equal(deniedNoteCollection.detail, 'individual_get_only');
      const deniedInstructorMaterial = classifyResourceAccess({
        service: 'instructor_materials',
        method: 'GET',
        path: '/instructor-materials',
        route: 'GET /instructor-materials',
      });
      assert.equal(deniedInstructorMaterial.outcome, 'deny_candidate', 'instructor material remains a local deny candidate');
      assert.equal(deniedInstructorMaterial.detail, 'resource_denied');
      assert.equal(
        deniedInstructorMaterial.contractStatus,
        'local_proposal_not_engine_verified',
        'local classification is not evidence of live API enforcement',
      );

      const replay = await runCli(
        'apply',
        backupPath,
        workspace,
        testPath,
        approvalSha256,
      );
      assert.notEqual(replay.status, 0, 'apply must reject replay of the consumed approval SHA-256');
      assert.match(replay.stderr, /Test restoration target has an unexpected change/);
      assert.deepEqual(
        await readFile(join(testPath, 'src', 'resource-access.mjs')),
        restoredBytes,
        'rejected replay must leave the restored test file unchanged',
      );
      await assertHashesUnchanged(backupPath, backupBefore);
      await assertHashesUnchanged(REPOSITORY_ROOT, workingBefore);
      assert.deepEqual(
        await readFile(join(backupPath, 'manifest.json')),
        backupManifestBefore,
        'apply must preserve the backup manifest bytes',
      );
    });
  });
});
