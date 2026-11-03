import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { createNoteBackupManifest } from '../src/note-backup-manifest.mjs';
import { signNoteBackupManifest } from '../src/note-backup-sign.mjs';
import { saveVerifiedNoteBackup } from '../src/note-backup-store.mjs';

const userId = '30000000-0000-4000-8000-000000000041';
const noteId = '50000000-0000-4000-8000-000000000041';
const backupVersion = 'synthetic-store-backup-v1';
const keyId = 'synthetic-store-key';
const title = 'synthetic private title marker';
const content = 'synthetic private content marker';
const privateKeyMarker = 'synthetic-private-key-marker';
const tokenMarker = 'synthetic-token-marker';
const completionPrefix = 'note-backups/v1/completed/';

function createFixture(overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const backup = {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
    ...overrides.backup,
  };
  const manifest = createNoteBackupManifest({
    ...backup,
    keyId,
    ...overrides.manifest,
  });
  const signature = signNoteBackupManifest({ manifest, privateKey });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    backup,
    manifest,
    signature,
    privateKeyMarker,
    tokenMarker,
    trustedPublicKeys: [{ keyId, publicKeyPem }],
  };
}

function createMemoryAdapter(options = {}) {
  const objects = new Map();
  let createCount = 0;
  let readCount = 0;

  return {
    objects,
    async createIfAbsent(path, bytes) {
      createCount += 1;
      if (objects.has(path)) return false;
      const action = options.onCreate
        ? await options.onCreate(path, Buffer.from(bytes), createCount)
        : null;
      if (action === 'false') return false;
      if (action === 'invalid') return undefined;
      if (action === 'throw') throw new Error(tokenMarker);
      objects.set(path, Buffer.from(bytes));
      if (action === 'store_then_throw') throw new Error(tokenMarker);
      return true;
    },
    async read(path) {
      readCount += 1;
      if (!objects.has(path)) return undefined;
      const bytes = Buffer.from(objects.get(path));
      const action = options.onRead
        ? await options.onRead(path, bytes, readCount)
        : null;
      if (action === 'missing') return undefined;
      if (action === 'throw') throw new Error(tokenMarker);
      if (action === 'invalid') return tokenMarker;
      if (Buffer.isBuffer(action) || action instanceof Uint8Array) {
        return action;
      }
      return bytes;
    },
  };
}

function save(fixture, storageAdapter) {
  return saveVerifiedNoteBackup({
    ...fixture,
    storageAdapter,
  });
}

function pathsFor(adapter) {
  return [...adapter.objects.keys()];
}

function completionPaths(adapter) {
  return pathsFor(adapter).filter(path => path.startsWith(completionPrefix));
}

function assertNoSensitiveData(value) {
  const serialized = JSON.stringify(value);
  for (const marker of [title, content, privateKeyMarker, tokenMarker]) {
    assert.equal(serialized.includes(marker), false);
  }
}

test('stores separately encoded objects and a final completion marker', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter();

  const result = await save(fixture, adapter);

  assert.equal(result.saved, true);
  assert.equal(result.status, 'complete');
  assert.match(result.backupRef, /^nb1_[0-9a-f]{64}$/u);
  const paths = pathsFor(adapter);
  assert.equal(paths.length, 4);
  assert.equal(paths.filter(path => path.endsWith('/backup.json')).length, 1);
  assert.equal(paths.filter(path => path.endsWith('/manifest.json')).length, 1);
  assert.equal(paths.filter(path => path.endsWith('/signature.txt')).length, 1);
  assert.equal(completionPaths(adapter).length, 1);

  const backupPath = paths.find(path => path.endsWith('/backup.json'));
  const manifestPath = paths.find(path => path.endsWith('/manifest.json'));
  const signaturePath = paths.find(path => path.endsWith('/signature.txt'));
  const completionPath = completionPaths(adapter)[0];
  assert.match(backupPath, /^note-backups\/v1\/[0-9a-f-]+\/[0-9a-f-]+\/[A-Za-z0-9_-]+\/backup\.json$/u);
  assert.match(manifestPath, /\/manifest\.json$/u);
  assert.match(signaturePath, /\/signature\.txt$/u);
  assert.match(completionPath, /^note-backups\/v1\/completed\/nb1_[0-9a-f]{64}\.json$/u);

  const storedBackup = JSON.parse(adapter.objects.get(backupPath).toString('utf8'));
  const storedManifest = JSON.parse(adapter.objects.get(manifestPath).toString('utf8'));
  const storedSignature = adapter.objects.get(signaturePath).toString('ascii');
  const completion = JSON.parse(adapter.objects.get(completionPath).toString('utf8'));
  assert.deepEqual(storedBackup, fixture.backup);
  assert.deepEqual(storedManifest, fixture.manifest);
  assert.equal(storedSignature, fixture.signature);
  assert.equal(completion.backupRef, result.backupRef);
  assert.deepEqual(Object.keys(completion.objects).sort(), [
    'backup',
    'manifest',
    'signature',
  ]);
  assertNoSensitiveData(result);
});

test('createIfAbsent refuses to overwrite an existing object', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter();
  const versionSegment = Buffer.from(fixture.backup.backupVersion, 'utf8')
    .toString('base64url');
  const existingPath = `note-backups/v1/${userId}/${noteId}/${versionSegment}/backup.json`;
  const original = Buffer.from('keep-this-object');
  adapter.objects.set(existingPath, original);

  const first = await adapter.createIfAbsent(existingPath, Buffer.from('replacement'));
  const second = await adapter.createIfAbsent(existingPath, Buffer.from('replacement'));

  assert.equal(first, false);
  assert.equal(second, false);
  assert.deepEqual(adapter.objects.get(existingPath), original);
  assert.equal((await save(fixture, adapter)).status, 'conflict');
  assert.deepEqual(adapter.objects.get(existingPath), original);
  assert.equal(completionPaths(adapter).length, 0);
});

test('a repeated save conflicts without changing the existing backup', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter();
  const first = await save(fixture, adapter);
  const before = new Map([...adapter.objects].map(([path, bytes]) => [
    path,
    Buffer.from(bytes),
  ]));

  const second = await save(fixture, adapter);

  assert.equal(first.saved, true);
  assert.equal(second.saved, false);
  assert.equal(second.status, 'conflict');
  assert.equal(second.reason, 'object_conflict');
  assert.deepEqual([...adapter.objects], [...before]);
  assertNoSensitiveData(second);
});

test('rejects a backup content hash mismatch before the first write', async () => {
  const fixture = createFixture({
    backup: { content: 'changed synthetic body' },
  });
  const adapter = createMemoryAdapter();
  fixture.backup.content = 'unmanifested synthetic body';

  const result = await save(fixture, adapter);

  assert.deepEqual(result, {
    saved: false,
    status: 'not_saved',
    reason: 'backup_hash_mismatch',
  });
  assert.equal(adapter.objects.size, 0);
  assertNoSensitiveData(result);
});

test('rejects an invalid Ed25519 signature before the first write', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter();

  const result = await save({ ...fixture, signature: `${fixture.signature}x` }, adapter);

  assert.equal(result.saved, false);
  assert.equal(result.reason, 'manifest_signature_invalid');
  assert.equal(adapter.objects.size, 0);
  assertNoSensitiveData(result);
});

test('rejects backup and manifest identity or version mismatches before writing', async t => {
  const cases = [
    ['id', { manifest: { id: '50000000-0000-4000-8000-000000000042' } }],
    ['owner_id', { manifest: { owner_id: '30000000-0000-4000-8000-000000000042' } }],
    ['backupVersion', { manifest: { backupVersion: 'other-synthetic-version' } }],
  ];

  for (const [field, overrides] of cases) {
    await t.test(field, async () => {
      const fixture = createFixture(overrides);
      const adapter = createMemoryAdapter();

      const result = await save(fixture, adapter);

      assert.equal(result.saved, false);
      assert.equal(result.reason, 'backup_manifest_mismatch');
      assert.equal(adapter.objects.size, 0);
      assertNoSensitiveData(result);
    });
  }
});

test('rejects an invalid backup UUID without creating an object', async () => {
  const fixture = createFixture();
  fixture.backup.id = '../synthetic-path';
  const adapter = createMemoryAdapter();

  const result = await save(fixture, adapter);

  assert.equal(result.reason, 'invalid_backup_or_manifest');
  assert.equal(adapter.objects.size, 0);
  assertNoSensitiveData(result);
});

test('encodes path-like backup versions into a single safe path segment', async () => {
  const pathLikeVersion = '../../synthetic/private\\version';
  const fixture = createFixture({
    backup: { backupVersion: pathLikeVersion },
  });
  const adapter = createMemoryAdapter();

  const result = await save(fixture, adapter);

  assert.equal(result.saved, true);
  const backupPath = pathsFor(adapter).find(path => path.endsWith('/backup.json'));
  const versionSegment = Buffer.from(pathLikeVersion, 'utf8').toString('base64url');
  assert.equal(backupPath.split('/').at(-2), versionSegment);
  assert.equal(backupPath.includes(pathLikeVersion), false);
  assert.equal(backupPath.split('/').some(segment => segment === '..'), false);
});

test('does not publish a completion marker when backup read-back is tampered', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter({
    onRead(path, bytes) {
      if (path.endsWith('/backup.json')) {
        bytes[0] ^= 1;
        return bytes;
      }
      return null;
    },
  });

  const result = await save(fixture, adapter);

  assert.equal(result.saved, false);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.reason, 'readback_mismatch');
  assert.equal(completionPaths(adapter).length, 0);
  assertNoSensitiveData(result);
});

test('does not publish a completion marker when manifest read-back is tampered', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter({
    onRead(path, bytes) {
      if (path.endsWith('/manifest.json')) {
        bytes[0] ^= 1;
        return bytes;
      }
      return null;
    },
  });

  const result = await save(fixture, adapter);

  assert.equal(result.saved, false);
  assert.equal(result.reason, 'readback_mismatch');
  assert.equal(completionPaths(adapter).length, 0);
  assertNoSensitiveData(result);
});

test('does not publish a completion marker when signature read-back is tampered', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter({
    onRead(path, bytes) {
      if (path.endsWith('/signature.txt')) {
        bytes[0] ^= 1;
        return bytes;
      }
      return null;
    },
  });

  const result = await save(fixture, adapter);

  assert.equal(result.saved, false);
  assert.equal(result.reason, 'readback_mismatch');
  assert.equal(completionPaths(adapter).length, 0);
  assertNoSensitiveData(result);
});

test('a middle object upload failure leaves only an incomplete orphan', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter({
    onCreate(_path, _bytes, createCount) {
      if (createCount === 2) throw new Error(tokenMarker);
      return null;
    },
  });

  const result = await save(fixture, adapter);

  assert.equal(result.saved, false);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.reason, 'storage_write_failed');
  assert.equal(adapter.objects.size, 1);
  assert.equal(completionPaths(adapter).length, 0);
  assertNoSensitiveData(result);
});

test('read exceptions and missing objects fail closed without completion', async t => {
  for (const [name, onRead] of [
    ['read exception', () => 'throw'],
    ['missing read result', () => 'missing'],
  ]) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const adapter = createMemoryAdapter({ onRead });

      const result = await save(fixture, adapter);

      assert.equal(result.saved, false);
      assert.equal(result.status, 'incomplete');
      assert.equal(result.reason, 'readback_failed');
      assert.equal(completionPaths(adapter).length, 0);
      assertNoSensitiveData(result);
    });
  }
});

test('invalid adapter read values fail closed without completion', async () => {
  const fixture = createFixture();
  const adapter = createMemoryAdapter({
    onRead() {
      return 'invalid';
    },
  });

  const result = await save(fixture, adapter);

  assert.equal(result.reason, 'readback_failed');
  assert.equal(completionPaths(adapter).length, 0);
  assertNoSensitiveData(result);
});

test('adapter write response errors are not treated as successful writes', async t => {
  for (const [name, action, expectedStatus, expectedReason] of [
    ['false result', 'false', 'conflict', 'object_conflict'],
    ['invalid result', 'invalid', 'incomplete', 'storage_adapter_invalid_result'],
    ['write exception', 'throw', 'incomplete', 'storage_write_failed'],
  ]) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const adapter = createMemoryAdapter({
        onCreate() {
          return action;
        },
      });

      const result = await save(fixture, adapter);

      assert.equal(result.saved, false);
      assert.equal(result.status, expectedStatus);
      assert.equal(result.reason, expectedReason);
      assert.equal(adapter.objects.size, 0);
      assertNoSensitiveData(result);
    });
  }
});

test('completion marker conflicts and uncertain writes are never reported complete', async t => {
  for (const [name, action, expectedStatus, expectedReason] of [
    ['conflict', 'false', 'conflict', 'completion_conflict'],
    ['invalid response', 'invalid', 'unconfirmed', 'storage_adapter_invalid_result'],
    ['write throws before creation', 'throw', 'unconfirmed', 'completion_write_unconfirmed'],
    ['write stores then throws', 'store_then_throw', 'unconfirmed', 'completion_write_unconfirmed'],
  ]) {
    await t.test(name, async () => {
      let writes = 0;
      const fixture = createFixture();
      const adapter = createMemoryAdapter({
        onCreate(_path, _bytes, createCount) {
          writes += 1;
          if (createCount === 4) return action;
          return null;
        },
      });

      const result = await save(fixture, adapter);

      assert.equal(writes, 4);
      assert.equal(result.saved, false);
      assert.equal(result.status, expectedStatus);
      assert.equal(result.reason, expectedReason);
      assertNoSensitiveData(result);
    });
  }
});

test('completion marker read-back failures are explicitly unconfirmed', async t => {
  for (const [name, onRead, expectedReason] of [
    ['missing marker', path => path.startsWith(completionPrefix) ? 'missing' : null,
      'completion_readback_unconfirmed'],
    ['read exception', path => path.startsWith(completionPrefix) ? 'throw' : null,
      'completion_readback_unconfirmed'],
    ['altered marker', (path, bytes) => {
      if (!path.startsWith(completionPrefix)) return null;
      bytes[0] ^= 1;
      return bytes;
    }, 'completion_readback_mismatch'],
  ]) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const adapter = createMemoryAdapter({ onRead });

      const result = await save(fixture, adapter);

      assert.equal(result.saved, false);
      assert.equal(result.status, 'unconfirmed');
      assert.equal(result.reason, expectedReason);
      assert.equal(completionPaths(adapter).length, 1);
      assertNoSensitiveData(result);
    });
  }
});

test('success and failure values do not expose note or key material', async () => {
  const fixture = createFixture();
  const success = await save(fixture, createMemoryAdapter());
  const failure = await save(
    { ...fixture, signature: 'invalid' },
    createMemoryAdapter(),
  );

  assertNoSensitiveData(success);
  assertNoSensitiveData(failure);
  assert.deepEqual(Object.keys(success).sort(), ['backupRef', 'saved', 'status']);
  assert.deepEqual(Object.keys(failure).sort(), ['reason', 'saved', 'status']);
  assert.equal(fixture.privateKeyMarker, privateKeyMarker);
  assert.equal(fixture.tokenMarker, tokenMarker);
});
