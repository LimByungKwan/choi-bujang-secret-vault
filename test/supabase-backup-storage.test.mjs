import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { createNoteBackupManifest } from '../src/note-backup-manifest.mjs';
import { readCompleteBackup } from '../src/note-backup-read.mjs';
import { signNoteBackupManifest } from '../src/note-backup-sign.mjs';
import { saveVerifiedNoteBackup } from '../src/note-backup-store.mjs';
import { createSupabaseBackupStorageAdapter } from '../src/supabase-backup-storage.mjs';

const bucketName = 'private-test-backups';
const otherBucketName = 'alternate-test-bucket';
const userId = '30000000-0000-4000-8000-000000000061';
const noteId = '50000000-0000-4000-8000-000000000061';
const backupVersion = 'synthetic-supabase-adapter-v1';
const keyId = 'synthetic-supabase-key';
const title = 'synthetic adapter private title marker';
const content = 'synthetic adapter private content marker';
const tokenMarker = 'synthetic-adapter-token-marker';
const serviceKeyMarker = 'synthetic-service-key-marker';
const privateKeyMarker = 'synthetic-private-key-marker';
const validObjectPath = `note-backups/v1/${userId}/${noteId}/c3VudGhldGlj/backup.json`;
const validCompletionPath = `note-backups/v1/completed/nb1_${'a'.repeat(64)}.json`;

function expectedBackupPaths(backup) {
  const versionSegment = Buffer.from(backup.backupVersion, 'utf8')
    .toString('base64url');
  const root = `note-backups/v1/${backup.owner_id}/${backup.id}/${versionSegment}`;
  const backupRef = `nb1_${createHash('sha256')
    .update(Buffer.from(root, 'utf8'))
    .digest('hex')}`;
  return {
    backup: `${root}/backup.json`,
    manifest: `${root}/manifest.json`,
    signature: `${root}/signature.txt`,
    completion: `note-backups/v1/completed/${backupRef}.json`,
  };
}

function createFakeClient(options = {}) {
  const objects = new Map();
  const calls = [];
  const buckets = [];
  const client = {
    storage: {
      from(name) {
        buckets.push(name);
        return {
          async upload(path, bytes, uploadOptions) {
            calls.push({
              method: 'upload',
              bucket: name,
              path,
              bytes: Buffer.from(bytes),
              options: { ...uploadOptions },
            });
            if (options.upload) {
              return options.upload({ name, path, bytes: Buffer.from(bytes), objects });
            }
            if (objects.has(path)) {
              return {
                data: null,
                error: { status: 409, statusCode: '409' },
              };
            }
            objects.set(path, Buffer.from(bytes));
            return {
              data: { id: 'synthetic-object-id', path, fullPath: `${name}/${path}` },
              error: null,
            };
          },
          async download(path) {
            calls.push({ method: 'download', bucket: name, path });
            if (options.download) {
              return options.download({ name, path, objects });
            }
            if (!objects.has(path)) {
              return {
                data: null,
                error: { status: 404, statusCode: '404' },
              };
            }
            return {
              data: new Blob([objects.get(path)]),
              error: null,
            };
          },
        };
      },
    },
  };
  return { client, calls, buckets, objects };
}

function adapterFor(fake = createFakeClient(), name = bucketName) {
  return {
    ...fake,
    adapter: createSupabaseBackupStorageAdapter({
      supabaseClient: fake.client,
      bucketName: name,
    }),
  };
}

function createBackupFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const backup = {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
  };
  const manifest = createNoteBackupManifest({ ...backup, keyId });
  const signature = signNoteBackupManifest({ manifest, privateKey });
  return {
    backup,
    manifest,
    signature,
    trustedPublicKeys: [{
      keyId,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    }],
  };
}

function assertSanitizedFailure(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const marker of [
    title,
    content,
    tokenMarker,
    serviceKeyMarker,
    privateKeyMarker,
    bucketName,
  ]) {
    assert.equal(text.includes(marker), false);
  }
}

test('factory creation and module use are lazy until adapter methods are called', () => {
  const fake = createFakeClient();
  const adapter = createSupabaseBackupStorageAdapter({
    supabaseClient: fake.client,
    bucketName,
  });

  assert.equal(fake.buckets.length, 0);
  assert.equal(fake.calls.length, 0);
  assert.equal(typeof adapter.createIfAbsent, 'function');
  assert.equal(typeof adapter.read, 'function');
});

test('uploads bytes to the explicit bucket with upsert disabled', async () => {
  const fake = createFakeClient();
  const { adapter } = adapterFor(fake);
  const bytes = Buffer.from('synthetic payload bytes');

  const result = await adapter.createIfAbsent(validObjectPath, bytes);

  assert.equal(result, true);
  assert.deepEqual(fake.buckets, [bucketName]);
  assert.equal(fake.calls.length, 1);
  assert.equal(fake.calls[0].method, 'upload');
  assert.equal(fake.calls[0].bucket, bucketName);
  assert.equal(fake.calls[0].path, validObjectPath);
  assert.deepEqual(fake.calls[0].bytes, bytes);
  assert.deepEqual(fake.calls[0].options, {
    upsert: false,
    contentType: 'application/octet-stream',
  });
  assert.deepEqual(fake.objects.get(validObjectPath), bytes);
});

test('returns false for SDK collision response variants', async t => {
  const collisionCases = [
    ['HTTP 409', { status: 409 }],
    ['string HTTP status', { statusCode: '409' }],
    ['Duplicate code', { code: 'Duplicate' }],
    ['ResourceAlreadyExists code', { code: 'ResourceAlreadyExists' }],
    ['Duplicate statusCode', { statusCode: 'Duplicate' }],
    ['ResourceAlreadyExists statusCode', { statusCode: 'ResourceAlreadyExists' }],
  ];

  for (const [name, error] of collisionCases) {
    await t.test(name, async () => {
      const fake = createFakeClient({
        upload: () => ({ data: null, error }),
      });
      const { adapter } = adapterFor(fake);

      const result = await adapter.createIfAbsent(validObjectPath, Buffer.from('bytes'));

      assert.equal(result, false);
      assert.equal(fake.calls.length, 1);
    });
  }
});

test('returns false for SDK-thrown duplicate conflicts', async t => {
  for (const [name, error] of [
    ['Duplicate', Object.assign(new Error(tokenMarker), { code: 'Duplicate' })],
    [
      'ResourceAlreadyExists',
      Object.assign(new Error(tokenMarker), { code: 'ResourceAlreadyExists' }),
    ],
    ['HTTP 409', Object.assign(new Error(tokenMarker), { status: 409 })],
  ]) {
    await t.test(name, async () => {
      const fake = createFakeClient({
        upload: () => { throw error; },
      });
      const { adapter } = adapterFor(fake);

      const result = await adapter.createIfAbsent(validObjectPath, Buffer.from('bytes'));

      assert.equal(result, false);
      assertSanitizedFailure(result);
    });
  }
});

test('does not classify authorization and server errors as collisions', async t => {
  for (const status of [401, 403, 500]) {
    await t.test(String(status), async () => {
      const fake = createFakeClient({
        upload: () => ({
          data: null,
          error: {
            status,
            statusCode: String(status),
            message: tokenMarker,
            serviceKey: serviceKeyMarker,
          },
        }),
      });
      const { adapter } = adapterFor(fake);

      await assert.rejects(
        adapter.createIfAbsent(validObjectPath, Buffer.from('bytes')),
        error => {
          assert.equal(error.message, 'storage_write_failed');
          assertSanitizedFailure(error.message);
          return true;
        },
      );
    });
  }
});

test('SDK write exceptions are reduced to a sanitized failure', async () => {
  const fake = createFakeClient({
    upload: () => {
      throw new Error(`${tokenMarker} ${serviceKeyMarker}`);
    },
  });
  const { adapter } = adapterFor(fake);

  await assert.rejects(
    adapter.createIfAbsent(validObjectPath, Buffer.from('bytes')),
    error => {
      assert.equal(error.message, 'storage_write_failed');
      assertSanitizedFailure(error.message);
      return true;
    },
  );
});

test('downloads a Blob and preserves its bytes in a Buffer', async () => {
  const expected = Buffer.from([0, 1, 2, 127, 128, 254, 255]);
  const fake = createFakeClient({
    download: () => ({ data: new Blob([expected]), error: null }),
  });
  const { adapter } = adapterFor(fake);

  const result = await adapter.read(validCompletionPath);

  assert.equal(Buffer.isBuffer(result), true);
  assert.deepEqual(result, expected);
  assert.deepEqual(fake.buckets, [bucketName]);
  assert.deepEqual(fake.calls, [{
    method: 'download',
    bucket: bucketName,
    path: validCompletionPath,
  }]);
});

test('downloads Uint8Array data as a copied Buffer', async () => {
  const expected = Uint8Array.from([9, 8, 7, 0, 255]);
  const fake = createFakeClient({
    download: () => ({ data: expected, error: null }),
  });
  const { adapter } = adapterFor(fake);

  const result = await adapter.read(validObjectPath);

  assert.equal(Buffer.isBuffer(result), true);
  assert.deepEqual(result, Buffer.from(expected));
  assert.notEqual(result.buffer, expected.buffer);
});

test('download errors, missing data and invalid response types fail safely', async t => {
  const cases = [
    ['SDK error response', () => ({
      data: null,
      error: { status: 500, message: tokenMarker },
    })],
    ['missing data', () => ({ error: null })],
    ['null data', () => ({ data: null, error: null })],
    ['string data', () => ({ data: tokenMarker, error: null })],
    ['object data', () => ({ data: { value: tokenMarker }, error: null })],
    ['missing response', () => null],
  ];

  for (const [name, response] of cases) {
    await t.test(name, async () => {
      const fake = createFakeClient({ download: response });
      const { adapter } = adapterFor(fake);

      await assert.rejects(adapter.read(validObjectPath), error => {
        assert.equal(error.message, 'storage_read_failed');
        assertSanitizedFailure(error.message);
        return true;
      });
    });
  }
});

test('SDK download exceptions do not leak the original error', async () => {
  const fake = createFakeClient({
    download: () => {
      throw new Error(`${tokenMarker} ${serviceKeyMarker}`);
    },
  });
  const { adapter } = adapterFor(fake);

  await assert.rejects(adapter.read(validObjectPath), error => {
    assert.equal(error.message, 'storage_read_failed');
    assertSanitizedFailure(error.message);
    return true;
  });
});

test('accepts only fixed backup object and completion marker paths', async t => {
  for (const path of [validObjectPath, validCompletionPath]) {
    await t.test(path.endsWith('.json') ? 'backup object' : 'completion marker', async () => {
      const fake = createFakeClient();
      const { adapter } = adapterFor(fake);

      const result = await adapter.createIfAbsent(path, Buffer.from('payload'));

      assert.equal(result, true);
      assert.equal(fake.calls[0].path, path);
    });
  }
});

test('rejects traversal, malformed and out-of-prefix paths before SDK access', async t => {
  const invalidPaths = [
    '../note-backups/v1/path',
    `/${validObjectPath}`,
    validObjectPath.replaceAll('/', '\\'),
    validObjectPath.replace('note-backups/v1', 'other-prefix'),
    `note-backups/v1/${userId}/not-a-uuid/c3VudGhldGlj/backup.json`,
    `note-backups/v1/${userId}/${noteId}/../backup.json`,
    `note-backups/v1/${userId}/${noteId}/bad+/backup.json`,
    'note-backups/v1/completed/anything.json',
    `${validObjectPath}/extra`,
  ];

  for (const path of invalidPaths) {
    await t.test('reject invalid path', async () => {
      const fake = createFakeClient();
      const { adapter } = adapterFor(fake);

      await assert.rejects(
        adapter.createIfAbsent(path, Buffer.from('bytes')),
        { message: 'invalid_storage_path' },
      );
      await assert.rejects(
        adapter.read(path),
        { message: 'invalid_storage_path' },
      );
      assert.equal(fake.buckets.length, 0);
      assert.equal(fake.calls.length, 0);
    });
  }
});

test('rejects invalid client and bucket inputs at factory creation', async t => {
  const fake = createFakeClient();
  const cases = [
    ['missing client', { supabaseClient: null, bucketName }],
    ['missing storage API', { supabaseClient: {}, bucketName }],
    ['missing from method', { supabaseClient: { storage: {} }, bucketName }],
    ['empty bucket', { supabaseClient: fake.client, bucketName: '' }],
    ['bucket path separator', { supabaseClient: fake.client, bucketName: '../private' }],
    ['bucket backslash', { supabaseClient: fake.client, bucketName: 'private\\bucket' }],
    ['bucket whitespace', { supabaseClient: fake.client, bucketName: ' private' }],
    ['oversized bucket', { supabaseClient: fake.client, bucketName: 'x'.repeat(101) }],
  ];

  for (const [name, input] of cases) {
    await t.test(name, async () => {
      assert.throws(
        () => createSupabaseBackupStorageAdapter(input),
        error => {
          assert.match(error.message, /^invalid_(?:supabase_client|private_bucket_name)$/u);
          assertSanitizedFailure(error.message);
          return true;
        },
      );
    });
  }
});

test('rejects invalid bytes before accessing the SDK', async () => {
  const fake = createFakeClient();
  const { adapter } = adapterFor(fake);

  await assert.rejects(
    adapter.createIfAbsent(validObjectPath, 'not bytes'),
    { message: 'invalid_storage_bytes' },
  );
  assert.equal(fake.buckets.length, 0);
  assert.equal(fake.calls.length, 0);
});

test('does not expose public URL, deletion or overwrite methods', () => {
  const { adapter } = adapterFor();

  assert.deepEqual(Object.keys(adapter).sort(), ['createIfAbsent', 'read']);
  assert.equal(adapter.getPublicUrl, undefined);
  assert.equal(adapter.createSignedUrl, undefined);
  assert.equal(adapter.remove, undefined);
  assert.equal(adapter.delete, undefined);
  assert.equal(adapter.upload, undefined);
});

test('connects Store and Reader through the fake Supabase client adapter', async () => {
  const fixture = createBackupFixture();
  const fake = createFakeClient();
  const { adapter } = adapterFor(fake);

  const saved = await saveVerifiedNoteBackup({
    ...fixture,
    storageAdapter: adapter,
  });
  assert.equal(saved.saved, true);
  assert.equal(saved.status, 'complete');
  const paths = expectedBackupPaths(fixture.backup);
  const storeUploads = fake.calls.filter(call => call.method === 'upload');
  const storeDownloads = fake.calls.filter(call => call.method === 'download');
  assert.deepEqual(storeUploads.map(call => call.path), [
    paths.backup,
    paths.manifest,
    paths.signature,
    paths.completion,
  ]);
  assert.deepEqual(storeDownloads.map(call => call.path), [
    paths.backup,
    paths.manifest,
    paths.signature,
    paths.completion,
  ]);
  assert.ok(storeUploads.every(call => call.options.upsert === false));

  const readerStart = fake.calls.length;
  const restored = await readCompleteBackup({
    targetId: noteId,
    ownerId: userId,
    backupVersion,
    trustedPublicKeys: fixture.trustedPublicKeys,
    storageAdapter: adapter,
  });

  assert.equal(restored.read, true);
  assert.equal(restored.status, 'complete');
  assert.deepEqual(restored.backup, fixture.backup);
  assert.deepEqual(restored.manifest, fixture.manifest);
  assert.equal(restored.signature, fixture.signature);
  assert.equal(fake.calls.filter(call => call.method === 'upload').length, 4);
  const readerCalls = fake.calls.slice(readerStart);
  assert.deepEqual(readerCalls.map(call => call.path), [
    paths.completion,
    paths.backup,
    paths.manifest,
    paths.signature,
  ]);
  assert.equal(fake.calls.filter(call => call.method === 'download').length, 8);
  assert.ok(fake.calls.every(call => call.bucket === bucketName));
  assertSanitizedFailure({
    saved,
    restored: {
      read: restored.read,
      status: restored.status,
      backupRef: restored.backupRef,
    },
  });
});
