import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  sign as signBytes,
} from 'node:crypto';
import { test } from 'node:test';
import { createNoteBackupManifest } from '../src/note-backup-manifest.mjs';
import {
  hashFullNote,
  hashNoteContent,
  planNoteRestore,
  planSignedNoteRestore,
  verifyRestoreManifestSignature,
} from '../src/note-restore-core.mjs';

const userId = '30000000-0000-4000-8000-000000000021';
const noteId = '50000000-0000-4000-8000-000000000021';
const backupVersion = 'synthetic-backup-v1';
const keyId = 'synthetic-manifest-key';
const title = '합성 백업 제목 🛡️';
const content = 'synthetic note body 😀';

function createInput(overrides = {}) {
  return {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
    keyId,
    ...overrides,
  };
}

function signableManifestFields(manifest) {
  return [
    'aleph.note-restore.manifest-signature/v1',
    manifest.backupVersion,
    manifest.id,
    manifest.owner_id,
    manifest.contentSha256,
    String(manifest.noteHashVersion),
    manifest.noteSha256,
    manifest.keyId,
  ];
}

function encodeSignaturePayload(manifest) {
  const chunks = [];
  for (const value of signableManifestFields(manifest)) {
    const bytes = Buffer.from(value, 'utf8');
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(bytes.length);
    chunks.push(prefix, bytes);
  }
  return Buffer.concat(chunks);
}

function createEphemeralSignature(manifest) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const signature = signBytes(null, encodeSignaturePayload(manifest), privateKey)
    .toString('base64url');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    signature,
    trustedPublicKeys: [{ keyId: manifest.keyId, publicKeyPem }],
  };
}

test('creates the exact current manifest fields from a synthetic note', () => {
  const manifest = createNoteBackupManifest(createInput());

  assert.deepEqual(Object.keys(manifest).sort(), [
    'backupVersion',
    'contentSha256',
    'id',
    'keyId',
    'noteHashVersion',
    'noteSha256',
    'owner_id',
  ].sort());
  assert.equal(manifest.id, noteId);
  assert.equal(manifest.owner_id, userId);
  assert.equal(manifest.backupVersion, backupVersion);
  assert.equal(manifest.keyId, keyId);
  assert.equal(manifest.noteHashVersion, 1);
});

test('manifest content and full-note hashes match the restore core helpers', () => {
  const input = createInput();
  const manifest = createNoteBackupManifest(input);

  assert.equal(manifest.contentSha256, hashNoteContent(input.content));
  assert.equal(manifest.noteSha256, hashFullNote(input));
});

test('same synthetic input deterministically creates the same manifest', () => {
  const input = createInput();

  assert.deepEqual(
    createNoteBackupManifest(input),
    createNoteBackupManifest({ ...input }),
  );
});

test('changing title changes the full-note hash', () => {
  const original = createNoteBackupManifest(createInput());
  const changed = createNoteBackupManifest(createInput({ title: '변경된 합성 제목' }));

  assert.notEqual(changed.noteSha256, original.noteSha256);
});

test('changing content changes the full-note hash', () => {
  const original = createNoteBackupManifest(createInput());
  const changed = createNoteBackupManifest(createInput({ content: 'changed synthetic body' }));

  assert.notEqual(changed.noteSha256, original.noteSha256);
});

test('changing note ID changes the full-note hash', () => {
  const original = createNoteBackupManifest(createInput());
  const changed = createNoteBackupManifest(createInput({
    id: '50000000-0000-4000-8000-000000000022',
  }));

  assert.notEqual(changed.noteSha256, original.noteSha256);
});

test('changing owner ID changes the full-note hash', () => {
  const original = createNoteBackupManifest(createInput());
  const changed = createNoteBackupManifest(createInput({
    owner_id: '30000000-0000-4000-8000-000000000022',
  }));

  assert.notEqual(changed.noteSha256, original.noteSha256);
});

test('changing backup version changes the full-note hash', () => {
  const original = createNoteBackupManifest(createInput());
  const changed = createNoteBackupManifest(createInput({
    backupVersion: 'synthetic-backup-v2',
  }));

  assert.notEqual(changed.noteSha256, original.noteSha256);
});

test('changing keyId changes only the keyId manifest field', () => {
  const original = createNoteBackupManifest(createInput());
  const changed = createNoteBackupManifest(createInput({
    keyId: 'synthetic-manifest-key-2',
  }));

  assert.equal(changed.keyId, 'synthetic-manifest-key-2');
  assert.equal(changed.noteSha256, original.noteSha256);
  assert.deepEqual(
    { ...changed, keyId: original.keyId },
    original,
  );
});

test('malformed note and owner UUIDs are rejected without echoing input', () => {
  for (const [field, badValue] of [
    ['id', 'synthetic-id-secret-like'],
    ['owner_id', 'synthetic-owner-secret-like'],
  ]) {
    assert.throws(
      () => createNoteBackupManifest(createInput({ [field]: badValue })),
      error => {
        assert.equal(error instanceof TypeError, true);
        assert.equal(error.message.includes(badValue), false);
        return true;
      },
    );
  }
});

test('missing required fields and non-record input are rejected', () => {
  for (const field of [
    'id',
    'owner_id',
    'title',
    'content',
    'backupVersion',
    'keyId',
  ]) {
    const input = createInput();
    delete input[field];
    assert.throws(
      () => createNoteBackupManifest(input),
      error => error instanceof TypeError && error.message === `missing_${field}`,
      `${field} must be required`,
    );
  }
  assert.throws(
    () => createNoteBackupManifest(null),
    error => error instanceof TypeError && error.message === 'invalid_note_backup',
  );
});

test('invalid field types and unsupported backup-version lengths are rejected', () => {
  const cases = [
    ['title', 42],
    ['content', null],
    ['backupVersion', ''],
    ['backupVersion', 'v'.repeat(101)],
    ['keyId', 'invalid key id'],
  ];

  for (const [field, value] of cases) {
    assert.throws(
      () => createNoteBackupManifest(createInput({ [field]: value })),
      TypeError,
      `${field} with invalid input must be rejected`,
    );
  }
});

test('unpaired UTF-16 surrogates in title and content are rejected safely', () => {
  for (const field of ['title', 'content']) {
    const marker = `synthetic-\ud800-${field}`;
    assert.throws(
      () => createNoteBackupManifest(createInput({ [field]: marker })),
      error => {
        assert.equal(error instanceof TypeError, true);
        assert.equal(error.message.includes(marker), false);
        return true;
      },
    );
  }
});

test('title and content values exceeding their hash limits are rejected', () => {
  assert.throws(
    () => createNoteBackupManifest(createInput({ title: 't'.repeat(64 * 1024 + 1) })),
    RangeError,
  );
  assert.throws(
    () => createNoteBackupManifest(createInput({ content: 'c'.repeat(16 * 1024 * 1024 + 1) })),
    RangeError,
  );
});

test('manifest contains neither title nor note content', () => {
  const manifest = createNoteBackupManifest(createInput());
  const serialized = JSON.stringify(manifest);

  assert.equal(Object.hasOwn(manifest, 'title'), false);
  assert.equal(Object.hasOwn(manifest, 'content'), false);
  assert.equal(serialized.includes(title), false);
  assert.equal(serialized.includes(content), false);
});

test('validation errors do not reveal note text or secret-like values', () => {
  const privateTitle = 'private synthetic title marker';
  const privateContent = 'private synthetic body marker';
  const input = createInput({
    title: privateTitle,
    content: privateContent,
    keyId: 'invalid key token-marker',
  });
  let thrown;

  try {
    createNoteBackupManifest(input);
  } catch (error) {
    thrown = error;
  }

  assert.equal(thrown instanceof TypeError, true);
  assert.equal(thrown.message.includes(privateTitle), false);
  assert.equal(thrown.message.includes(privateContent), false);
  assert.equal(thrown.message.includes('token-marker'), false);
});

test('generated latest manifest passes planNoteRestore hash validation', () => {
  const input = createInput();
  const manifest = createNoteBackupManifest(input);
  const result = planNoteRestore({
    authenticatedUserId: userId,
    backup: input,
    manifest,
  });

  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'missing_note_insert_candidate');
  assert.equal(result.targetId, noteId);
  assert.equal(result.integrity.fullNoteSha256Verified, true);
});

test('unsigned generated manifest is rejected by signed restore planning', () => {
  const input = createInput();
  const manifest = createNoteBackupManifest(input);
  const result = planSignedNoteRestore({
    authenticatedUserId: userId,
    backup: input,
    manifest,
    trustedPublicKeys: [],
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'manifest_signature_invalid');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('generated manifest fields are compatible with Ed25519 signature verification', () => {
  const input = createInput();
  const manifest = createNoteBackupManifest(input);
  const { signature, trustedPublicKeys } = createEphemeralSignature(manifest);

  assert.deepEqual(
    verifyRestoreManifestSignature({ manifest, signature, trustedPublicKeys }),
    { verified: true, reason: 'verified' },
  );
});
