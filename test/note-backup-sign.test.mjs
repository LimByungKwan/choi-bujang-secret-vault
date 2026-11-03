import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  sign as signBytes,
} from 'node:crypto';
import { test } from 'node:test';
import { createNoteBackupManifest } from '../src/note-backup-manifest.mjs';
import { signNoteBackupManifest } from '../src/note-backup-sign.mjs';
import {
  hashNoteContent,
  planSignedNoteRestore,
  verifyRestoreManifestSignature,
} from '../src/note-restore-core.mjs';

const userId = '30000000-0000-4000-8000-000000000031';
const noteId = '50000000-0000-4000-8000-000000000031';
const backupVersion = 'synthetic-signing-backup-v1';
const keyId = 'synthetic-ed25519-key';
const title = '가상 서명 테스트 제목';
const content = 'synthetic signing test body';
const ed25519Keys = generateKeyPairSync('ed25519');
const otherEd25519Keys = generateKeyPairSync('ed25519');
const rsaKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });

function createManifest(overrides = {}) {
  return {
    backupVersion,
    id: noteId,
    owner_id: userId,
    contentSha256: hashNoteContent(content),
    noteHashVersion: 1,
    noteSha256: 'a'.repeat(64),
    keyId,
    ...overrides,
  };
}

function trustedKey(publicKey = ed25519Keys.publicKey, id = keyId) {
  return [{
    keyId: id,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  }];
}

function verify(manifest, signature, publicKey = ed25519Keys.publicKey) {
  return verifyRestoreManifestSignature({
    manifest,
    signature,
    trustedPublicKeys: trustedKey(publicKey, manifest.keyId),
  });
}

test('signer returns canonical unpadded base64url for a synthetic Ed25519 key', () => {
  const manifest = createManifest();
  const signature = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });

  assert.match(signature, /^[A-Za-z0-9_-]{86}$/u);
  assert.equal(signature.includes('='), false);
  assert.equal(verify(manifest, signature).verified, true);
});

test('same manifest and Ed25519 KeyObject produce a deterministic signature', () => {
  const manifest = createManifest();

  assert.equal(
    signNoteBackupManifest({ manifest, privateKey: ed25519Keys.privateKey }),
    signNoteBackupManifest({ manifest, privateKey: ed25519Keys.privateKey }),
  );
});

test('PKCS#8 PEM for the same Ed25519 key signs successfully in memory', () => {
  const manifest = createManifest();
  const privateKeyPem = ed25519Keys.privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  });
  const signature = signNoteBackupManifest({ manifest, privateKey: privateKeyPem });

  assert.equal(verify(manifest, signature).verified, true);
});

test('another Ed25519 public key cannot verify the generated signature', () => {
  const manifest = createManifest();
  const signature = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });

  assert.deepEqual(verify(manifest, signature, otherEd25519Keys.publicKey), {
    verified: false,
    reason: 'signature_mismatch',
  });
});

test('changing any signed manifest field invalidates the signature', () => {
  const original = createManifest();
  const signature = signNoteBackupManifest({
    manifest: original,
    privateKey: ed25519Keys.privateKey,
  });
  const changes = [
    ['id', '50000000-0000-4000-8000-000000000032'],
    ['owner_id', '30000000-0000-4000-8000-000000000032'],
    ['backupVersion', 'synthetic-signing-backup-v2'],
    ['contentSha256', 'b'.repeat(64)],
    ['noteHashVersion', 2],
    ['noteSha256', 'c'.repeat(64)],
    ['keyId', 'synthetic-ed25519-key-2'],
  ];

  for (const [field, value] of changes) {
    const changed = { ...original, [field]: value };
    assert.equal(
      verify(changed, signature).verified,
      false,
      `${field} mutation must not verify`,
    );
  }
});

test('RSA private keys are rejected', () => {
  assert.throws(
    () => signNoteBackupManifest({
      manifest: createManifest(),
      privateKey: rsaKeys.privateKey,
    }),
    error => error instanceof TypeError && error.message === 'invalid_private_key',
  );
});

test('public KeyObjects are rejected as signing keys', () => {
  assert.throws(
    () => signNoteBackupManifest({
      manifest: createManifest(),
      privateKey: ed25519Keys.publicKey,
    }),
    error => error instanceof TypeError && error.message === 'invalid_private_key',
  );
});

test('missing private key is rejected', () => {
  assert.throws(
    () => signNoteBackupManifest({ manifest: createManifest() }),
    error => error instanceof TypeError && error.message === 'invalid_private_key',
  );
});

test('malformed private-key material is rejected without echoing the input', () => {
  const invalidKey = 'synthetic-private-key-marker';

  assert.throws(
    () => signNoteBackupManifest({
      manifest: createManifest(),
      privateKey: invalidKey,
    }),
    error => {
      assert.equal(error instanceof TypeError, true);
      assert.equal(error.message, 'invalid_private_key');
      assert.equal(error.message.includes(invalidKey), false);
      return true;
    },
  );
});

test('missing required manifest fields are rejected', () => {
  for (const field of [
    'backupVersion',
    'id',
    'owner_id',
    'contentSha256',
    'noteHashVersion',
    'noteSha256',
    'keyId',
  ]) {
    const manifest = createManifest();
    delete manifest[field];
    assert.throws(
      () => signNoteBackupManifest({
        manifest,
        privateKey: ed25519Keys.privateKey,
      }),
      error => error instanceof TypeError && error.message === 'invalid_manifest',
      `${field} must be required`,
    );
  }
});

test('invalid UUID, hash, version, and keyId manifest values are rejected', () => {
  const cases = [
    ['id', 'not-a-uuid'],
    ['owner_id', 'not-a-uuid'],
    ['contentSha256', 'not-a-sha256'],
    ['noteSha256', 'not-a-sha256'],
    ['noteHashVersion', 99],
    ['backupVersion', ''],
    ['backupVersion', 'v'.repeat(101)],
    ['keyId', 'invalid key id'],
  ];

  for (const [field, value] of cases) {
    assert.throws(
      () => signNoteBackupManifest({
        manifest: createManifest({ [field]: value }),
        privateKey: ed25519Keys.privateKey,
      }),
      error => error instanceof TypeError && error.message === 'invalid_manifest',
      `${field} must be rejected`,
    );
  }
});

test('signing errors do not reveal note content or private-key material', () => {
  const privateMarker = 'synthetic-private-key-marker';
  let thrown;
  try {
    signNoteBackupManifest({
      manifest: createManifest({
        title,
        content,
        noteSha256: 'invalid hash marker',
      }),
      privateKey: privateMarker,
    });
  } catch (error) {
    thrown = error;
  }

  assert.equal(thrown instanceof TypeError, true);
  assert.equal(thrown.message.includes(title), false);
  assert.equal(thrown.message.includes(content), false);
  assert.equal(thrown.message.includes(privateMarker), false);
});

test('signature result excludes private key and original note text', () => {
  const manifest = createManifest({
    title,
    content,
  });
  const signature = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });
  const privateKeyPem = ed25519Keys.privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  });

  assert.equal(signature.includes(title), false);
  assert.equal(signature.includes(content), false);
  assert.equal(signature.includes(privateKeyPem), false);
  assert.equal(signature.includes('BEGIN PRIVATE KEY'), false);
});

test('manifest generator output signs and verifies with the existing verifier', () => {
  const backup = {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
  };
  const manifest = createNoteBackupManifest({
    ...backup,
    keyId,
  });
  const signature = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });

  assert.deepEqual(verify(manifest, signature), {
    verified: true,
    reason: 'verified',
  });
});

test('generated signature and manifest yield a signed restore plan for a deleted note', () => {
  const backup = {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
  };
  const manifest = createNoteBackupManifest({
    ...backup,
    keyId,
  });
  const signature = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });
  const result = planSignedNoteRestore({
    authenticatedUserId: userId,
    backup,
    manifest,
    signature,
    trustedPublicKeys: trustedKey(),
  });

  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'missing_note_insert_candidate');
  assert.equal(result.targetId, noteId);
  assert.equal(result.plan.operation, 'insert_if_absent');
  assert.equal(result.integrity.manifestSignatureVerified, true);
  assert.equal(result.integrity.fullNoteSha256Verified, true);
});

test('signer and verifier agree on payload encoding with multibyte backup versions', () => {
  const manifest = createManifest({ backupVersion: '가상-백업-v1' });
  const signature = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });

  assert.deepEqual(verify(manifest, signature), {
    verified: true,
    reason: 'verified',
  });
});

test('signer payload field framing matches the verifier schema and order', () => {
  const manifest = createManifest({ backupVersion: '가상-v1' });
  const fields = [
    'aleph.note-restore.manifest-signature/v1',
    manifest.backupVersion,
    manifest.id,
    manifest.owner_id,
    manifest.contentSha256,
    '1',
    manifest.noteSha256,
    manifest.keyId,
  ];
  const expectedPayload = Buffer.concat(fields.flatMap(value => {
    const bytes = Buffer.from(value, 'utf8');
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(bytes.length);
    return [prefix, bytes];
  }));
  const independentlySigned = signBytes(
    null,
    expectedPayload,
    ed25519Keys.privateKey,
  ).toString('base64url');
  const signerOutput = signNoteBackupManifest({
    manifest,
    privateKey: ed25519Keys.privateKey,
  });

  assert.equal(signerOutput, independentlySigned);
  assert.equal(verify(manifest, signerOutput).verified, true);
});
