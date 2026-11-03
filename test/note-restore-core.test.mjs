import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signBytes } from 'node:crypto';
import { test } from 'node:test';
import {
  hashFullNote,
  hashNoteContent,
  planNoteRestore,
  planSignedNoteRestore,
  serializeNoteForHash,
  verifyRestoreManifestSignature,
} from '../src/note-restore-core.mjs';

const userA = '30000000-0000-4000-8000-000000000001';
const userB = '30000000-0000-4000-8000-000000000002';
const noteB = '50000000-0000-4000-8000-000000000001';
const backupVersion = 'fixture-backup-v1';
const backupTitle = '합성 백업 제목';
const backupContent = 'synthetic backup content';
const changedContent = 'synthetic changed content';

function createBackup() {
  return {
    backup: {
      id: noteB,
      owner_id: userB,
      title: backupTitle,
      content: backupContent,
      backupVersion,
    },
    manifest: {
      id: noteB,
      owner_id: userB,
      backupVersion,
      contentSha256: hashNoteContent(backupContent),
    },
  };
}

function createCurrentNote(overrides = {}) {
  return {
    id: noteB,
    owner_id: userB,
    title: backupTitle,
    content: backupContent,
    ...overrides,
  };
}

test('deleted B note yields a same-ID insert_if_absent plan after backup verification', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
  });

  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'missing_note_insert_candidate');
  assert.equal(result.targetId, noteB);
  assert.deepEqual(result.plan, {
    operation: 'insert_if_absent',
    targetId: noteB,
    ownerBoundToAuthenticatedUser: true,
    replacementContentSha256: hashNoteContent(backupContent),
    backupVersion,
  });
  assert.deepEqual(result.integrity, {
    contentSha256Verified: true,
    sha256Scope: 'content UTF-8 bytes only',
    otherFieldsProtectedByContentSha256: false,
  });
});

test('B note identical to the backup yields a no_change plan', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    currentNote: createCurrentNote(),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'already_matches_backup');
  assert.deepEqual(result.plan, {
    operation: 'no_change',
    targetId: noteB,
    currentContentSha256: hashNoteContent(backupContent),
    backupVersion,
  });
});

test('changed B note with matching approved current-content hash yields a conditional plan', () => {
  const { backup, manifest } = createBackup();
  const currentNote = createCurrentNote({ content: changedContent });
  const currentHash = hashNoteContent(changedContent);
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    currentNote,
    approvedCurrentContentSha256: currentHash,
  });

  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'approved_current_content_replace_candidate');
  assert.equal(result.targetId, noteB);
  assert.deepEqual(result.plan, {
    operation: 'replace_if_content_hash_matches',
    targetId: noteB,
    expectedCurrentContentSha256: currentHash,
    replacementContentSha256: hashNoteContent(backupContent),
    ownerBoundToAuthenticatedUser: true,
    backupVersion,
  });
});

test('changed B note without approved current-content hash is rejected', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    currentNote: createCurrentNote({ content: changedContent }),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'current_content_approval_required');
  assert.equal(result.plan, null);
});

test('changed B note with a mismatched approved current-content hash is rejected', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    currentNote: createCurrentNote({ content: changedContent }),
    approvedCurrentContentSha256: hashNoteContent('different synthetic content'),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'current_content_approval_mismatch');
  assert.equal(result.plan, null);
});

test('authenticated user differing from backup owner is rejected', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userA,
    backup,
    manifest,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'authenticated_user_backup_owner_mismatch');
  assert.equal(result.targetId, noteB);
  assert.equal(result.plan, null);
});

test('current note owned by another user is rejected even with a matching ID', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    currentNote: createCurrentNote({ owner_id: userA, content: changedContent }),
    approvedCurrentContentSha256: hashNoteContent(changedContent),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'current_note_owner_mismatch');
  assert.equal(result.plan, null);
});

test('backup content differing from manifest SHA-256 is rejected', () => {
  const { backup, manifest } = createBackup();
  backup.content = changedContent;
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'backup_content_hash_mismatch');
  assert.equal(result.plan, null);
});

test('backup ID differing from manifest ID is rejected', () => {
  const { backup, manifest } = createBackup();
  manifest.id = '50000000-0000-4000-8000-000000000002';
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'backup_manifest_identity_mismatch');
  assert.equal(result.plan, null);
});

test('malformed backup UUID and invalid backup version are rejected', () => {
  const malformedId = createBackup();
  malformedId.backup.id = 'not-a-uuid';
  assert.equal(
    planNoteRestore({
      authenticatedUserId: userB,
      ...malformedId,
    }).reason,
    'invalid_backup_identity',
  );

  const invalidVersion = createBackup();
  invalidVersion.backup.backupVersion = '';
  assert.equal(
    planNoteRestore({
      authenticatedUserId: userB,
      ...invalidVersion,
    }).reason,
    'invalid_backup_fields',
  );
});

test('content-only SHA-256 does not authenticate a changed title', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    currentNote: createCurrentNote({ title: '다른 합성 제목' }),
  });

  assert.equal(manifest.contentSha256, hashNoteContent(backup.content));
  assert.equal(result.integrity.contentSha256Verified, true);
  assert.equal(result.integrity.otherFieldsProtectedByContentSha256, false);
  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'current_title_conflict');
  assert.equal(result.plan, null);
});

test('results do not expose backup content, title, tokens, or secret-like values', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
  });
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes(backup.content), false);
  assert.equal(serialized.includes(backup.title), false);
  assert.equal(serialized.includes('Authorization'), false);
  assert.equal(serialized.includes('Bearer'), false);
  assert.equal(serialized.includes('secret'), false);
});

function createFullNote(overrides = {}) {
  return {
    id: noteB,
    owner_id: userB,
    title: backupTitle,
    content: backupContent,
    backupVersion,
    ...overrides,
  };
}

function createCurrentManifest(backup, overrides = {}) {
  return {
    id: backup.id,
    owner_id: backup.owner_id,
    backupVersion: backup.backupVersion,
    contentSha256: hashNoteContent(backup.content),
    noteHashVersion: 1,
    noteSha256: hashFullNote(backup),
    ...overrides,
  };
}

function planLatestBackup(backup, manifest = createCurrentManifest(backup)) {
  return planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
  });
}

test('full-note hash is deterministic for the same synthetic input', () => {
  const backup = createFullNote();

  assert.equal(hashFullNote(backup), hashFullNote({ ...backup }));
});

test('full-note hash changes when the title changes', () => {
  assert.notEqual(
    hashFullNote(createFullNote()),
    hashFullNote(createFullNote({ title: '변경된 합성 제목' })),
  );
});

test('full-note hash changes when the content changes', () => {
  assert.notEqual(
    hashFullNote(createFullNote()),
    hashFullNote(createFullNote({ content: 'changed synthetic content' })),
  );
});

test('full-note hash changes when the note ID changes', () => {
  assert.notEqual(
    hashFullNote(createFullNote()),
    hashFullNote({ ...createFullNote(), id: '50000000-0000-4000-8000-000000000002' }),
  );
});

test('full-note hash changes when the owner ID changes', () => {
  assert.notEqual(
    hashFullNote(createFullNote()),
    hashFullNote({ ...createFullNote(), owner_id: userA }),
  );
});

test('full-note hash changes when the backup version changes', () => {
  assert.notEqual(
    hashFullNote(createFullNote()),
    hashFullNote(createFullNote({ backupVersion: 'fixture-backup-v2' })),
  );
});

test('length prefixes distinguish different title/content field boundaries', () => {
  const first = createFullNote({ title: 'ab', content: 'c' });
  const second = createFullNote({ title: 'a', content: 'bc' });

  assert.equal(first.title + first.content, second.title + second.content);
  assert.notDeepEqual(serializeNoteForHash(first), serializeNoteForHash(second));
});

test('serialization preserves Korean and emoji as their exact UTF-8 bytes', () => {
  const note = createFullNote({
    title: '한글 제목 🛡️',
    content: '합성 본문 😀',
  });
  const fields = [
    'aleph.note-restore.full-note',
    '1',
    note.backupVersion,
    note.id,
    note.owner_id,
    note.title,
    note.content,
  ].map(value => Buffer.from(value, 'utf8'));
  const expected = Buffer.concat(fields.flatMap(field => {
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(field.length);
    return [prefix, field];
  }));

  assert.deepEqual(serializeNoteForHash(note), expected);
  assert.equal(hashFullNote(note).length, 64);
});

test('a valid latest manifest verifies the full-note SHA-256', () => {
  const backup = createFullNote();
  const result = planLatestBackup(backup);

  assert.equal(result.canRestore, true);
  assert.equal(result.integrity.fullNoteSha256Verified, true);
});

test('a latest manifest missing noteSha256 is rejected', () => {
  const backup = createFullNote();
  const manifest = createCurrentManifest(backup);
  delete manifest.noteSha256;
  const result = planLatestBackup(backup, manifest);

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'invalid_manifest_fields');
  assert.equal(result.integrity.fullNoteSha256Verified, undefined);
});

test('a mismatched latest-manifest noteSha256 is rejected', () => {
  const backup = createFullNote();
  const result = planLatestBackup(backup, createCurrentManifest(backup, {
    noteSha256: '0'.repeat(64),
  }));

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'backup_note_hash_mismatch');
  assert.equal(result.integrity.fullNoteSha256Verified, false);
});

test('an unsupported latest-manifest noteHashVersion is rejected', () => {
  const backup = createFullNote();
  const result = planLatestBackup(backup, createCurrentManifest(backup, {
    noteHashVersion: 2,
  }));

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'unsupported_note_hash_version');
});

test('a noteSha256 without noteHashVersion cannot fall back to legacy validation', () => {
  const backup = createFullNote();
  const manifest = createCurrentManifest(backup);
  delete manifest.noteHashVersion;
  const result = planLatestBackup(backup, manifest);

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'unsupported_note_hash_version');
});

test('a changed backup title is rejected by the latest full-note hash', () => {
  const original = createFullNote();
  const backup = createFullNote({ title: '변조된 합성 제목' });
  const result = planLatestBackup(backup, createCurrentManifest(original));

  assert.equal(hashNoteContent(backup.content), hashNoteContent(original.content));
  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'backup_note_hash_mismatch');
  assert.equal(result.integrity.fullNoteSha256Verified, false);
});

test('latest manifest identity mutations are rejected', () => {
  const backup = createFullNote();
  const cases = [
    ['ID', { id: '50000000-0000-4000-8000-000000000002' }],
    ['owner ID', { owner_id: userA }],
    ['backup version', { backupVersion: 'fixture-backup-v2' }],
  ];

  for (const [fieldName, overrides] of cases) {
    const result = planLatestBackup(
      backup,
      createCurrentManifest(backup, overrides),
    );
    assert.equal(result.canRestore, false, `${fieldName} mutation must be rejected`);
    assert.equal(
      result.reason,
      'backup_manifest_identity_mismatch',
      `${fieldName} mutation must fail identity matching`,
    );
  }
});

test('full-note serialization rejects unpaired UTF-16 surrogates', () => {
  const invalidTitle = 'synthetic \ud800 marker';

  assert.throws(
    () => serializeNoteForHash(createFullNote({ title: invalidTitle })),
    error => {
      assert.equal(error instanceof TypeError, true);
      assert.equal(error.message.includes(invalidTitle), false);
      return true;
    },
  );
});

test('full-note serialization rejects title values exceeding the byte limit', () => {
  assert.throws(
    () => serializeNoteForHash(createFullNote({ title: 'a'.repeat(64 * 1024 + 1) })),
    error => error instanceof RangeError && error.message === 'note_title_too_large',
  );
});

test('valid full-note hash with mismatched content hash is rejected but marked verified', () => {
  const backup = createFullNote();
  const result = planLatestBackup(backup, createCurrentManifest(backup, {
    contentSha256: hashNoteContent('different synthetic content'),
  }));

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'backup_content_hash_mismatch');
  assert.equal(result.plan, null);
  assert.equal(result.integrity.fullNoteSha256Verified, true);
});

test('mismatched full-note hash is rejected and marked unverified', () => {
  const backup = createFullNote();
  const result = planLatestBackup(backup, createCurrentManifest(backup, {
    noteSha256: '0'.repeat(64),
  }));

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'backup_note_hash_mismatch');
  assert.equal(result.integrity.fullNoteSha256Verified, false);
});

test('legacy manifest results omit fullNoteSha256Verified', () => {
  const { backup, manifest } = createBackup();
  const result = planNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
  });

  assert.equal(result.canRestore, true);
  assert.equal(Object.hasOwn(result.integrity, 'fullNoteSha256Verified'), false);
});

test('latest-manifest rejection results do not expose synthetic note or secret-like values', () => {
  const backup = createFullNote({
    title: 'private synthetic title marker',
    content: 'private synthetic content marker',
  });
  const result = planLatestBackup(backup, createCurrentManifest(backup, {
    noteSha256: '0'.repeat(64),
  }));
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes(backup.title), false);
  assert.equal(serialized.includes(backup.content), false);
  assert.equal(serialized.includes('Authorization'), false);
  assert.equal(serialized.includes('Bearer'), false);
});

const signatureKeyOne = generateKeyPairSync('ed25519');
const signatureKeyTwo = generateKeyPairSync('ed25519');
const nonEd25519Key = generateKeyPairSync('rsa', { modulusLength: 2048 });

function createSignatureManifest(overrides = {}) {
  return {
    backupVersion: 'synthetic-signature-backup-v1',
    id: '50000000-0000-4000-8000-000000000003',
    owner_id: '30000000-0000-4000-8000-000000000003',
    contentSha256: '1'.repeat(64),
    noteHashVersion: 1,
    noteSha256: '2'.repeat(64),
    keyId: 'synthetic-ed25519-key-1',
    ...overrides,
  };
}

function encodeManifestSignaturePayload(manifest) {
  const values = [
    'aleph.note-restore.manifest-signature/v1',
    manifest.backupVersion,
    manifest.id,
    manifest.owner_id,
    manifest.contentSha256,
    String(manifest.noteHashVersion),
    manifest.noteSha256,
    manifest.keyId,
  ];
  return Buffer.concat(values.flatMap(value => {
    const bytes = Buffer.from(value, 'utf8');
    const lengthPrefix = Buffer.alloc(4);
    lengthPrefix.writeUInt32BE(bytes.length);
    return [lengthPrefix, bytes];
  }));
}

function signManifest(manifest, privateKey = signatureKeyOne.privateKey) {
  return signBytes(null, encodeManifestSignaturePayload(manifest), privateKey)
    .toString('base64url');
}

const trustedSignatureKeys = [
  {
    keyId: 'synthetic-ed25519-key-1',
    publicKeyPem: signatureKeyOne.publicKey.export({
      type: 'spki',
      format: 'pem',
    }),
  },
  {
    keyId: 'synthetic-ed25519-key-2',
    publicKeyPem: signatureKeyTwo.publicKey.export({
      type: 'spki',
      format: 'pem',
    }),
  },
];

function verifyManifest(
  manifest,
  signature = signManifest(manifest),
  trustedPublicKeys = trustedSignatureKeys,
) {
  return verifyRestoreManifestSignature({
    manifest,
    signature,
    trustedPublicKeys,
  });
}

function verifyTamperedManifest(field, value) {
  const manifest = createSignatureManifest();
  const signature = signManifest(manifest);
  manifest[field] = value;
  return verifyManifest(manifest, signature);
}

test('manifest signature payload uses the specified version, field order, and UTF-8 byte lengths', () => {
  const manifest = createSignatureManifest({
    backupVersion: '합성-v1',
    keyId: 'synthetic-ed25519-key-1',
  });
  const payload = encodeManifestSignaturePayload(manifest);
  const expectedValues = [
    'aleph.note-restore.manifest-signature/v1',
    manifest.backupVersion,
    manifest.id,
    manifest.owner_id,
    manifest.contentSha256,
    '1',
    manifest.noteSha256,
    manifest.keyId,
  ];
  let offset = 0;

  for (const expectedValue of expectedValues) {
    const expectedBytes = Buffer.from(expectedValue, 'utf8');
    const actualLength = payload.readUInt32BE(offset);
    offset += 4;
    assert.equal(actualLength, expectedBytes.length);
    assert.deepEqual(
      payload.subarray(offset, offset + actualLength),
      expectedBytes,
    );
    offset += actualLength;
  }
  assert.equal(offset, payload.length);
});

test('valid synthetic Ed25519 signature and trusted public key are verified', () => {
  const manifest = createSignatureManifest();

  assert.deepEqual(verifyManifest(manifest), {
    verified: true,
    reason: 'verified',
  });
});

test('changing signed backupVersion is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('backupVersion', 'synthetic-signature-backup-v2'),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('changing signed note ID is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('id', '50000000-0000-4000-8000-000000000004'),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('changing signed owner ID is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('owner_id', '30000000-0000-4000-8000-000000000004'),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('changing signed contentSha256 is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('contentSha256', '3'.repeat(64)),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('changing signed noteHashVersion to an unsupported version is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('noteHashVersion', 2),
    { verified: false, reason: 'invalid_manifest' },
  );
});

test('changing signed noteSha256 is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('noteSha256', '4'.repeat(64)),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('changing signed keyId to another trusted key is rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('keyId', 'synthetic-ed25519-key-2'),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('a modified canonical base64url signature is rejected', () => {
  const manifest = createSignatureManifest();
  const signature = signManifest(manifest);
  const modifiedSignature = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;

  assert.deepEqual(
    verifyManifest(manifest, modifiedSignature),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('a missing signature is rejected', () => {
  assert.deepEqual(
    verifyRestoreManifestSignature({
      manifest: createSignatureManifest(),
      trustedPublicKeys: trustedSignatureKeys,
    }),
    { verified: false, reason: 'invalid_signature' },
  );
});

test('a malformed base64url signature is rejected', () => {
  assert.deepEqual(
    verifyManifest(createSignatureManifest(), 'not*base64url'),
    { verified: false, reason: 'invalid_signature' },
  );
});

test('a signature encoding with the wrong byte length is rejected', () => {
  assert.deepEqual(
    verifyManifest(
      createSignatureManifest(),
      Buffer.alloc(63, 7).toString('base64url'),
    ),
    { verified: false, reason: 'invalid_signature' },
  );
});

test('a manifest keyId absent from the trusted list is rejected', () => {
  const manifest = createSignatureManifest({ keyId: 'unknown-synthetic-key' });

  assert.deepEqual(
    verifyManifest(manifest),
    { verified: false, reason: 'unknown_key_id' },
  );
});

test('duplicate trusted key IDs are rejected', () => {
  const manifest = createSignatureManifest();
  const duplicateKeys = [
    ...trustedSignatureKeys,
    { ...trustedSignatureKeys[0] },
  ];

  assert.deepEqual(
    verifyManifest(manifest, signManifest(manifest), duplicateKeys),
    { verified: false, reason: 'invalid_trusted_keys' },
  );
});

test('a trusted public key that is not Ed25519 is rejected', () => {
  const manifest = createSignatureManifest();
  const rsaKey = {
    keyId: manifest.keyId,
    publicKeyPem: nonEd25519Key.publicKey.export({
      type: 'spki',
      format: 'pem',
    }),
  };

  assert.deepEqual(
    verifyManifest(manifest, signManifest(manifest), [rsaKey]),
    { verified: false, reason: 'invalid_public_key' },
  );
});

test('a malformed trusted public-key PEM is rejected', () => {
  const manifest = createSignatureManifest();
  const malformedKey = {
    keyId: manifest.keyId,
    publicKeyPem: '-----BEGIN PUBLIC KEY-----invalid-----END PUBLIC KEY-----',
  };

  assert.deepEqual(
    verifyManifest(manifest, signManifest(manifest), [malformedKey]),
    { verified: false, reason: 'invalid_public_key' },
  );
});

test('a different valid Ed25519 key cannot verify the original signature', () => {
  const manifest = createSignatureManifest();
  const otherKey = [{
    keyId: manifest.keyId,
    publicKeyPem: signatureKeyTwo.publicKey.export({
      type: 'spki',
      format: 'pem',
    }),
  }];

  assert.deepEqual(
    verifyManifest(manifest, signManifest(manifest), otherKey),
    { verified: false, reason: 'signature_mismatch' },
  );
});

test('unsupported signature manifest versions are rejected', () => {
  assert.deepEqual(
    verifyTamperedManifest('noteHashVersion', 99),
    { verified: false, reason: 'invalid_manifest' },
  );
});

test('signature manifest fields with invalid types are rejected', () => {
  const invalidCases = [
    ['backupVersion', 1],
    ['id', null],
    ['owner_id', {}],
    ['contentSha256', 123],
    ['noteHashVersion', '1'],
    ['noteSha256', null],
    ['keyId', 1],
  ];

  for (const [field, value] of invalidCases) {
    const manifest = createSignatureManifest({ [field]: value });
    const result = verifyRestoreManifestSignature({
      manifest,
      signature: 'A'.repeat(86),
      trustedPublicKeys: trustedSignatureKeys,
    });
    assert.deepEqual(
      result,
      { verified: false, reason: 'invalid_manifest' },
      `${field} with an invalid type must be rejected`,
    );
  }
});

test('signature verification results do not expose manifest extras, key material, or token-like values', () => {
  const manifest = createSignatureManifest({
    title: 'synthetic private title marker',
    content: 'synthetic private note marker',
    token: 'synthetic-token-marker',
  });
  const privateKeyPem = signatureKeyOne.privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  });
  const result = verifyManifest(manifest);
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes(manifest.title), false);
  assert.equal(serialized.includes(manifest.content), false);
  assert.equal(serialized.includes(manifest.token), false);
  assert.equal(serialized.includes(privateKeyPem), false);
  assert.equal(serialized.includes('BEGIN PRIVATE KEY'), false);
  assert.equal(serialized.includes('Bearer'), false);
});

function createSignedRestoreFixture({
  backupOverrides = {},
  manifestOverrides = {},
} = {}) {
  const backup = createFullNote(backupOverrides);
  const manifest = createSignatureManifest({
    backupVersion: backup.backupVersion,
    id: backup.id,
    owner_id: backup.owner_id,
    contentSha256: hashNoteContent(backup.content),
    noteHashVersion: 1,
    noteSha256: hashFullNote(backup),
    ...manifestOverrides,
  });
  return {
    backup,
    manifest,
    signature: signManifest(manifest),
  };
}

function planSignedFixture({
  authenticatedUserId = userB,
  currentNote = null,
  approvedCurrentContentSha256 = null,
  trustedPublicKeys = trustedSignatureKeys,
  ...fixtureOptions
} = {}) {
  const fixture = createSignedRestoreFixture(fixtureOptions);
  const result = planSignedNoteRestore({
    authenticatedUserId,
    ...fixture,
    trustedPublicKeys,
    currentNote,
    approvedCurrentContentSha256,
  });
  return { ...fixture, result };
}

function assertRestoreResultShape(result) {
  assert.deepEqual(
    Object.keys(result).sort(),
    ['canRestore', 'integrity', 'plan', 'reason', 'targetId'].sort(),
  );
  assert.equal(typeof result.canRestore, 'boolean');
  assert.equal(typeof result.reason, 'string');
  assert.equal(result.plan === null || typeof result.plan === 'object', true);
  assert.equal(typeof result.integrity, 'object');
  assert.equal(typeof result.integrity.manifestSignatureVerified, 'boolean');
}

test('signed restore creates insert_if_absent only after signature and backup verification', () => {
  const { backup, result } = planSignedFixture();

  assertRestoreResultShape(result);
  assert.equal(verifyManifest(createSignedRestoreFixture().manifest).verified, true);
  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'missing_note_insert_candidate');
  assert.equal(result.targetId, backup.id);
  assert.deepEqual(result.plan, {
    operation: 'insert_if_absent',
    targetId: backup.id,
    ownerBoundToAuthenticatedUser: true,
    replacementContentSha256: hashNoteContent(backup.content),
    replacementNoteSha256: hashFullNote(backup),
    backupVersion: backup.backupVersion,
  });
  assert.equal(result.integrity.manifestSignatureVerified, true);
  assert.equal(result.integrity.fullNoteSha256Verified, true);
});

test('signed restore reports no_change for an identical current note', () => {
  const { result } = planSignedFixture({
    currentNote: createCurrentNote(),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'already_matches_backup');
  assert.equal(result.plan.operation, 'no_change');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('signed restore permits a changed current note only with its matching approved hash', () => {
  const currentNote = createCurrentNote({ content: changedContent });
  const { result } = planSignedFixture({
    currentNote,
    approvedCurrentContentSha256: hashNoteContent(changedContent),
  });

  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'approved_current_content_replace_candidate');
  assert.equal(result.plan.operation, 'replace_if_content_hash_matches');
  assert.equal(
    result.plan.expectedCurrentContentSha256,
    hashNoteContent(changedContent),
  );
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('signed restore permits an approved changed title and content using the full current-note hash', () => {
  const fixture = createSignedRestoreFixture();
  const currentNote = {
    ...fixture.backup,
    title: 'explicitly approved synthetic title',
    content: 'explicitly approved synthetic content',
  };
  const approvedCurrentNoteSha256 = hashFullNote(currentNote);
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
    currentNote,
    approvedCurrentNoteSha256,
  });

  assert.equal(result.canRestore, true);
  assert.equal(result.reason, 'approved_current_note_replace_candidate');
  assert.equal(result.plan.operation, 'replace_if_note_hash_matches');
  assert.equal(result.plan.expectedCurrentNoteSha256, approvedCurrentNoteSha256);
  assert.equal(result.plan.replacementNoteSha256, fixture.manifest.noteSha256);
});

test('signed restore rejects a stale full current-note approval hash', () => {
  const fixture = createSignedRestoreFixture();
  const currentNote = {
    ...fixture.backup,
    title: 'current synthetic title',
    content: 'current synthetic content',
  };
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
    currentNote,
    approvedCurrentNoteSha256: hashFullNote({
      ...currentNote,
      content: 'a different synthetic state',
    }),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.reason, 'current_note_approval_mismatch');
  assert.equal(result.plan, null);
});

test('signed restore rejects a missing signature before planning', () => {
  const fixture = createSignedRestoreFixture();
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    backup: fixture.backup,
    manifest: fixture.manifest,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'manifest_signature_invalid');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('signed restore rejects a modified signature before planning', () => {
  const fixture = createSignedRestoreFixture();
  const modifiedSignature = `${fixture.signature[0] === 'A' ? 'B' : 'A'}${fixture.signature.slice(1)}`;
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    signature: modifiedSignature,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'manifest_signature_invalid');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('signed restore rejects an invalid trusted public key before planning', () => {
  const fixture = createSignedRestoreFixture();
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: [{
      keyId: fixture.manifest.keyId,
      publicKeyPem: 'malformed synthetic public key',
    }],
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'manifest_signature_invalid');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('signed restore rejects an unregistered keyId before planning', () => {
  const fixture = createSignedRestoreFixture({
    manifestOverrides: { keyId: 'unregistered-synthetic-key' },
  });
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'manifest_signature_invalid');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('signed restore rejects legacy manifests without signature fallback', () => {
  const { backup, manifest } = createBackup();
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    backup,
    manifest,
    signature: 'A'.repeat(86),
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'signed_manifest_required');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('signed restore rejects latest manifests missing noteSha256', () => {
  const fixture = createSignedRestoreFixture();
  delete fixture.manifest.noteSha256;
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'signed_manifest_required');
  assert.equal(result.integrity.manifestSignatureVerified, false);
});

test('signed restore rejects an authenticated user different from the backup owner', () => {
  const fixture = createSignedRestoreFixture();
  const signatureResult = verifyManifest(fixture.manifest, fixture.signature);
  const result = planSignedNoteRestore({
    authenticatedUserId: userA,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(signatureResult.verified, true);
  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'authenticated_user_backup_owner_mismatch');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('valid signature cannot authorize a backup with a changed title', () => {
  const fixture = createSignedRestoreFixture();
  const signatureResult = verifyManifest(fixture.manifest, fixture.signature);
  fixture.backup.title = 'tampered synthetic title';
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(signatureResult.verified, true);
  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'backup_note_hash_mismatch');
  assert.equal(result.integrity.manifestSignatureVerified, true);
  assert.equal(result.integrity.fullNoteSha256Verified, false);
});

test('valid signature cannot authorize backup content changed after signing', () => {
  const fixture = createSignedRestoreFixture();
  const signatureResult = verifyManifest(fixture.manifest, fixture.signature);
  fixture.backup.content = 'tampered synthetic content';
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
  });

  assert.equal(signatureResult.verified, true);
  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'backup_note_hash_mismatch');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('valid signature does not allow restoring over a current note owned by another user', () => {
  const fixture = createSignedRestoreFixture();
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    trustedPublicKeys: trustedSignatureKeys,
    currentNote: createCurrentNote({
      owner_id: userA,
      content: changedContent,
    }),
    approvedCurrentContentSha256: hashNoteContent(changedContent),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'current_note_owner_mismatch');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('valid signature does not bypass missing approval for changed current content', () => {
  const { result } = planSignedFixture({
    currentNote: createCurrentNote({ content: changedContent }),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'current_content_approval_required');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('valid signature does not bypass an invalid approval hash for changed current content', () => {
  const { result } = planSignedFixture({
    currentNote: createCurrentNote({ content: changedContent }),
    approvedCurrentContentSha256: 'not-a-sha256',
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'current_content_approval_required');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('valid signature does not bypass a mismatched approval hash', () => {
  const { result } = planSignedFixture({
    currentNote: createCurrentNote({ content: changedContent }),
    approvedCurrentContentSha256: hashNoteContent('other synthetic content'),
  });

  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.reason, 'current_content_approval_mismatch');
  assert.equal(result.integrity.manifestSignatureVerified, true);
});

test('signed restore failures do not expose note data, tokens, or key material', () => {
  const fixture = createSignedRestoreFixture({
    backupOverrides: {
      title: 'private synthetic title marker',
      content: 'private synthetic content marker',
    },
  });
  const result = planSignedNoteRestore({
    authenticatedUserId: userB,
    ...fixture,
    signature: 'invalid-signature',
    trustedPublicKeys: trustedSignatureKeys,
  });
  const serialized = JSON.stringify(result);
  const privateKeyPem = signatureKeyOne.privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  });

  assertRestoreResultShape(result);
  assert.equal(result.canRestore, false);
  assert.equal(result.plan, null);
  assert.equal(result.integrity.manifestSignatureVerified, false);
  assert.equal(serialized.includes(fixture.backup.title), false);
  assert.equal(serialized.includes(fixture.backup.content), false);
  assert.equal(serialized.includes(privateKeyPem), false);
  assert.equal(serialized.includes('BEGIN PRIVATE KEY'), false);
  assert.equal(serialized.includes('Bearer'), false);
});
