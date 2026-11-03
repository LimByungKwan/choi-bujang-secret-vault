import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_BACKUP_VERSION_LENGTH = 100;
const MAX_TITLE_BYTES = 64 * 1024;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const NOTE_HASH_DOMAIN = 'aleph.note-restore.full-note';
const NOTE_HASH_SCHEMA_VERSION = '1';
const NOTE_HASH_VERSION = 1;
const MANIFEST_SIGNATURE_SCHEMA_VERSION = 'aleph.note-restore.manifest-signature/v1';
const MANIFEST_SIGNATURE_VERSION = 1;
const MANIFEST_KEY_ID = /^[A-Za-z0-9._-]{1,64}$/u;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const MAX_PUBLIC_KEY_PEM_BYTES = 16 * 1024;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hashText(value) {
  return createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex');
}

function validUtf16(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function utf8Field(value, name, maxBytes) {
  if (typeof value !== 'string' || !validUtf16(value)) {
    throw new TypeError(`invalid_${name}`);
  }
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > maxBytes || bytes.length > 0xffffffff) {
    throw new RangeError(`${name}_too_large`);
  }
  return bytes;
}

function noteHashFields(note) {
  if (!isRecord(note)) throw new TypeError('invalid_note');
  for (const field of ['id', 'owner_id', 'title', 'content', 'backupVersion']) {
    if (!Object.hasOwn(note, field)) throw new TypeError(`missing_${field}`);
  }
  if (typeof note.id !== 'string' || !UUID.test(note.id)) {
    throw new TypeError('invalid_note_id');
  }
  if (typeof note.owner_id !== 'string' || !UUID.test(note.owner_id)) {
    throw new TypeError('invalid_note_owner_id');
  }
  if (typeof note.backupVersion !== 'string'
      || !validBackupVersion(note.backupVersion)) {
    throw new TypeError('invalid_backup_version');
  }

  // Required string fields are id/owner_id (existing UUID format),
  // backupVersion (1..100 characters and at most 100 UTF-8 bytes), title
  // (at most 64 KiB), and content (at most 16 MiB). Unpaired UTF-16
  // surrogates are rejected; text is not normalized. Order is fixed and
  // each UTF-8 field has a 4-byte unsigned big-endian byte-length prefix.
  // created_at is excluded; adding it requires a new hash schema and scope.
  return [
    utf8Field(NOTE_HASH_DOMAIN, 'hash_domain', 128),
    utf8Field(NOTE_HASH_SCHEMA_VERSION, 'hash_schema_version', 16),
    utf8Field(note.backupVersion, 'backup_version', MAX_BACKUP_VERSION_LENGTH),
    utf8Field(note.id, 'note_id', 36),
    utf8Field(note.owner_id, 'note_owner_id', 36),
    utf8Field(note.title, 'note_title', MAX_TITLE_BYTES),
    utf8Field(note.content, 'note_content', MAX_CONTENT_BYTES),
  ];
}

function serializeFields(fields) {
  const serialized = [];
  for (const field of fields) {
    const lengthPrefix = Buffer.allocUnsafe(4);
    lengthPrefix.writeUInt32BE(field.length);
    serialized.push(lengthPrefix, field);
  }
  return Buffer.concat(serialized);
}

function result({
  canRestore = false,
  reason,
  targetId = null,
  plan = null,
  contentSha256Verified = false,
  fullNoteSha256Verified,
}) {
  const integrity = {
    contentSha256Verified,
    sha256Scope: 'content UTF-8 bytes only',
    otherFieldsProtectedByContentSha256: false,
  };
  if (fullNoteSha256Verified !== undefined) {
    integrity.fullNoteSha256Verified = fullNoteSha256Verified;
  }
  return {
    canRestore,
    reason,
    targetId,
    plan,
    integrity,
  };
}

function validBackupVersion(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_BACKUP_VERSION_LENGTH;
}

/**
 * Hashes the UTF-8 bytes of a note's content field only.
 * The hash does not protect title or other row/manifest fields.
 */
export function hashNoteContent(content) {
  if (typeof content !== 'string') {
    throw new TypeError('note_content_must_be_string');
  }
  return hashText(content);
}

/**
 * Serializes a note deterministically. Fixed fields are domain, hash schema
 * version, backupVersion, id, owner_id, title, content; each is UTF-8 encoded
 * without normalization and prefixed by a 4-byte unsigned big-endian byte
 * length.
 */
export function serializeNoteForHash(note) {
  return serializeFields(noteHashFields(note));
}

/**
 * Hashes all supported note fields. Manifest signature verification is a
 * separate responsibility; this digest does not authenticate the manifest.
 */
export function hashFullNote(note) {
  return createHash('sha256').update(serializeNoteForHash(note)).digest('hex');
}

function manifestSignatureFields(manifest) {
  if (!isRecord(manifest)
      || typeof manifest.backupVersion !== 'string'
      || !validBackupVersion(manifest.backupVersion)
      || typeof manifest.id !== 'string'
      || !UUID.test(manifest.id)
      || typeof manifest.owner_id !== 'string'
      || !UUID.test(manifest.owner_id)
      || typeof manifest.contentSha256 !== 'string'
      || !SHA256.test(manifest.contentSha256)
      || manifest.noteHashVersion !== MANIFEST_SIGNATURE_VERSION
      || typeof manifest.noteSha256 !== 'string'
      || !SHA256.test(manifest.noteSha256)
      || typeof manifest.keyId !== 'string'
      || !MANIFEST_KEY_ID.test(manifest.keyId)) {
    return null;
  }

  try {
    return [
      utf8Field(
        MANIFEST_SIGNATURE_SCHEMA_VERSION,
        'signature_schema_version',
        128,
      ),
      utf8Field(manifest.backupVersion, 'backup_version', MAX_BACKUP_VERSION_LENGTH),
      utf8Field(manifest.id, 'note_id', 36),
      utf8Field(manifest.owner_id, 'note_owner_id', 36),
      utf8Field(manifest.contentSha256, 'content_sha256', 64),
      utf8Field(String(manifest.noteHashVersion), 'note_hash_version', 16),
      utf8Field(manifest.noteSha256, 'note_sha256', 64),
      utf8Field(manifest.keyId, 'key_id', 64),
    ];
  } catch {
    return null;
  }
}

/**
 * Verifies an Ed25519 signature over a versioned manifest payload.
 *
 * Input shape:
 *   { manifest, signature, trustedPublicKeys: [{ keyId, publicKeyPem }] }
 * signature is canonical, unpadded base64url encoding of exactly 64 bytes.
 * The payload uses 4-byte unsigned big-endian UTF-8 byte lengths in this
 * fixed order: versioned schema/domain identifier, backupVersion, id, owner_id,
 * contentSha256, noteHashVersion, noteSha256, keyId.
 *
 * Public keys must come from a separately trusted source. A valid signature
 * does not provide note confidentiality or guarantee atomic database writes.
 */
export function verifyRestoreManifestSignature({
  manifest,
  signature,
  trustedPublicKeys,
} = {}) {
  const fields = manifestSignatureFields(manifest);
  if (!fields) {
    return { verified: false, reason: 'invalid_manifest' };
  }

  if (typeof signature !== 'string' || !BASE64URL_SIGNATURE.test(signature)) {
    return { verified: false, reason: 'invalid_signature' };
  }
  const signatureBytes = Buffer.from(signature, 'base64url');
  if (signatureBytes.length !== 64
      || signatureBytes.toString('base64url') !== signature) {
    return { verified: false, reason: 'invalid_signature' };
  }

  if (!Array.isArray(trustedPublicKeys)) {
    return { verified: false, reason: 'invalid_trusted_keys' };
  }
  const seenKeyIds = new Set();
  for (const trustedKey of trustedPublicKeys) {
    if (!isRecord(trustedKey)
        || typeof trustedKey.keyId !== 'string'
        || !MANIFEST_KEY_ID.test(trustedKey.keyId)
        || typeof trustedKey.publicKeyPem !== 'string'
        || !validUtf16(trustedKey.publicKeyPem)
        || Buffer.byteLength(trustedKey.publicKeyPem, 'utf8') > MAX_PUBLIC_KEY_PEM_BYTES
        || seenKeyIds.has(trustedKey.keyId)) {
      return { verified: false, reason: 'invalid_trusted_keys' };
    }
    seenKeyIds.add(trustedKey.keyId);
  }

  const matchingKeys = trustedPublicKeys.filter(
    trustedKey => trustedKey.keyId === manifest.keyId,
  );
  if (matchingKeys.length !== 1) {
    return {
      verified: false,
      reason: matchingKeys.length === 0 ? 'unknown_key_id' : 'invalid_trusted_keys',
    };
  }

  const { publicKeyPem } = matchingKeys[0];
  if (!/^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----\s*$/u
    .test(publicKeyPem)) {
    return { verified: false, reason: 'invalid_public_key' };
  }

  let publicKey;
  try {
    publicKey = createPublicKey(publicKeyPem);
  } catch {
    return { verified: false, reason: 'invalid_public_key' };
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    return { verified: false, reason: 'invalid_public_key' };
  }

  const payload = serializeFields(fields);
  try {
    if (!verifySignature(null, payload, publicKey, signatureBytes)) {
      return { verified: false, reason: 'signature_mismatch' };
    }
  } catch {
    return { verified: false, reason: 'signature_verification_failed' };
  }

  return { verified: true, reason: 'verified' };
}

/**
 * Builds a database-free restore plan from a backup and an already verified
 * server-side identity. It never writes, logs, or returns note title/content.
 *
 * The legacy manifest (both noteHashVersion and noteSha256 absent) is accepted
 * only for existing local fixtures. Any operational restore API must require
 * the current hash version and noteSha256. Signature verification remains a
 * separate responsibility.
 * A caller must still execute the plan with an atomic database condition.
 * This comparison alone cannot prevent a concurrent update between checking
 * the current row and applying the plan.
 */
export function planNoteRestore({
  authenticatedUserId,
  backup,
  manifest,
  currentNote = null,
  approvedCurrentContentSha256 = null,
  approvedCurrentNoteSha256 = null,
} = {}) {
  if (typeof authenticatedUserId !== 'string' || !UUID.test(authenticatedUserId)) {
    return result({ reason: 'invalid_authenticated_user_id' });
  }
  if (!isRecord(backup) || !isRecord(manifest)) {
    return result({ reason: 'invalid_backup_or_manifest' });
  }

  const { id, owner_id: backupOwnerId, title, content, backupVersion } = backup;
  if (typeof id !== 'string' || !UUID.test(id)
      || typeof backupOwnerId !== 'string' || !UUID.test(backupOwnerId)) {
    return result({ reason: 'invalid_backup_identity' });
  }
  if (typeof title !== 'string' || typeof content !== 'string'
      || !validBackupVersion(backupVersion)) {
    return result({
      reason: 'invalid_backup_fields',
      targetId: id,
    });
  }

  if (typeof manifest.id !== 'string' || !UUID.test(manifest.id)
      || typeof manifest.owner_id !== 'string' || !UUID.test(manifest.owner_id)
      || !validBackupVersion(manifest.backupVersion)
      || typeof manifest.contentSha256 !== 'string'
      || !SHA256.test(manifest.contentSha256)) {
    return result({
      reason: 'invalid_manifest_fields',
      targetId: id,
    });
  }

  const hasNoteHashVersion = Object.hasOwn(manifest, 'noteHashVersion');
  const hasNoteSha256 = Object.hasOwn(manifest, 'noteSha256');
  const isLegacyManifest = !hasNoteHashVersion && !hasNoteSha256;
  if (!isLegacyManifest
      && (!hasNoteHashVersion || !hasNoteSha256
        || manifest.noteHashVersion !== NOTE_HASH_VERSION
        || typeof manifest.noteSha256 !== 'string'
        || !SHA256.test(manifest.noteSha256))) {
    return result({
      reason: manifest.noteHashVersion !== NOTE_HASH_VERSION
        ? 'unsupported_note_hash_version'
        : 'invalid_manifest_fields',
      targetId: id,
    });
  }

  if (manifest.id !== id || manifest.owner_id !== backupOwnerId
      || manifest.backupVersion !== backupVersion) {
    return result({
      reason: 'backup_manifest_identity_mismatch',
      targetId: id,
    });
  }

  const backupContentSha256 = hashText(content);
  let backupFullNoteSha256;
  if (!isLegacyManifest) {
    try {
      backupFullNoteSha256 = hashFullNote(backup);
    } catch {
      return result({
        reason: 'invalid_backup_fields',
        targetId: id,
        fullNoteSha256Verified: false,
      });
    }
    if (backupFullNoteSha256 !== manifest.noteSha256) {
      return result({
        reason: 'backup_note_hash_mismatch',
        targetId: id,
        fullNoteSha256Verified: false,
      });
    }
  }
  if (backupContentSha256 !== manifest.contentSha256) {
    return result({
      reason: 'backup_content_hash_mismatch',
      targetId: id,
      ...(!isLegacyManifest ? { fullNoteSha256Verified: true } : {}),
    });
  }

  const contentVerifiedResult = values => result({
    ...values,
    contentSha256Verified: true,
    ...(!isLegacyManifest ? { fullNoteSha256Verified: true } : {}),
  });

  if (backupOwnerId !== authenticatedUserId) {
    return contentVerifiedResult({
      reason: 'authenticated_user_backup_owner_mismatch',
      targetId: id,
    });
  }

  if (currentNote === null) {
    return contentVerifiedResult({
      canRestore: true,
      reason: 'missing_note_insert_candidate',
      targetId: id,
      plan: {
        operation: 'insert_if_absent',
        targetId: id,
        ownerBoundToAuthenticatedUser: true,
        replacementContentSha256: backupContentSha256,
        ...(!isLegacyManifest
          ? { replacementNoteSha256: backupFullNoteSha256 }
          : {}),
        backupVersion,
      },
    });
  }

  if (!isRecord(currentNote)
      || typeof currentNote.id !== 'string' || !UUID.test(currentNote.id)
      || typeof currentNote.owner_id !== 'string' || !UUID.test(currentNote.owner_id)
      || typeof currentNote.title !== 'string'
      || typeof currentNote.content !== 'string') {
    return contentVerifiedResult({
      reason: 'invalid_current_note',
      targetId: id,
    });
  }
  if (currentNote.owner_id !== authenticatedUserId
      || currentNote.owner_id !== backupOwnerId) {
    return contentVerifiedResult({
      reason: 'current_note_owner_mismatch',
      targetId: id,
    });
  }
  if (currentNote.id !== id) {
    return contentVerifiedResult({
      reason: 'current_note_id_mismatch',
      targetId: id,
    });
  }

  const currentContentSha256 = hashText(currentNote.content);
  if (currentNote.title === title && currentNote.content === content) {
    return contentVerifiedResult({
      reason: 'already_matches_backup',
      targetId: id,
      plan: {
        operation: 'no_change',
        targetId: id,
        currentContentSha256,
        ...(!isLegacyManifest
          ? { currentNoteSha256: hashFullNote({ ...currentNote, backupVersion }) }
          : {}),
        backupVersion,
      },
    });
  }

  if (approvedCurrentNoteSha256 !== null) {
    if (typeof approvedCurrentNoteSha256 !== 'string'
        || !SHA256.test(approvedCurrentNoteSha256)) {
      return contentVerifiedResult({
        reason: 'current_note_approval_invalid',
        targetId: id,
      });
    }
    let currentNoteSha256;
    try {
      currentNoteSha256 = hashFullNote({ ...currentNote, backupVersion });
    } catch {
      return contentVerifiedResult({
        reason: 'invalid_current_note',
        targetId: id,
      });
    }
    if (approvedCurrentNoteSha256 !== currentNoteSha256) {
      return contentVerifiedResult({
        reason: 'current_note_approval_mismatch',
        targetId: id,
      });
    }
    return contentVerifiedResult({
      canRestore: true,
      reason: 'approved_current_note_replace_candidate',
      targetId: id,
      plan: {
        operation: 'replace_if_note_hash_matches',
        targetId: id,
        expectedCurrentNoteSha256: currentNoteSha256,
        replacementContentSha256: backupContentSha256,
        ...(!isLegacyManifest
          ? { replacementNoteSha256: backupFullNoteSha256 }
          : {}),
        ownerBoundToAuthenticatedUser: true,
        backupVersion,
      },
    });
  }

  if (currentNote.title !== title) {
    return contentVerifiedResult({
      reason: 'current_title_conflict',
      targetId: id,
    });
  }
  if (currentContentSha256 === backupContentSha256) {
    return contentVerifiedResult({
      reason: 'current_note_metadata_conflict',
      targetId: id,
    });
  }
  if (typeof approvedCurrentContentSha256 !== 'string'
      || !SHA256.test(approvedCurrentContentSha256)) {
    return contentVerifiedResult({
      reason: 'current_content_approval_required',
      targetId: id,
    });
  }
  if (approvedCurrentContentSha256 !== currentContentSha256) {
    return contentVerifiedResult({
      reason: 'current_content_approval_mismatch',
      targetId: id,
    });
  }

  return contentVerifiedResult({
    canRestore: true,
    reason: 'approved_current_content_replace_candidate',
    targetId: id,
    plan: {
      operation: 'replace_if_content_hash_matches',
      targetId: id,
      expectedCurrentContentSha256: currentContentSha256,
      replacementContentSha256: backupContentSha256,
      ...(!isLegacyManifest
        ? { replacementNoteSha256: backupFullNoteSha256 }
        : {}),
      ownerBoundToAuthenticatedUser: true,
      backupVersion,
    },
  });
}

/**
 * Creates a restore plan only after requiring and verifying the current
 * signed-manifest format. Future operational restore APIs must call this
 * function rather than planNoteRestore(), whose legacy compatibility path
 * does not require a manifest signature.
 */
export function planSignedNoteRestore({
  authenticatedUserId,
  backup,
  manifest,
  signature,
  trustedPublicKeys,
  currentNote = null,
  approvedCurrentContentSha256 = null,
  approvedCurrentNoteSha256 = null,
} = {}) {
  let targetId = null;
  const signedResult = (values, manifestSignatureVerified) => {
    const response = result(values);
    return {
      ...response,
      integrity: {
        ...response.integrity,
        manifestSignatureVerified,
      },
    };
  };

  let isLatestManifest = false;
  try {
    if (isRecord(manifest)) {
      if (typeof manifest.id === 'string' && UUID.test(manifest.id)) {
        targetId = manifest.id;
      }
      isLatestManifest = manifest.noteHashVersion === NOTE_HASH_VERSION
        && typeof manifest.noteSha256 === 'string'
        && SHA256.test(manifest.noteSha256);
    }
  } catch {
    return signedResult({
      reason: 'signed_manifest_required',
      targetId,
    }, false);
  }
  if (!isLatestManifest) {
    return signedResult({
      reason: 'signed_manifest_required',
      targetId,
    }, false);
  }

  let signatureVerification;
  try {
    signatureVerification = verifyRestoreManifestSignature({
      manifest,
      signature,
      trustedPublicKeys,
    });
  } catch {
    return signedResult({
      reason: 'manifest_signature_invalid',
      targetId,
    }, false);
  }
  if (!signatureVerification.verified) {
    return signedResult({
      reason: 'manifest_signature_invalid',
      targetId,
    }, false);
  }

  let restorePlan;
  try {
    restorePlan = planNoteRestore({
      authenticatedUserId,
      backup,
      manifest,
      currentNote,
      approvedCurrentContentSha256,
      approvedCurrentNoteSha256,
    });
  } catch {
    return signedResult({
      reason: 'restore_plan_failed',
      targetId,
    }, true);
  }

  return {
    ...restorePlan,
    integrity: {
      ...restorePlan.integrity,
      manifestSignatureVerified: true,
    },
  };
}
