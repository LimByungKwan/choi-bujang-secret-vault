import {
  KeyObject,
  createPrivateKey,
  sign as signBytes,
} from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/u;
const MAX_BACKUP_VERSION_BYTES = 100;
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const SIGNATURE_SCHEMA = 'aleph.note-restore.manifest-signature/v1';

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
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

function utf8Field(value, maxBytes) {
  if (typeof value !== 'string' || !validUtf16(value)) {
    throw new TypeError('invalid_manifest');
  }
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > maxBytes || bytes.length > 0xffffffff) {
    throw new TypeError('invalid_manifest');
  }
  return bytes;
}

function manifestPayloadFields(manifest) {
  if (!isRecord(manifest)) throw new TypeError('invalid_manifest');
  for (const field of [
    'backupVersion',
    'id',
    'owner_id',
    'contentSha256',
    'noteHashVersion',
    'noteSha256',
    'keyId',
  ]) {
    if (!Object.hasOwn(manifest, field)) throw new TypeError('invalid_manifest');
  }

  if (typeof manifest.backupVersion !== 'string'
      || manifest.backupVersion.length === 0
      || manifest.backupVersion.length > 100
      || typeof manifest.id !== 'string'
      || !UUID.test(manifest.id)
      || typeof manifest.owner_id !== 'string'
      || !UUID.test(manifest.owner_id)
      || typeof manifest.contentSha256 !== 'string'
      || !SHA256.test(manifest.contentSha256)
      || manifest.noteHashVersion !== 1
      || typeof manifest.noteSha256 !== 'string'
      || !SHA256.test(manifest.noteSha256)
      || typeof manifest.keyId !== 'string'
      || !KEY_ID.test(manifest.keyId)) {
    throw new TypeError('invalid_manifest');
  }

  return [
    utf8Field(SIGNATURE_SCHEMA, 128),
    utf8Field(manifest.backupVersion, MAX_BACKUP_VERSION_BYTES),
    utf8Field(manifest.id, 36),
    utf8Field(manifest.owner_id, 36),
    utf8Field(manifest.contentSha256, 64),
    utf8Field(String(manifest.noteHashVersion), 16),
    utf8Field(manifest.noteSha256, 64),
    utf8Field(manifest.keyId, 64),
  ];
}

function serializeManifestPayload(fields) {
  const chunks = [];
  for (const field of fields) {
    const lengthPrefix = Buffer.alloc(4);
    lengthPrefix.writeUInt32BE(field.length);
    chunks.push(lengthPrefix, field);
  }
  return Buffer.concat(chunks);
}

/**
 * Signs the current manifest payload with a caller-provided Ed25519 private
 * key. The fixed version, field order, and 4-byte big-endian UTF-8 length
 * prefixes must remain byte-for-byte aligned with the restore verifier.
 * This independent serializer can drift; keep it covered by tests that verify
 * generated signatures with verifyRestoreManifestSignature().
 *
 * Keep the private key only in the approved backup-signing boundary. Restore
 * services should receive trusted public keys only.
 */
export function signNoteBackupManifest({ manifest, privateKey } = {}) {
  const fields = manifestPayloadFields(manifest);
  if (privateKey === undefined || privateKey === null) {
    throw new TypeError('invalid_private_key');
  }

  let key;
  try {
    if (typeof privateKey === 'string'
        && Buffer.byteLength(privateKey, 'utf8') > MAX_PRIVATE_KEY_BYTES) {
      throw new TypeError('invalid_private_key');
    }
    key = privateKey instanceof KeyObject
      ? privateKey
      : createPrivateKey(privateKey);
  } catch {
    throw new TypeError('invalid_private_key');
  }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('invalid_private_key');
  }

  try {
    return signBytes(
      null,
      serializeManifestPayload(fields),
      key,
    ).toString('base64url');
  } catch {
    throw new Error('manifest_signing_failed');
  }
}
