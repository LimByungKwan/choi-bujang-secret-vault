import { createHash } from 'node:crypto';
import {
  hashFullNote,
  hashNoteContent,
  verifyRestoreManifestSignature,
} from './note-restore-core.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const STORAGE_PREFIX = 'note-backups/v1';
const COMPLETION_SCHEMA = 'aleph.note-backup.complete/v1';

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, expectedKeys) {
  return isRecord(value)
    && Object.keys(value).length === expectedKeys.length
    && expectedKeys.every(key => Object.hasOwn(value, key));
}

function storageBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return null;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function backupReference(root) {
  return `nb1_${sha256(Buffer.from(root, 'utf8'))}`;
}

function validBackupVersion(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 100
    && Buffer.byteLength(value, 'utf8') <= 100
    && !hasUnpairedSurrogate(value);
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function failure(reason) {
  return { read: false, status: 'unavailable', reason };
}

async function readObject(storageAdapter, path) {
  try {
    const bytes = storageBytes(await storageAdapter.read(path));
    return bytes ? { bytes, reason: null } : { bytes: null, reason: 'object_unavailable' };
  } catch {
    return { bytes: null, reason: 'object_unavailable' };
  }
}

function parseJson(bytes) {
  try {
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function completionObjects(marker, expectedPaths) {
  if (!hasExactKeys(marker, ['schema', 'backupRef', 'objects'])
      || marker.schema !== COMPLETION_SCHEMA
      || !isRecord(marker.objects)
      || !hasExactKeys(marker.objects, ['backup', 'manifest', 'signature'])) {
    return null;
  }

  const refs = {};
  for (const name of ['backup', 'manifest', 'signature']) {
    const ref = marker.objects[name];
    if (!hasExactKeys(ref, ['path', 'sha256'])
        || ref.path !== expectedPaths[name]
        || typeof ref.sha256 !== 'string'
        || !SHA256.test(ref.sha256)) {
      return null;
    }
    refs[name] = ref;
  }
  return refs;
}

function parseBackup(value, targetId, ownerId, backupVersion) {
  if (!hasExactKeys(value, ['id', 'owner_id', 'title', 'content', 'backupVersion'])
      || value.id !== targetId
      || value.owner_id !== ownerId
      || value.backupVersion !== backupVersion
      || typeof value.title !== 'string'
      || typeof value.content !== 'string') {
    return null;
  }
  return {
    id: value.id,
    owner_id: value.owner_id,
    title: value.title,
    content: value.content,
    backupVersion: value.backupVersion,
  };
}

function parseManifest(value, targetId, ownerId, backupVersion) {
  if (!hasExactKeys(value, [
    'id',
    'owner_id',
    'backupVersion',
    'contentSha256',
    'noteHashVersion',
    'noteSha256',
    'keyId',
  ])
      || value.id !== targetId
      || value.owner_id !== ownerId
      || value.backupVersion !== backupVersion
      || typeof value.contentSha256 !== 'string'
      || typeof value.noteHashVersion !== 'number'
      || typeof value.noteSha256 !== 'string'
      || typeof value.keyId !== 'string'
      || !KEY_ID.test(value.keyId)) {
    return null;
  }
  return {
    id: value.id,
    owner_id: value.owner_id,
    backupVersion: value.backupVersion,
    contentSha256: value.contentSha256,
    noteHashVersion: value.noteHashVersion,
    noteSha256: value.noteSha256,
    keyId: value.keyId,
  };
}

/**
 * Reads a completed immutable backup through an injected storage adapter.
 *
 * Input contract:
 *   { targetId, ownerId, backupVersion, trustedPublicKeys, storageAdapter }
 * targetId and ownerId must come from the caller's verified server-side
 * authorization and ownership checks. trustedPublicKeys must be server-trusted.
 * The adapter must provide consistent reads of the completion marker and
 * referenced objects; this function cannot prevent later replacement or
 * deletion by a mutable storage backend.
 *
 * Completion markers are publication gates, not authenticity proofs. The
 * backup hash and manifest signature are always checked independently. An
 * operational API must not expose the returned backup directly to a client.
 */
export async function readCompleteBackup({
  targetId,
  ownerId,
  backupVersion,
  trustedPublicKeys,
  storageAdapter,
} = {}) {
  if (!isRecord(storageAdapter) || typeof storageAdapter.read !== 'function') {
    return failure('storage_adapter_invalid');
  }
  if (typeof targetId !== 'string' || !UUID.test(targetId)
      || typeof ownerId !== 'string' || !UUID.test(ownerId)
      || !validBackupVersion(backupVersion)) {
    return failure('invalid_backup_reference');
  }
  if (!Array.isArray(trustedPublicKeys)) {
    return failure('invalid_trusted_keys');
  }

  const versionSegment = Buffer.from(backupVersion, 'utf8').toString('base64url');
  const root = `${STORAGE_PREFIX}/${ownerId}/${targetId}/${versionSegment}`;
  const backupRef = backupReference(root);
  const expectedPaths = {
    backup: `${root}/backup.json`,
    manifest: `${root}/manifest.json`,
    signature: `${root}/signature.txt`,
  };
  const completionPath = `${STORAGE_PREFIX}/completed/${backupRef}.json`;

  const completionRead = await readObject(storageAdapter, completionPath);
  if (completionRead.reason) return failure('completion_marker_unavailable');
  const marker = parseJson(completionRead.bytes);
  if (!marker
      || marker.backupRef !== backupRef
      || !completionObjects(marker, expectedPaths)) {
    return failure('completion_marker_invalid');
  }
  const refs = completionObjects(marker, expectedPaths);

  const stored = {};
  for (const name of ['backup', 'manifest', 'signature']) {
    const objectRead = await readObject(storageAdapter, expectedPaths[name]);
    if (objectRead.reason) return failure('backup_object_unavailable');
    if (sha256(objectRead.bytes) !== refs[name].sha256) {
      return failure('backup_object_hash_mismatch');
    }
    stored[name] = objectRead.bytes;
  }

  const parsedBackup = parseJson(stored.backup);
  const parsedManifest = parseJson(stored.manifest);
  if (!parsedBackup || !parsedManifest) {
    return failure('backup_object_invalid');
  }
  const backup = parseBackup(parsedBackup, targetId, ownerId, backupVersion);
  const manifest = parseManifest(parsedManifest, targetId, ownerId, backupVersion);
  if (!backup || !manifest) return failure('backup_identity_mismatch');

  if (stored.signature.some(byte => byte > 0x7f)) {
    return failure('manifest_signature_invalid');
  }
  const signature = stored.signature.toString('ascii');
  if (!SIGNATURE.test(signature)
      || Buffer.from(signature, 'ascii').compare(stored.signature) !== 0) {
    return failure('manifest_signature_invalid');
  }

  try {
    if (hashNoteContent(backup.content) !== manifest.contentSha256
        || hashFullNote(backup) !== manifest.noteSha256) {
      return failure('backup_hash_mismatch');
    }
  } catch {
    return failure('backup_hash_invalid');
  }

  const signatureResult = verifyRestoreManifestSignature({
    manifest,
    signature,
    trustedPublicKeys,
  });
  if (!signatureResult.verified) {
    return failure('manifest_signature_invalid');
  }

  return {
    read: true,
    status: 'complete',
    backupRef,
    backup,
    manifest,
    signature,
  };
}
