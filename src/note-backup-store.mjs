import { createHash } from 'node:crypto';
import {
  hashFullNote,
  hashNoteContent,
  verifyRestoreManifestSignature,
} from './note-restore-core.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const STORAGE_PREFIX = 'note-backups/v1';

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function backupReference(root) {
  return `nb1_${sha256(Buffer.from(root, 'utf8'))}`;
}

function storageBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return null;
}

function failure(reason, status = 'not_saved') {
  return { saved: false, status, reason };
}

function verifiedBackupFields(backup) {
  if (!isRecord(backup)
      || typeof backup.id !== 'string'
      || !UUID.test(backup.id)
      || typeof backup.owner_id !== 'string'
      || !UUID.test(backup.owner_id)
      || typeof backup.backupVersion !== 'string'
      || backup.backupVersion.length === 0
      || backup.backupVersion.length > 100
      || typeof backup.title !== 'string'
      || typeof backup.content !== 'string') {
    return null;
  }
  return {
    id: backup.id,
    owner_id: backup.owner_id,
    title: backup.title,
    content: backup.content,
    backupVersion: backup.backupVersion,
  };
}

function verifiedManifestFields(manifest) {
  if (!isRecord(manifest)
      || typeof manifest.id !== 'string'
      || typeof manifest.owner_id !== 'string'
      || typeof manifest.backupVersion !== 'string'
      || typeof manifest.contentSha256 !== 'string'
      || typeof manifest.noteHashVersion !== 'number'
      || typeof manifest.noteSha256 !== 'string'
      || typeof manifest.keyId !== 'string') {
    return null;
  }
  return {
    id: manifest.id,
    owner_id: manifest.owner_id,
    backupVersion: manifest.backupVersion,
    contentSha256: manifest.contentSha256,
    noteHashVersion: manifest.noteHashVersion,
    noteSha256: manifest.noteSha256,
    keyId: manifest.keyId,
  };
}

function serializeJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

async function createObject(storageAdapter, path, bytes) {
  try {
    const created = await storageAdapter.createIfAbsent(path, bytes);
    if (created === false) return 'object_conflict';
    if (created !== true) return 'storage_adapter_invalid_result';
  } catch {
    return 'storage_write_failed';
  }
  return null;
}

async function readObject(storageAdapter, path) {
  try {
    const bytes = storageBytes(await storageAdapter.read(path));
    return bytes ? { bytes, reason: null } : { bytes: null, reason: 'readback_failed' };
  } catch {
    return { bytes: null, reason: 'readback_failed' };
  }
}

/**
 * Saves a verified backup through an injected immutable storage adapter only.
 *
 * Adapter contract:
 * - createIfAbsent(path, bytes) atomically creates exactly one absent object,
 *   returns true on creation and false on an existing path, and never overwrites.
 * - read(path) returns the exact object bytes as Buffer or Uint8Array.
 * - Restore-facing reads MUST use readCompleteBackup(backupRef), which first
 *   requires the final completion marker and then verifies every referenced
 *   object. An absent marker means the backup is unavailable, even if staged
 *   objects exist.
 *
 * Objects use fixed paths beneath note-backups/v1/<owner UUID>/<note UUID>/
 * <base64url backupVersion>/{backup.json,manifest.json,signature.txt}. The
 * completion marker is written last under note-backups/v1/completed/<backupRef>.json.
 *
 * Competing writers fail closed on any existing object or completion marker.
 * A failure after some immutable objects were created leaves an incomplete
 * orphan; it is never promoted automatically, overwritten, or deleted. Retry
 * requires investigation and a new backupVersion. The adapter must provide
 * atomic create-if-absent per object; these separate objects are not one
 * transaction, so the final marker is the publication boundary.
 */
export async function saveVerifiedNoteBackup({
  backup,
  manifest,
  signature,
  trustedPublicKeys,
  storageAdapter,
} = {}) {
  if (!isRecord(storageAdapter)
      || typeof storageAdapter.createIfAbsent !== 'function'
      || typeof storageAdapter.read !== 'function') {
    return failure('storage_adapter_invalid');
  }

  const verifiedBackup = verifiedBackupFields(backup);
  const verifiedManifest = verifiedManifestFields(manifest);
  if (!verifiedBackup || !verifiedManifest) {
    return failure('invalid_backup_or_manifest');
  }
  if (verifiedBackup.id !== verifiedManifest.id
      || verifiedBackup.owner_id !== verifiedManifest.owner_id
      || verifiedBackup.backupVersion !== verifiedManifest.backupVersion) {
    return failure('backup_manifest_mismatch');
  }

  let contentHash;
  let fullNoteHash;
  let backupBytes;
  let manifestBytes;
  let signatureBytes;
  try {
    contentHash = hashNoteContent(verifiedBackup.content);
    fullNoteHash = hashFullNote(verifiedBackup);
    if (contentHash !== verifiedManifest.contentSha256
        || fullNoteHash !== verifiedManifest.noteSha256) {
      return failure('backup_hash_mismatch');
    }

    const signatureResult = verifyRestoreManifestSignature({
      manifest: verifiedManifest,
      signature,
      trustedPublicKeys,
    });
    if (!signatureResult.verified) {
      return failure('manifest_signature_invalid');
    }

    backupBytes = serializeJson(verifiedBackup);
    manifestBytes = serializeJson(verifiedManifest);
    signatureBytes = Buffer.from(signature, 'ascii');
  } catch {
    return failure('invalid_backup_or_manifest');
  }

  const versionSegment = Buffer.from(verifiedBackup.backupVersion, 'utf8')
    .toString('base64url');
  const root = `${STORAGE_PREFIX}/${verifiedBackup.owner_id}/${verifiedBackup.id}/${versionSegment}`;
  const backupRef = backupReference(root);
  const paths = {
    backup: `${root}/backup.json`,
    manifest: `${root}/manifest.json`,
    signature: `${root}/signature.txt`,
  };
  const objects = [
    [paths.backup, backupBytes],
    [paths.manifest, manifestBytes],
    [paths.signature, signatureBytes],
  ];

  for (const [path, bytes] of objects) {
    const reason = await createObject(storageAdapter, path, bytes);
    if (reason) {
      return failure(
        reason,
        reason === 'object_conflict' ? 'conflict' : 'incomplete',
      );
    }
  }

  const stored = {};
  for (const [name, path] of Object.entries(paths)) {
    const readResult = await readObject(storageAdapter, path);
    if (readResult.reason) return failure(readResult.reason, 'incomplete');
    const expected = name === 'backup'
      ? backupBytes
      : name === 'manifest'
        ? manifestBytes
        : signatureBytes;
    if (!readResult.bytes.equals(expected)) {
      return failure('readback_mismatch', 'incomplete');
    }
    stored[name] = readResult.bytes;
  }

  let storedBackup;
  let storedManifest;
  let storedSignature;
  try {
    storedBackup = JSON.parse(stored.backup.toString('utf8'));
    storedManifest = JSON.parse(stored.manifest.toString('utf8'));
    storedSignature = stored.signature.toString('ascii');
  } catch {
    return failure('readback_mismatch', 'incomplete');
  }

  const storedBackupFields = verifiedBackupFields(storedBackup);
  const storedManifestFields = verifiedManifestFields(storedManifest);
  if (!storedBackupFields || !storedManifestFields
      || storedBackupFields.id !== storedManifestFields.id
      || storedBackupFields.owner_id !== storedManifestFields.owner_id
      || storedBackupFields.backupVersion !== storedManifestFields.backupVersion) {
    return failure('readback_mismatch', 'incomplete');
  }

  try {
    if (hashNoteContent(storedBackupFields.content) !== storedManifestFields.contentSha256
        || hashFullNote(storedBackupFields) !== storedManifestFields.noteSha256
        || !verifyRestoreManifestSignature({
          manifest: storedManifestFields,
          signature: storedSignature,
          trustedPublicKeys,
        }).verified) {
      return failure('readback_verification_failed', 'incomplete');
    }
  } catch {
    return failure('readback_verification_failed', 'incomplete');
  }

  const completionPath = `${STORAGE_PREFIX}/completed/${backupRef}.json`;
  const completionBytes = serializeJson({
    schema: 'aleph.note-backup.complete/v1',
    backupRef,
    objects: {
      backup: { path: paths.backup, sha256: sha256(stored.backup) },
      manifest: { path: paths.manifest, sha256: sha256(stored.manifest) },
      signature: { path: paths.signature, sha256: sha256(stored.signature) },
    },
  });
  let completionReason;
  try {
    const created = await storageAdapter.createIfAbsent(completionPath, completionBytes);
    if (created === false) return failure('completion_conflict', 'conflict');
    if (created !== true) {
      return failure('storage_adapter_invalid_result', 'unconfirmed');
    }
  } catch {
    completionReason = 'completion_write_unconfirmed';
  }
  if (completionReason) return failure(completionReason, 'unconfirmed');

  const completionRead = await readObject(storageAdapter, completionPath);
  if (completionRead.reason) {
    return failure('completion_readback_unconfirmed', 'unconfirmed');
  }
  if (!completionRead.bytes.equals(completionBytes)) {
    return failure('completion_readback_mismatch', 'unconfirmed');
  }

  return {
    saved: true,
    status: 'complete',
    backupRef,
  };
}
