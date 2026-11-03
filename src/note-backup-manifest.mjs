import {
  hashFullNote,
  hashNoteContent,
} from './note-restore-core.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/u;
const MAX_BACKUP_VERSION_LENGTH = 100;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Creates a manifest compatible with the current restore hash/signature
 * verifiers. This function does not authenticate the caller or prove that
 * owner_id was verified; servers must pass ownership obtained from their
 * verified session and a server-side ownership check, never trust request data.
 *
 * Signing, private Storage persistence, read-back verification, and publishing
 * a completion marker are separate steps. A partial upload is not a valid
 * backup.
 */
export function createNoteBackupManifest(input = {}) {
  if (!isRecord(input)) {
    throw new TypeError('invalid_note_backup');
  }
  for (const field of [
    'id',
    'owner_id',
    'title',
    'content',
    'backupVersion',
    'keyId',
  ]) {
    if (!Object.hasOwn(input, field)) {
      throw new TypeError(`missing_${field}`);
    }
  }
  const { id, owner_id, title, content, backupVersion, keyId } = input;

  if (typeof id !== 'string' || !UUID.test(id)) {
    throw new TypeError('invalid_note_id');
  }
  if (typeof owner_id !== 'string' || !UUID.test(owner_id)) {
    throw new TypeError('invalid_note_owner_id');
  }
  if (typeof title !== 'string' || typeof content !== 'string') {
    throw new TypeError('invalid_note_text_fields');
  }
  if (typeof backupVersion !== 'string'
      || backupVersion.length === 0
      || backupVersion.length > MAX_BACKUP_VERSION_LENGTH) {
    throw new TypeError('invalid_backup_version');
  }
  if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) {
    throw new TypeError('invalid_key_id');
  }

  const note = { id, owner_id, title, content, backupVersion };
  return {
    id,
    owner_id,
    backupVersion,
    contentSha256: hashNoteContent(content),
    noteHashVersion: 1,
    noteSha256: hashFullNote(note),
    keyId,
  };
}
