const STORAGE_PREFIX = 'note-backups/v1';
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const OBJECT_PATH = new RegExp(
  `^${STORAGE_PREFIX}/${UUID}/${UUID}/[A-Za-z0-9_-]+/(?:backup\\.json|manifest\\.json|signature\\.txt)$`,
  'iu',
);
const COMPLETION_PATH = new RegExp(
  `^${STORAGE_PREFIX}/completed/nb1_[0-9a-f]{64}\\.json$`,
  'u',
);
const BUCKET_NAME = /^[\w!.*'() &$@=;:+,?-]{1,100}$/u;
const DUPLICATE_CODES = new Set(['Duplicate', 'ResourceAlreadyExists']);

function isRecord(value) {
  return value !== null && typeof value === 'object';
}

function isStoragePath(path) {
  return typeof path === 'string'
    && !path.startsWith('/')
    && !path.includes('\\')
    && !path.split('/').some(segment => segment === '.' || segment === '..')
    && (OBJECT_PATH.test(path) || COMPLETION_PATH.test(path));
}

function isBucketName(value) {
  return typeof value === 'string'
    && value.length <= 100
    && value.trim() === value
    && !value.includes('/')
    && !value.includes('\\')
    && BUCKET_NAME.test(value);
}

function isDuplicateError(error) {
  if (!isRecord(error)) return false;
  const code = error.code;
  const statusCode = error.statusCode;
  if (DUPLICATE_CODES.has(code) || DUPLICATE_CODES.has(statusCode)) {
    return true;
  }
  if (typeof code === 'string' && code.length > 0) return false;
  return error.status === 409
    || error.status === '409'
    || statusCode === '409'
    || statusCode === 409;
}

function errorReason(operation) {
  return new Error(`storage_${operation}_failed`);
}

function responseBytes(data) {
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    return data.arrayBuffer().then(arrayBuffer => Buffer.from(arrayBuffer));
  }
  return null;
}

/**
 * Creates a lazy adapter over an existing Supabase client and an explicit
 * private bucket. The caller must provide an authorized server-side client;
 * this factory does not create clients, make requests, or verify bucket policy.
 *
 * Only the fixed backup object and completion-marker paths are accepted.
 * Storage errors are reduced to a collision result or a sanitized exception;
 * their messages, bucket name, and paths are never logged or re-exposed.
 */
export function createSupabaseBackupStorageAdapter({
  supabaseClient,
  bucketName,
} = {}) {
  if (!isRecord(supabaseClient)
      || !isRecord(supabaseClient.storage)
      || typeof supabaseClient.storage.from !== 'function') {
    throw new TypeError('invalid_supabase_client');
  }
  if (!isBucketName(bucketName)) {
    throw new TypeError('invalid_private_bucket_name');
  }

  function bucket() {
    try {
      return supabaseClient.storage.from(bucketName);
    } catch {
      throw errorReason('client');
    }
  }

  return {
    async createIfAbsent(path, bytes) {
      if (!isStoragePath(path)) throw new TypeError('invalid_storage_path');
      if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
        throw new TypeError('invalid_storage_bytes');
      }

      let response;
      try {
        response = await bucket().upload(path, Buffer.from(bytes), {
          upsert: false,
          contentType: 'application/octet-stream',
        });
      } catch (error) {
        if (isDuplicateError(error)) return false;
        throw errorReason('write');
      }

      if (!isRecord(response)) throw errorReason('write');
      if (response.error !== null && response.error !== undefined) {
        if (isDuplicateError(response.error)) return false;
        throw errorReason('write');
      }
      if (!isRecord(response.data)) throw errorReason('write');
      return true;
    },

    async read(path) {
      if (!isStoragePath(path)) throw new TypeError('invalid_storage_path');

      let response;
      try {
        response = await bucket().download(path);
      } catch {
        throw errorReason('read');
      }
      if (!isRecord(response)
          || response.error !== null && response.error !== undefined) {
        throw errorReason('read');
      }

      try {
        const bytes = responseBytes(response.data);
        if (bytes === null) throw errorReason('read');
        return await bytes;
      } catch {
        throw errorReason('read');
      }
    },
  };
}
