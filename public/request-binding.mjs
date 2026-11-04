function encodeQueryComponent(value) {
  return encodeURIComponent(value).replace(/[!'()*]/gu, character => (
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  ));
}

function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalJson(item)).join(',')}]`;
  }
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.keys(value).sort().map(key => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ));
    return `{${entries.join(',')}}`;
  }
  throw new TypeError('invalid_json_body');
}

function normalizePathAndQuery(value) {
  if (typeof value !== 'string' || value.length > 4096) {
    throw new TypeError('invalid_request_target');
  }
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('#')
      || value.includes('\\')) {
    throw new TypeError('invalid_request_target');
  }

  const queryIndex = value.indexOf('?');
  const rawPath = queryIndex < 0 ? value : value.slice(0, queryIndex);
  const rawQuery = queryIndex < 0 ? '' : value.slice(queryIndex + 1);
  const rawSegments = rawPath.split('/');
  if (rawSegments.some(segment => /%(?:2f|5c)/iu.test(segment))) {
    throw new TypeError('invalid_request_target');
  }
  const decodedSegments = rawSegments.map(segment => {
    let decoded;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new TypeError('invalid_request_target');
    }
    if (decoded === '.' || decoded === '..' || decoded.includes('\\') || decoded.includes('/')) {
      throw new TypeError('invalid_request_target');
    }
    return decoded;
  });
  if (decodedSegments.slice(1, -1).some(segment => segment.length === 0)) {
    throw new TypeError('invalid_request_target');
  }
  if (decodedSegments.length > 1 && decodedSegments.at(-1) === '') decodedSegments.pop();
  const pathname = rawPath === '/'
    ? '/'
    : decodedSegments.map(encodeQueryComponent).join('/');
  const entries = [...new URLSearchParams(rawQuery).entries()].sort(([keyA, valueA], [keyB, valueB]) => (
    keyA < keyB ? -1 : keyA > keyB ? 1
      : valueA < valueB ? -1 : valueA > valueB ? 1 : 0
  ));
  const query = entries.map(([key, item]) => (
    `${encodeQueryComponent(key)}=${encodeQueryComponent(item)}`
  )).join('&');
  return query ? `${pathname}?${query}` : pathname;
}

export async function createHttpRequestBinding({
  method,
  target,
  body,
  hasBody,
}) {
  if (typeof method !== 'string' || !/^[A-Za-z]{3,10}$/u.test(method)
      || typeof hasBody !== 'boolean') {
    throw new TypeError('invalid_request_binding');
  }
  const normalizedMethod = method.toUpperCase();
  const canonicalTarget = normalizePathAndQuery(target);
  let bodySha256 = null;
  if (hasBody) {
    const canonicalBody = canonicalJson(body);
    const bytes = new TextEncoder().encode(canonicalBody);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    bodySha256 = [...new Uint8Array(digest)]
      .map(byte => byte.toString(16).padStart(2, '0')).join('');
  } else if (body !== undefined) {
    throw new TypeError('unexpected_request_body');
  }
  return Object.freeze({
    method: normalizedMethod,
    target: canonicalTarget,
    bodySha256,
    bodyPresent: hasBody,
  });
}
