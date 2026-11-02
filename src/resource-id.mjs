export const RESOURCE_TYPES = Object.freeze([
  'note',
  'class-announcement',
  'instructor-material',
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function createResourceId(type, id) {
  if (!RESOURCE_TYPES.includes(type)) throw new TypeError('invalid_resource_type');
  if (typeof id !== 'string' || !UUID.test(id)) throw new TypeError('invalid_resource_id');
  return `${type}:${id}`;
}

export function parseResourceId(resourceId) {
  if (typeof resourceId !== 'string') return null;
  const separator = resourceId.indexOf(':');
  if (separator < 1) return null;

  const type = resourceId.slice(0, separator);
  const id = resourceId.slice(separator + 1);
  if (!RESOURCE_TYPES.includes(type) || !UUID.test(id)) return null;
  return { type, id };
}
