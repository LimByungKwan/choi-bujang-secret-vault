const LOCAL_ROUTE_CONVENTIONS = Object.freeze({
  notes: { resourceType: 'personal_note', root: '/notes', access: 'individual_get' },
  announcements: {
    resourceType: 'class_announcement',
    root: '/announcements',
    access: 'get_only',
  },
  instructor_materials: {
    resourceType: 'instructor_material',
    root: '/instructor-materials',
    access: 'deny_all',
  },
});

function classification(resourceType, outcome, detail) {
  return {
    resourceType,
    outcome,
    detail,
    contractStatus: 'local_proposal_not_engine_verified',
  };
}

function validMethod(method) {
  return typeof method === 'string' && /^[A-Z]+$/u.test(method);
}

function pathShape(path, root) {
  if (typeof path !== 'string' || path.includes('?') || path.includes('#')
      || path.includes('%') || path.includes('\\') || path.includes('//')
      || /\s/u.test(path)) return null;
  if (path === root) return { pattern: root, hasId: false };
  if (!path.startsWith(`${root}/`)) return null;

  const id = path.slice(root.length + 1);
  if (!id || id.includes('/') || id === '.' || id === '..') return null;
  if (id.toLowerCase() === 'export') {
    return { pattern: `${root}/export`, hasId: true, reserved: true };
  }
  return { pattern: `${root}/:id`, hasId: true };
}

export function classifyResourceAccess(input = {}) {
  const request = input !== null && typeof input === 'object' && !Array.isArray(input)
    ? input
    : {};
  const { service, method, path, route } = request;
  if (typeof service !== 'string' || !Object.hasOwn(LOCAL_ROUTE_CONVENTIONS, service)) {
    return classification(null, 'deny_candidate', 'unknown_service');
  }

  const convention = LOCAL_ROUTE_CONVENTIONS[service];
  const shape = pathShape(path, convention.root);
  if (!validMethod(method) || !shape || typeof route !== 'string') {
    return classification(convention.resourceType, 'deny_candidate', 'invalid_path_shape');
  }

  const expectedRoute = `${method} ${shape.hasId ? `${convention.root}/:id` : shape.pattern}`;
  if (route !== expectedRoute) {
    return classification(convention.resourceType, 'deny_candidate', 'service_method_path_route_mismatch');
  }
  if (shape.reserved) {
    return classification(convention.resourceType, 'deny_candidate', 'reserved_function_path');
  }

  if (convention.access === 'deny_all') {
    return classification(convention.resourceType, 'deny_candidate', 'resource_denied');
  }
  if (convention.access === 'individual_get' && (!shape.hasId || method !== 'GET')) {
    return classification(convention.resourceType, 'deny_candidate', 'individual_get_only');
  }
  if (convention.access === 'get_only' && method !== 'GET') {
    return classification(convention.resourceType, 'deny_candidate', 'read_only_resource');
  }

  return classification(convention.resourceType, 'allow_candidate', 'route_matches_local_convention');
}
