export function createDeviceApprovalGuard({ verifyApproval }) {
  if (typeof verifyApproval !== 'function') {
    throw new TypeError('verify_approval_required');
  }

  return async function runWithApprovedDevice(serverContext, operation) {
    if (typeof operation !== 'function') {
      throw new TypeError('protected_operation_required');
    }

    let status;
    try {
      status = await verifyApproval(serverContext);
    } catch {
      return { allowed: false, reason: 'verification_unavailable' };
    }

    if (status !== 'approved') {
      return { allowed: false, reason: 'approval_required' };
    }

    return { allowed: true, value: await operation() };
  };
}
