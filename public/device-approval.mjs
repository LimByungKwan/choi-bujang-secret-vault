export function createDeviceApprovalController({
  checkApproval,
  clearProtectedUi,
  onStateChange,
  loadNotes,
}) {
  if (typeof checkApproval !== 'function'
      || typeof clearProtectedUi !== 'function'
      || typeof onStateChange !== 'function'
      || typeof loadNotes !== 'function') {
    throw new TypeError('invalid_device_approval_dependencies');
  }

  let generation = 0;
  let state = 'unknown';
  let authenticated = false;

  function setState(nextState) {
    state = nextState;
    onStateChange(nextState);
  }

  function isCurrent(requestGeneration) {
    return authenticated
      && generation === requestGeneration
      && state === 'approved';
  }

  async function setSession(user) {
    const requestGeneration = ++generation;
    authenticated = Boolean(user);
    setState('unknown');
    clearProtectedUi();

    if (!authenticated) {
      setState('signed_out');
      return;
    }

    setState('checking');
    let result;
    try {
      result = await checkApproval();
    } catch {
      if (generation === requestGeneration) {
        clearProtectedUi();
        setState('unavailable');
      }
      return;
    }

    if (generation !== requestGeneration) return;
    if (result !== 'approved') {
      clearProtectedUi();
      setState('unapproved');
      return;
    }

    setState('approved');
    try {
      await loadNotes(() => isCurrent(requestGeneration));
    } catch {
      if (generation === requestGeneration) {
        clearProtectedUi();
        setState('unavailable');
      }
    }
  }

  function invalidate() {
    generation += 1;
    authenticated = false;
    clearProtectedUi();
    setState('unknown');
  }

  return Object.freeze({
    get state() {
      return state;
    },
    isApproved() {
      return authenticated && state === 'approved';
    },
    setSession,
    invalidate,
  });
}
