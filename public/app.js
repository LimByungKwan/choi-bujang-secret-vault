import { createDeviceApprovalController } from './device-approval.mjs';
import { createHttpRequestBinding } from './request-binding.mjs';

const authStatus = document.querySelector('#auth-status');
const opsSummaryValues = {
  decider: document.querySelector('#ops-decider-value'),
  detect: document.querySelector('#ops-detect-value'),
  revocation: document.querySelector('#ops-revocation-value'),
  restore: document.querySelector('#ops-restore-value'),
};
const opsSummarySources = {
  decider: document.querySelector('#ops-decider-source'),
  detect: document.querySelector('#ops-detect-source'),
  revocation: document.querySelector('#ops-revocation-source'),
  restore: document.querySelector('#ops-restore-source'),
};
const opsSummaryRequestId = document.querySelector('#ops-request-id');
const opsSummaryCheckedAt = document.querySelector('#ops-checked-at');
const opsSummaryCommit = document.querySelector('#ops-commit');
const connectivityStatus = document.querySelector('#connectivity-status');
const deviceApprovalStatus = document.querySelector('#device-approval-status');
const deviceApprovalResult = document.querySelector('#device-approval-result');
const deviceApprovalRequest = document.querySelector('#device-approval-request');
const loginForm = document.querySelector('#login-form');
const loginEmail = document.querySelector('#login-email');
const loginPassword = document.querySelector('#login-password');
const loginButton = document.querySelector('#login-button');
const loginError = document.querySelector('#login-error');
const accountView = document.querySelector('#account-view');
const accountEmail = document.querySelector('#account-email');
const logoutButton = document.querySelector('#logout-button');
const logoutError = document.querySelector('#logout-error');
const authInitError = document.querySelector('#auth-init-error');
const notesList = document.querySelector('#notes');
const noteForm = document.querySelector('#note-form');
const noteTitle = document.querySelector('#note-title');
const noteBody = document.querySelector('#note-body');
const noteSubmit = document.querySelector('#note-submit');
const noteCancel = document.querySelector('#note-cancel');
const noteError = document.querySelector('#note-error');
let activeUser = null;
let csrfToken = null;
let sessionFlight = null;
let sessionRevision = 0;
let editingNoteId = null;

function renderConnectivityStatus() {
  const online = navigator.onLine;
  connectivityStatus.textContent = online
    ? '브라우저 연결 상태: 온라인. 서버 접속 가능 여부를 보장하지는 않습니다.'
    : '브라우저 연결 상태: 오프라인. 로그인과 메모 API를 사용할 수 없습니다.';
  connectivityStatus.dataset.state = online ? 'online' : 'offline';
}

function resetOpsSummary() {
  for (const element of Object.values(opsSummaryValues)) element.textContent = '확인 전';
  for (const element of Object.values(opsSummarySources)) element.textContent = '확인 전';
  opsSummaryRequestId.textContent = '확인 전';
  opsSummaryCheckedAt.textContent = '확인 전';
  opsSummaryCommit.textContent = '확인 전';
}

function failOpsSummary(message, requestId = message) {
  for (const element of Object.values(opsSummaryValues)) element.textContent = message;
  for (const element of Object.values(opsSummarySources)) element.textContent = message;
  opsSummaryRequestId.textContent = requestId;
  opsSummaryCheckedAt.textContent = message;
  opsSummaryCommit.textContent = message;
}

function countSummary(counts, labels) {
  if (!counts || typeof counts !== 'object' || Array.isArray(counts)) return null;
  return labels.map(([key, label]) => {
    const value = counts[key];
    return Number.isSafeInteger(value) && value >= 0 ? `${label} ${value}` : null;
  }).every(Boolean)
    ? labels.map(([key, label]) => `${label} ${counts[key]}`).join(' · ')
    : null;
}

function renderOpsSummary(data, headerRequestId) {
  const sections = data?.sections;
  const sourceLabels = {
    api_measured: '실측',
    code_static: '코드 기준',
    not_connected: '미연결',
  };
  if (!sections || !Array.isArray(sections.decider?.rules)
      || sections.decider.source !== 'code_static'
      || sections.detect?.source !== 'not_connected'
      || sections.detect.events !== null
      || sections.revocation?.source !== 'api_measured'
      || sections.restore?.source !== 'api_measured'
      || typeof data.requestId !== 'string'
      || typeof data.checkedAt !== 'string'
      || typeof data.commit !== 'string') {
    return false;
  }

  const revocation = countSummary(sections.revocation.counts, [
    ['pending', '대기'], ['approved', '승인'], ['rejected', '거부'], ['revoked', '회수'],
  ]);
  const outcomes = countSummary(sections.restore.outcomes, [
    ['restored', '복구'], ['no_change', '변경 없음'], ['conflict', '충돌'],
    ['not_owned', '소유자 불일치'], ['failed', '실패'], ['rejected', '거부'],
  ]);
  if (!revocation || !outcomes
      || !sections.decider.rules.every(rule => typeof rule === 'string')
      || (sections.restore.latestAt !== null
        && (typeof sections.restore.latestAt !== 'string'
          || !Number.isFinite(Date.parse(sections.restore.latestAt))))) {
    return false;
  }

  opsSummaryValues.decider.textContent = sections.decider.rules.join(' · ');
  opsSummaryValues.detect.textContent = '미연결';
  opsSummaryValues.revocation.textContent = revocation;
  opsSummaryValues.restore.textContent = `${outcomes} · 최근 기록 ${
    sections.restore.latestAt ?? '없음'
  }`;
  for (const [section, element] of Object.entries(opsSummarySources)) {
    element.textContent = sourceLabels[sections[section].source];
  }
  opsSummaryRequestId.textContent = data.requestId || headerRequestId || '확인 실패(HTTP 200)';
  opsSummaryCheckedAt.textContent = data.checkedAt;
  opsSummaryCommit.textContent = data.commit;
  return true;
}

async function loadOpsSummary() {
  if (!activeUser) {
    resetOpsSummary();
    return;
  }
  const revision = sessionRevision;
  try {
    const headers = {};
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const response = await fetch('/api/ops/summary', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
      headers,
    });
    if (revision !== sessionRevision || !activeUser) return;
    const requestId = response.headers.get('x-request-id');
    if (!response.ok) {
      failOpsSummary(`확인 실패(HTTP ${response.status})`, requestId
        ? `${requestId} · 확인 실패(HTTP ${response.status})`
        : `확인 실패(HTTP ${response.status})`);
      return;
    }
    const data = await readJson(response);
    if (revision !== sessionRevision || !activeUser) return;
    if (!renderOpsSummary(data, requestId)) {
      failOpsSummary('확인 실패(HTTP 200)', requestId || '확인 실패(HTTP 200)');
    }
  } catch {
    if (revision === sessionRevision && activeUser) {
      failOpsSummary('확인 실패(HTTP 응답 없음)');
    }
  }
}

deviceApprovalRequest.disabled = false;
deviceApprovalRequest.addEventListener('click', async () => {
  deviceApprovalRequest.disabled = true;
  deviceApprovalResult.textContent = '기기 등록을 확인하고 있습니다.';
  try {
    const challenge = await authRequest('/api/device/registration-options', {});
    const credential = await navigator.credentials.create({
      publicKey: decodeRegistrationOptions(challenge.options),
    });
    if (!credential) throw new Error('기기 등록이 취소되었습니다.');
    const result = await authRequest('/api/device/registration-verify', {
      challengeId: challenge.challengeId,
      response: serializeCredential(credential),
    });
    deviceApprovalResult.textContent = result.status === 'pending'
      ? '기기 등록이 완료되었습니다. 관리자 승인을 기다리는 중입니다.'
      : '기기 등록 결과를 확인하지 못했습니다.';
    await deviceApproval.setSession(activeUser);
  } catch (error) {
    deviceApprovalResult.textContent = error.message || '기기 등록을 완료하지 못했습니다.';
  } finally {
    deviceApprovalRequest.disabled = !activeUser;
  }
});

window.addEventListener('online', renderConnectivityStatus);
window.addEventListener('offline', renderConnectivityStatus);
renderConnectivityStatus();

function clearProtectedUi() {
  noteForm.hidden = true;
  noteForm.reset();
  editingNoteId = null;
  noteCancel.hidden = true;
  noteSubmit.textContent = '메모 추가';
  noteError.hidden = true;
  notesList.replaceChildren();
}

function renderDeviceApprovalState(state) {
  const messages = {
    unknown: '기기 승인 상태: 확인 불가. 보호 메모는 닫혀 있습니다.',
    signed_out: '기기 승인 상태: 로그인 후 확인할 수 있습니다.',
    checking: '기기 승인 상태를 서버에 확인하고 있습니다. 보호 메모는 닫혀 있습니다.',
    approved: '기기 승인 상태: 서버에서 승인 확인됨.',
    unapproved: '기기 승인이 확인되지 않았습니다. 등록 또는 관리자 승인이 필요합니다.',
    unavailable: '기기 승인 서버에 연결할 수 없습니다. 보호 메모는 닫혀 있습니다.',
  };
  deviceApprovalStatus.textContent = messages[state] ?? messages.unknown;
  deviceApprovalStatus.dataset.state = state in messages ? state : 'unknown';
  noteForm.hidden = state !== 'approved';
  deviceApprovalResult.textContent = state === 'approved'
    ? '서버 승인 확인 결과로 자료실 접근이 허용되었습니다.'
    : '서버가 승인 상태를 확인하기 전에는 자료실에 접근할 수 없습니다.';
}

function refreshDeviceApprovalAfterDenial() {
  const user = activeUser;
  deviceApproval.invalidate();
  if (user) void deviceApproval.setSession(user);
}

async function checkDeviceApproval() {
  const challenge = await authRequest('/api/device/challenge', { purpose: 'status' });
  if (!challenge.challengeId || !challenge.options) return 'unapproved';
  const response = await navigator.credentials.get({
    publicKey: decodeAuthenticationOptions(challenge.options),
  });
  if (!response) return 'unapproved';
  const result = await authRequest('/api/device/verify', {
    purpose: 'status',
    challengeId: challenge.challengeId,
    response: serializeCredential(response),
  });
  return result.status === 'approved' ? 'approved' : 'unapproved';
}

const deviceApproval = createDeviceApprovalController({
  checkApproval: checkDeviceApproval,
  clearProtectedUi,
  onStateChange: renderDeviceApprovalState,
  loadNotes,
});
clearProtectedUi();
renderDeviceApprovalState('unknown');

function decodeBase64Url(value) {
  const base64 = value.replace(/-/gu, '+').replace(/_/gu, '/');
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/gu, '').replace(/\+/gu, '-').replace(/\//gu, '_');
}

function decodeRegistrationOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    excludeCredentials: options.excludeCredentials?.map(item => ({
      ...item, id: decodeBase64Url(item.id),
    })),
  };
}

function decodeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: options.allowCredentials?.map(item => ({
      ...item, id: decodeBase64Url(item.id),
    })),
  };
}

function serializeCredential(credential) {
  const response = {
    clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) {
    response.attestationObject = encodeBase64Url(credential.response.attestationObject);
  }
  if (credential.response.authenticatorData) {
    response.authenticatorData = encodeBase64Url(credential.response.authenticatorData);
  }
  if (credential.response.signature) {
    response.signature = encodeBase64Url(credential.response.signature);
  }
  if (credential.response.userHandle) {
    response.userHandle = encodeBase64Url(credential.response.userHandle);
  }
  if (credential.response.getTransports) {
    response.transports = credential.response.getTransports();
  }
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function renderAuthState(user) {
  activeUser = user;
  sessionRevision += 1;
  const signedIn = Boolean(user);
  authStatus.textContent = signedIn ? '로그인되었습니다.' : '로그인되어 있지 않습니다.';
  loginForm.hidden = signedIn;
  accountView.hidden = !signedIn;
  deviceApprovalRequest.disabled = !signedIn;
  noteForm.hidden = true;
  accountEmail.textContent = user?.email ?? '';
  loginError.hidden = true;
  logoutError.hidden = true;
  authInitError.hidden = true;
  void deviceApproval.setSession(user);
  if (signedIn) {
    void loadOpsSummary();
  } else {
    resetOpsSummary();
    clearProtectedUi();
  }
}

function messageForFailure(code, status, fallback) {
  if (code === 'INVALID_CREDENTIALS') return '이메일 또는 비밀번호를 확인해 주세요.';
  if (code === 'AUTH_RATE_LIMITED' || status === 429) return '요청이 많습니다. 잠시 후 다시 시도해 주세요.';
  if (code === 'ORIGIN_NOT_ALLOWED' || code === 'CSRF_FAILED') return '보안 확인에 실패했습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.';
  if (code === 'UNAUTHORIZED' || status === 401) return '로그인 세션이 만료되었습니다. 다시 로그인해 주세요.';
  if (code === 'NOTE_NOT_FOUND') return '메모를 찾을 수 없거나 접근할 수 없습니다.';
  if (code === 'DEVICE_NOT_APPROVED') return '기기 승인이 확인되지 않아 보호 화면을 닫았습니다.';
  if (code === 'INVALID_NOTE' || code === 'INVALID_NOTE_ID') return '입력한 메모 정보를 확인해 주세요.';
  return fallback;
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function getSession() {
  if (!sessionFlight) {
    sessionFlight = (async () => {
      let response;
      try {
        response = await fetch('/api/auth/session', {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
        });
      } catch {
        throw new Error('로그인 상태를 확인하지 못했습니다. 연결을 확인해 주세요.');
      }
      const data = await readJson(response);
      if (!response.ok || typeof data.authenticated !== 'boolean'
          || typeof data.csrfToken !== 'string') {
        throw new Error(messageForFailure(data.error, response.status,
          '로그인 상태를 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.'));
      }
      csrfToken = data.csrfToken;
      sessionRevision += 1;
      const user = data.authenticated && data.user
        && typeof data.user.id === 'string'
        ? data.user
        : null;
      renderAuthState(user);
      return user;
    })().finally(() => {
      sessionFlight = null;
    });
  }
  return sessionFlight;
}

async function authRequest(path, body) {
  if (!csrfToken) await getSession();
  let response;
  try {
    response = await fetch(path, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error('인증 서버에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.');
  }
  const data = await readJson(response);
  if (!response.ok) {
    if (data.error === 'DEVICE_NOT_APPROVED') refreshDeviceApprovalAfterDenial();
    throw new Error(messageForFailure(data.error, response.status,
      '요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.'));
  }
  return data;
}

async function getDeviceAssertion(purpose, binding) {
  const challenge = await authRequest('/api/device/challenge', { purpose, ...binding });
  if (!challenge.challengeId || !challenge.options) {
    const error = new Error('기기 승인이 확인되지 않았습니다.');
    error.code = 'DEVICE_NOT_APPROVED';
    throw error;
  }
  const credential = await navigator.credentials.get({
    publicKey: decodeAuthenticationOptions(challenge.options),
  });
  if (!credential) throw new Error('기기 확인이 취소되었습니다.');
  return { challengeId: challenge.challengeId, response: serializeCredential(credential) };
}

async function notesRequest(path, options = {}, retryAfterRefresh = true) {
  if (!deviceApproval.isApproved()) {
    throw new Error('기기 승인 상태를 확인할 수 없어 보호 메모를 열지 않았습니다.');
  }
  const requestRevision = sessionRevision;
  const method = options.method ?? 'GET';
  const hasBody = options.body !== undefined;
  let boundBody;
  if (hasBody) {
    try {
      boundBody = JSON.parse(options.body);
    } catch {
      throw new Error('요청 본문을 서명할 수 없습니다.');
    }
  }
  const requestBinding = await createHttpRequestBinding({
    method,
    target: path,
    body: boundBody,
    hasBody,
  });
  let deviceAssertion;
  try {
    deviceAssertion = await getDeviceAssertion('notes', {
      method: requestBinding.method,
      target: requestBinding.target,
      hasBody,
      ...(hasBody ? { body: boundBody } : {}),
    });
  } catch (error) {
    if (error.code === 'DEVICE_NOT_APPROVED') refreshDeviceApprovalAfterDenial();
    throw error;
  }
  const headers = {};
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  headers['X-Device-Assertion'] = JSON.stringify(deviceAssertion);
  let response;
  try {
    response = await fetch(path, {
      ...options,
      method,
      cache: 'no-store',
      credentials: 'same-origin',
      headers,
    });
  } catch {
    throw new Error('자료 서버에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.');
  }
  if (response.status === 401 && retryAfterRefresh) {
    const user = requestRevision === sessionRevision
      ? await getSession()
      : activeUser;
    if (user) return notesRequest(path, options, false);
    renderAuthState(null);
  }
  const data = await readJson(response);
  if (!response.ok) {
    throw new Error(messageForFailure(data.error, response.status,
      '메모 요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.'));
  }
  return data;
}

async function loadNotes(isApprovalCurrent = () => true) {
  if (!activeUser || !deviceApproval.isApproved()) {
    clearProtectedUi();
    return;
  }
  const userId = activeUser.id;
  const revision = sessionRevision;
  const isCurrent = () => isApprovalCurrent()
    && deviceApproval.isApproved()
    && activeUser?.id === userId
    && sessionRevision === revision;

  try {
    const data = await notesRequest('/api/notes');
    if (!isCurrent()) return;
    if (!Array.isArray(data.notes)) throw new Error('자료 형식이 맞지 않습니다.');
    notesList.replaceChildren(...data.notes.map(note => {
      const item = document.createElement('li');
      const title = document.createElement('strong');
      const content = document.createElement('span');
      const actions = document.createElement('div');
      const editButton = document.createElement('button');
      const deleteButton = document.createElement('button');
      title.textContent = note.title;
      content.textContent = note.body;
      actions.className = 'note-actions';
      editButton.type = 'button';
      editButton.textContent = '수정';
      editButton.addEventListener('click', () => {
        editingNoteId = note.id;
        noteTitle.value = note.title;
        noteBody.value = note.body;
        noteSubmit.textContent = '수정 저장';
        noteCancel.hidden = false;
        noteError.hidden = true;
        noteTitle.focus();
      });
      deleteButton.type = 'button';
      deleteButton.className = 'delete-button';
      deleteButton.textContent = '삭제';
      deleteButton.addEventListener('click', async () => {
        deleteButton.disabled = true;
        noteError.hidden = true;
        try {
          await notesRequest(`/api/notes/${encodeURIComponent(note.id)}`, {
            method: 'DELETE',
          });
          await loadNotes();
        } catch (error) {
          showNoteError(error.message || '메모를 삭제하지 못했습니다.');
          deleteButton.disabled = false;
        }
      });
      actions.append(editButton, deleteButton);
      item.append(title, content, actions);
      return item;
    }));
    noteError.hidden = true;
  } catch (error) {
    if (isCurrent()) {
      const item = document.createElement('li');
      item.textContent = error.message || '메모를 불러오지 못했습니다.';
      notesList.replaceChildren(item);
    }
  }
}

function showNoteError(message) {
  noteError.textContent = message;
  noteError.hidden = false;
}

noteForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!activeUser) return;
  noteSubmit.disabled = true;
  noteError.hidden = true;
  const isEditing = editingNoteId !== null;
  const path = isEditing
    ? `/api/notes/${encodeURIComponent(editingNoteId)}`
    : '/api/notes';
  try {
    await notesRequest(path, {
      method: isEditing ? 'PUT' : 'POST',
      body: JSON.stringify({ title: noteTitle.value, body: noteBody.value }),
    });
    editingNoteId = null;
    noteForm.reset();
    noteSubmit.textContent = '메모 추가';
    noteCancel.hidden = true;
    await loadNotes();
  } catch (error) {
    showNoteError(error.message || '메모를 저장하지 못했습니다.');
  } finally {
    noteSubmit.disabled = false;
  }
});

noteCancel.addEventListener('click', () => {
  editingNoteId = null;
  noteForm.reset();
  noteSubmit.textContent = '메모 추가';
  noteCancel.hidden = true;
  noteError.hidden = true;
});

loginForm.addEventListener('submit', async event => {
  event.preventDefault();
  loginButton.disabled = true;
  loginError.hidden = true;
  try {
    const data = await authRequest('/api/auth/login', {
      email: loginEmail.value.trim(),
      password: loginPassword.value,
    });
    loginPassword.value = '';
    renderAuthState(data.user);
  } catch (error) {
    loginError.textContent = error.message || '로그인하지 못했습니다. 입력을 확인해 주세요.';
    loginError.hidden = false;
  } finally {
    loginButton.disabled = false;
  }
});

logoutButton.addEventListener('click', async () => {
  logoutButton.disabled = true;
  logoutError.hidden = true;
  try {
    await authRequest('/api/auth/logout', {});
    renderAuthState(null);
  } catch (error) {
    try {
      const user = await getSession();
      if (!user) renderAuthState(null);
    } catch {
      authStatus.textContent = '세션 상태를 확인하지 못했습니다.';
    }
    logoutError.textContent = error.message || '로그아웃 요청을 확인하지 못했습니다.';
    logoutError.hidden = false;
  } finally {
    logoutButton.disabled = false;
  }
});

getSession().then(() => {
  noteError.hidden = true;
}).catch(error => {
  deviceApproval.invalidate();
  activeUser = null;
  clearProtectedUi();
  authStatus.textContent = '로그인 상태를 확인하지 못했습니다.';
  loginForm.hidden = false;
  accountView.hidden = true;
  noteForm.hidden = true;
  authInitError.textContent = error.message || '페이지를 새로고침한 뒤 다시 시도해 주세요.';
  authInitError.hidden = false;
});
