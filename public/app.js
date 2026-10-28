const authStatus = document.querySelector('#auth-status');
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

function renderAuthState(user) {
  activeUser = user;
  const signedIn = Boolean(user);
  authStatus.textContent = signedIn ? '로그인되었습니다.' : '로그인되어 있지 않습니다.';
  loginForm.hidden = signedIn;
  accountView.hidden = !signedIn;
  noteForm.hidden = !signedIn;
  accountEmail.textContent = user?.email ?? '';
  loginError.hidden = true;
  logoutError.hidden = true;
  authInitError.hidden = true;
  if (!signedIn) {
    editingNoteId = null;
    noteForm.reset();
    noteCancel.hidden = true;
    noteSubmit.textContent = '메모 추가';
    const item = document.createElement('li');
    item.textContent = '로그인하면 가상 자료를 확인할 수 있습니다.';
    notesList.replaceChildren(item);
  }
}

function messageForFailure(code, status, fallback) {
  if (code === 'INVALID_CREDENTIALS') return '이메일 또는 비밀번호를 확인해 주세요.';
  if (code === 'AUTH_RATE_LIMITED' || status === 429) return '요청이 많습니다. 잠시 후 다시 시도해 주세요.';
  if (code === 'ORIGIN_NOT_ALLOWED' || code === 'CSRF_FAILED') return '보안 확인에 실패했습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.';
  if (code === 'UNAUTHORIZED' || status === 401) return '로그인 세션이 만료되었습니다. 다시 로그인해 주세요.';
  if (code === 'NOTE_NOT_FOUND') return '메모를 찾을 수 없거나 접근할 수 없습니다.';
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
    throw new Error(messageForFailure(data.error, response.status,
      '요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.'));
  }
  return data;
}

async function notesRequest(path, options = {}, retryAfterRefresh = true) {
  const requestRevision = sessionRevision;
  const headers = {};
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  let response;
  try {
    response = await fetch(path, {
      ...options,
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

async function loadNotes() {
  if (!activeUser) return;
  try {
    const data = await notesRequest('/api/notes');
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
    if (activeUser) {
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
    await loadNotes();
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

getSession().then(user => {
  if (user) return loadNotes();
  noteError.hidden = true;
}).catch(error => {
  authStatus.textContent = '로그인 상태를 확인하지 못했습니다.';
  loginForm.hidden = false;
  accountView.hidden = true;
  noteForm.hidden = true;
  authInitError.textContent = error.message || '페이지를 새로고침한 뒤 다시 시도해 주세요.';
  authInitError.hidden = false;
});
