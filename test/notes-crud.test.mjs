import assert from 'node:assert/strict';
import { test } from 'node:test';

const userA = '30000000-0000-4000-8000-000000000001';
const userB = '30000000-0000-4000-8000-000000000002';
const noteA = '20000000-0000-4000-8000-000000000001';
const noteB = '50000000-0000-4000-8000-000000000001';

test('notes API enforces verified ownership for every CRUD operation', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  process.env.SUPABASE_URL = 'https://unit-test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-secret-placeholder';

  const notes = [
    { id: noteA, owner_id: userA, title: '과제', content: '가상 과제 기록' },
    { id: '20000000-0000-4000-8000-000000000002', owner_id: userA, title: '포트폴리오', content: '가상 포트폴리오 기록' },
    { id: '20000000-0000-4000-8000-000000000003', owner_id: userA, title: '아침 리추얼', content: '가상 리추얼 기록' },
    { id: '20000000-0000-4000-8000-000000000004', owner_id: userA, title: '훈련 행정 자료', content: '가상 행정 기록' },
    { id: noteB, owner_id: userB, title: 'B 계정 테스트 메모', content: '소유권 검증용 가상 자료' },
  ];
  const databaseCalls = [];
  globalThis.fetch = async (input, init) => {
    const url = new URL(input);
    const method = init?.method ?? 'GET';
    const ownerFilter = url.searchParams.get('owner_id');
    const idFilter = url.searchParams.get('id');
    databaseCalls.push({ method, url, body: init?.body });

    assert.equal(url.pathname, '/rest/v1/learning_notes');
    const id = idFilter?.slice(3);
    let rows;

    if (method === 'GET') {
      assert.equal(ownerFilter?.startsWith('eq.'), true);
      const ownerId = ownerFilter.slice(3);
      rows = notes.filter(note => note.owner_id === ownerId && (!id || note.id === id));
    } else if (method === 'POST') {
      assert.equal(ownerFilter, null);
      const inserted = JSON.parse(init.body);
      assert.deepEqual(Object.keys(inserted).sort(), ['content', 'id', 'owner_id', 'title']);
      assert.ok([userA, userB].includes(inserted.owner_id));
      notes.push(inserted);
      rows = [{ id: inserted.id }];
    } else if (method === 'PATCH') {
      assert.equal(ownerFilter?.startsWith('eq.'), true);
      const ownerId = ownerFilter.slice(3);
      const updated = JSON.parse(init.body);
      assert.deepEqual(Object.keys(updated).sort(), ['content', 'title']);
      rows = notes
        .filter(note => note.owner_id === ownerId && note.id === id)
        .map(note => {
          note.title = updated.title;
          note.content = updated.content;
          return note;
        });
      rows = rows.map(({ id: noteId, title, content }) => ({
        id: noteId,
        title,
        content,
      }));
    } else if (method === 'DELETE') {
      assert.equal(ownerFilter?.startsWith('eq.'), true);
      const ownerId = ownerFilter.slice(3);
      rows = [];
      for (let index = notes.length - 1; index >= 0; index -= 1) {
        if (notes[index].owner_id === ownerId && notes[index].id === id) {
          rows.push({ id: notes[index].id });
          notes.splice(index, 1);
        }
      }
    } else {
      assert.fail(`Unexpected database method: ${method}`);
    }

    return new Response(JSON.stringify(method === 'POST' ? rows[0] : rows), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const { createNotesHandler } = await import('../api/notes.js');
    const handler = createNotesHandler({
      createVerifier: () => async authorization => {
        if (authorization === 'Bearer test-user-a') return { kind: 'student', userId: userA };
        if (authorization === 'Bearer test-user-b') return { kind: 'student', userId: userB };
        return null;
      },
    });

    const invoke = async ({ method, user, id, body } = {}) => {
      let statusCode;
      let responseBody;
      const headers = new Map();
      await handler({
        method,
        url: id ? `/api/notes/${id}` : '/api/notes',
        query: id ? { id } : {},
        headers: user ? { authorization: `Bearer test-user-${user}` } : {},
        body,
      }, {
        setHeader: (name, value) => headers.set(name.toLowerCase(), value),
        status: value => {
          statusCode = value;
          return { json: value => { responseBody = value; } };
        },
      });
      return { statusCode, body: responseBody, headers };
    };

    const unauthenticated = await invoke({ method: 'GET' });
    assert.equal(unauthenticated.statusCode, 401);
    assert.deepEqual(unauthenticated.body, { error: 'UNAUTHORIZED' });
    assert.equal(databaseCalls.length, 0);

    const listA = await invoke({ method: 'GET', user: 'a' });
    assert.equal(listA.statusCode, 200);
    assert.equal(listA.body.notes.length, 4);
    assert.ok(listA.body.notes.every(note => note.id !== noteB));

    const listB = await invoke({ method: 'GET', user: 'b' });
    assert.equal(listB.statusCode, 200);
    assert.deepEqual(listB.body.notes, [{
      id: noteB,
      title: 'B 계정 테스트 메모',
      body: '소유권 검증용 가상 자료',
    }]);

    for (const user of ['a', 'b']) {
      const expectedOwner = user === 'a' ? userA : userB;
      const spoofedOwner = user === 'a' ? userB : userA;
      const created = await invoke({
        method: 'POST',
        user,
        body: {
          title: `${user.toUpperCase()} 새 메모`,
          body: '가상 테스트 내용',
          owner_id: spoofedOwner,
          user_id: spoofedOwner,
        },
      });
      assert.equal(created.statusCode, 201);
      const createdRow = notes.find(note => note.id === created.body.id);
      assert.equal(createdRow.owner_id, expectedOwner);

      const read = await invoke({ method: 'GET', user, id: created.body.id });
      assert.equal(read.statusCode, 200);
      assert.deepEqual(read.body, {
        id: created.body.id,
        title: `${user.toUpperCase()} 새 메모`,
        body: '가상 테스트 내용',
      });

      const updated = await invoke({
        method: 'PUT',
        user,
        id: created.body.id,
        body: {
          title: `${user.toUpperCase()} 수정 메모`,
          body: '수정된 가상 테스트 내용',
          owner_id: spoofedOwner,
          user_id: spoofedOwner,
        },
      });
      assert.equal(updated.statusCode, 200);
      assert.deepEqual(updated.body, {
        id: created.body.id,
        title: `${user.toUpperCase()} 수정 메모`,
        body: '수정된 가상 테스트 내용',
      });
      assert.equal(notes.find(note => note.id === created.body.id).owner_id, expectedOwner);

      const removed = await invoke({ method: 'DELETE', user, id: created.body.id });
      assert.equal(removed.statusCode, 200);
      assert.deepEqual(removed.body, { id: created.body.id });
    }

    for (const [user, otherNote] of [['a', noteB], ['b', noteA]]) {
      const read = await invoke({ method: 'GET', user, id: otherNote });
      assert.equal(read.statusCode, 404);
      assert.deepEqual(read.body, { error: 'NOTE_NOT_FOUND' });

      const updated = await invoke({
        method: 'PUT',
        user,
        id: otherNote,
        body: { title: '무단 수정 시도', body: '변경되면 안 됨' },
      });
      assert.equal(updated.statusCode, 404);
      assert.deepEqual(updated.body, { error: 'NOTE_NOT_FOUND' });

      const removed = await invoke({ method: 'DELETE', user, id: otherNote });
      assert.equal(removed.statusCode, 404);
      assert.deepEqual(removed.body, { error: 'NOTE_NOT_FOUND' });
    }

    assert.equal(notes.find(note => note.id === noteA).title, '과제');
    assert.equal(notes.find(note => note.id === noteB).title, 'B 계정 테스트 메모');
    assert.ok(databaseCalls
      .filter(({ method }) => method !== 'POST')
      .every(({ url }) => [`eq.${userA}`, `eq.${userB}`]
        .includes(url.searchParams.get('owner_id'))));
    assert.ok(databaseCalls.filter(({ method }) => method === 'PATCH' || method === 'DELETE')
      .every(({ url }) => url.searchParams.has('id') && url.searchParams.has('owner_id')));
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

test('notes API accepts cookie sessions only with matching origin and CSRF token', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  process.env.SUPABASE_URL = 'https://unit-test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-secret-placeholder';
  let databaseRequests = 0;
  globalThis.fetch = async input => {
    databaseRequests += 1;
    const url = new URL(input);
    assert.equal(url.pathname, '/rest/v1/learning_notes');
    assert.equal(url.searchParams.get('owner_id'), `eq.${userA}`);
    return new Response(JSON.stringify([{
      id: noteA,
      owner_id: userA,
      title: '기존 A 메모',
      content: '가상 테스트 자료',
    }]), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const { createNotesHandler } = await import('../api/notes.js');
    const handler = createNotesHandler({
      createVerifier: () => async authorization => (
        authorization === 'Bearer cookie-session-access'
          ? { kind: 'student', userId: userA }
          : null
      ),
    });
    const invoke = async headers => {
      let statusCode;
      let body;
      const responseHeaders = new Map();
      await handler({ method: 'GET', headers }, {
        setHeader: (name, value) => responseHeaders.set(name.toLowerCase(), value),
        status: value => {
          statusCode = value;
          return { json: valueBody => { body = valueBody; } };
        },
      });
      return { statusCode, body, headers: responseHeaders };
    };

    const csrfToken = 'b'.repeat(64);
    const cookie = `__Secure-aleph_access=cookie-session-access; __Secure-aleph_csrf=${csrfToken}`;
    const rejected = await invoke({
      cookie,
      origin: 'https://attacker.example',
      'x-csrf-token': csrfToken,
    });
    assert.equal(rejected.statusCode, 403);
    assert.equal(databaseRequests, 0);

    const accepted = await invoke({
      cookie,
      origin: 'https://choi-bujang-secret-vault-iota-three.vercel.app',
      'x-csrf-token': csrfToken,
    });
    assert.equal(accepted.statusCode, 200);
    assert.deepEqual(accepted.body.notes, [{
      id: noteA,
      title: '기존 A 메모',
      body: '가상 테스트 자료',
    }]);
    assert.equal(accepted.headers.get('cache-control'), 'no-store');
    assert.equal(databaseRequests, 1);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});
