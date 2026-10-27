import assert from 'node:assert/strict';
import { test } from 'node:test';

const userId = '30000000-0000-4000-8000-000000000001';
const noteId = '40000000-0000-4000-8000-000000000001';

test('authenticated notes API lists legacy and new notes without owner filtering', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  process.env.SUPABASE_URL = 'https://unit-test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-secret-placeholder';

  const notes = [
    { id: noteId, owner_id: null, title: '과제', content: '실습용 가상 과제 기록' },
    { id: '20000000-0000-4000-8000-000000000002', owner_id: null, title: '포트폴리오', content: '실습용 가상 포트폴리오 기록' },
    { id: '20000000-0000-4000-8000-000000000003', owner_id: null, title: '아침 리추얼', content: '실습용 가상 리추얼 기록' },
    { id: '20000000-0000-4000-8000-000000000004', owner_id: null, title: '훈련 행정 자료', content: '실습용 가상 행정 기록' },
  ];
  let deleted = false;
  const databaseCalls = [];
  globalThis.fetch = async (input, init) => {
    const url = new URL(input);
    const method = init?.method ?? 'GET';
    databaseCalls.push({ method, url });
    const idFilter = url.searchParams.get('id');
    let responseBody;
    let status = 200;

    if (method === 'GET') {
      if (idFilter) {
        responseBody = deleted || idFilter !== `eq.${noteId}` ? [] : [notes[0]];
      } else {
        assert.equal(url.searchParams.has('owner_id'), false);
        responseBody = notes.filter(item => !deleted || item.id !== noteId);
      }
    } else if (method === 'POST') {
      const inserted = JSON.parse(init.body);
      assert.match(inserted.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
      assert.equal(inserted.owner_id, userId);
      assert.equal(inserted.title, '새 제목');
      assert.equal(inserted.content, '새 내용');
      notes.push(inserted);
      status = 201;
      responseBody = { id: inserted.id };
    } else if (method === 'PATCH') {
      assert.equal(url.searchParams.has('owner_id'), false);
      const updated = JSON.parse(init.body);
      notes[0] = { ...notes[0], title: updated.title, content: updated.content };
      responseBody = [notes[0]];
    } else if (method === 'DELETE') {
      assert.equal(url.searchParams.has('owner_id'), false);
      deleted = true;
      responseBody = [{ id: noteId }];
    } else {
      assert.fail(`Unexpected database method: ${method}`);
    }

    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const { createNotesHandler } = await import('../api/notes.js');
    const handler = createNotesHandler({
      createVerifier: () => async authorization => {
        if (authorization === 'Bearer valid-student') return { kind: 'student', userId };
        if (authorization === 'Bearer judge') return { kind: 'judge', userId };
        return null;
      },
    });

    const invoke = async ({ method, id, authorization = 'Bearer valid-student', body } = {}) => {
      let statusCode;
      let responseBody;
      const headers = new Map();
      const url = id ? `/api/notes/${id}` : '/api/notes';
      await handler({
        method,
        url,
        query: id ? { id } : {},
        headers: authorization ? { authorization } : {},
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

    for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
      const response = await invoke({
        method,
        id: method === 'GET' || method === 'PUT' || method === 'DELETE' ? noteId : undefined,
        authorization: null,
      });
      assert.equal(response.statusCode, 401);
      assert.deepEqual(response.body, { error: 'UNAUTHORIZED' });
    }

    const list = await invoke({ method: 'GET' });
    assert.deepEqual(list.body, {
      notes: [
        { id: noteId, title: '과제', body: '실습용 가상 과제 기록' },
        { id: '20000000-0000-4000-8000-000000000002', title: '포트폴리오', body: '실습용 가상 포트폴리오 기록' },
        { id: '20000000-0000-4000-8000-000000000003', title: '아침 리추얼', body: '실습용 가상 리추얼 기록' },
        { id: '20000000-0000-4000-8000-000000000004', title: '훈련 행정 자료', body: '실습용 가상 행정 기록' },
      ],
    });
    assert.equal(list.body.notes.length, 4);

    const created = await invoke({
      method: 'POST',
      body: { title: '새 제목', body: '새 내용' },
    });
    assert.equal(created.statusCode, 201);
    assert.match(created.body.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
    const listAfterCreate = await invoke({ method: 'GET' });
    assert.equal(listAfterCreate.statusCode, 200);
    assert.equal(listAfterCreate.body.notes.length, 5);
    assert.deepEqual(listAfterCreate.body.notes.at(-1), {
      id: created.body.id,
      title: '새 제목',
      body: '새 내용',
    });

    const single = await invoke({ method: 'GET', id: noteId });
    assert.equal(single.statusCode, 200);
    assert.deepEqual(single.body, { id: noteId, title: '과제', body: '실습용 가상 과제 기록' });

    const updated = await invoke({
      method: 'PUT',
      id: noteId,
      body: { title: '수정 제목', body: '수정 내용' },
    });
    assert.equal(updated.statusCode, 200);
    assert.deepEqual(updated.body, { id: noteId, title: '수정 제목', body: '수정 내용' });

    const removed = await invoke({ method: 'DELETE', id: noteId });
    assert.equal(removed.statusCode, 200);
    assert.deepEqual(removed.body, { id: noteId });

    const missing = await invoke({ method: 'GET', id: noteId });
    assert.equal(missing.statusCode, 404);
    assert.deepEqual(missing.body, { error: 'NOTE_NOT_FOUND' });

    assert.equal(databaseCalls.filter(call => call.method === 'GET' && !call.url.searchParams.has('id'))
      .every(call => !call.url.searchParams.has('owner_id')), true);
    assert.equal(databaseCalls.filter(call => call.url.searchParams.has('id'))
      .every(call => !call.url.searchParams.has('owner_id')), true);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});
