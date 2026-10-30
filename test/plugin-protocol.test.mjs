import { test } from 'node:test';
import assert from 'node:assert/strict';
import { apply, Config } from '../lib/index.js';

const MOJIBAKE = '\u00e4\u00b8\u00ad\u00e6\u2013\u2021';

function setup(overrides = {}) {
  const handlers = new Map();
  const ctx = { on: (event, handler) => handlers.set(event, handler) };
  apply(ctx, Config({ mode: 'warn', ...overrides }));
  return {
    pre: handlers.get('tools/pre-execute'),
    post: handlers.get('tools/post-execute'),
  };
}

function execution(name, args, signal = new AbortController().signal) {
  return { name, arguments: args, agent: {}, signal };
}

const allow = async () => ({ kind: 'allow' });

for (const [command, contentKey] of [['create', 'file_text'], ['str_replace', 'new_str'], ['insert', 'new_str']]) {
  test(`latest str_replace_editor ${command} payload is intercepted`, async () => {
    const { pre } = setup();
    const args = { command, path: '/work/note.md', [contentKey]: MOJIBAKE };
    if (command === 'str_replace') args.old_str = 'old';
    if (command === 'insert') args.insert_line = 0;
    const decision = await pre(execution('str_replace_editor', args), allow);
    assert.equal(decision.kind, 'deny');
    assert.match(decision.reason, /note\.md/);
  });
}

test('editor repair scans new_str but not the garbled old_str', async () => {
  const { pre } = setup();
  const decision = await pre(execution('str_replace_editor', {
    command: 'str_replace',
    path: '/work/note.md',
    old_str: MOJIBAKE,
    new_str: '中文',
  }), allow);
  assert.equal(decision.kind, 'allow');
});

test('apply_patch intercepts added mojibake and reports the target path', async () => {
  const { pre } = setup();
  const input = `*** Begin Patch\n*** Add File: docs/note.md\n+${MOJIBAKE}\n*** End Patch`;
  const decision = await pre(execution('apply_patch', { input }), allow);
  assert.equal(decision.kind, 'deny');
  assert.match(decision.reason, /docs\/note\.md/);
});

test('apply_patch permits repairing mojibake because removed lines are not write payloads', async () => {
  const { pre } = setup();
  const input = `*** Begin Patch\n*** Update File: docs/note.md\n@@\n-${MOJIBAKE}\n+中文\n*** End Patch`;
  const decision = await pre(execution('apply_patch', { input }), allow);
  assert.equal(decision.kind, 'allow');
});

test('apply_patch honors excludePaths per operation', async () => {
  const { pre } = setup({ excludePaths: ['generated/*'] });
  const input = `*** Begin Patch\n*** Add File: generated/note.md\n+${MOJIBAKE}\n*** End Patch`;
  const decision = await pre(execution('apply_patch', { input }), allow);
  assert.equal(decision.kind, 'allow');
});

test('terminal_send scans text and permits an identical reviewed retry', async () => {
  const { pre } = setup();
  const exec = execution('terminal_send', { sessionId: 'pty-1', text: `printf '${MOJIBAKE}' > note.md` });
  assert.equal((await pre(exec, allow)).kind, 'deny');
  assert.equal((await pre(exec, allow)).kind, 'allow');
});

test('terminal_read mojibake output adds plugin context', async () => {
  const { post } = setup();
  const decision = await post(
    execution('terminal_read', { sessionId: 'pty-1' }),
    { isError: false, content: [{ type: 'text', text: MOJIBAKE }] },
    async () => ({ kind: 'accept' }),
  );
  assert.equal(decision.kind, 'accept');
  assert.equal(decision.additionalContexts.length, 1);
  assert.equal(decision.additionalContexts[0].source.kind, 'plugin');
});

test('aborted pre-execution does not call downstream', async () => {
  const { pre } = setup();
  const controller = new AbortController();
  controller.abort();
  let called = false;
  await assert.rejects(
    pre(execution('write', { file_path: 'note.md', content: 'clean' }, controller.signal), async () => {
      called = true;
      return { kind: 'allow' };
    }),
    { name: 'AbortError' },
  );
  assert.equal(called, false);
});

test('aborted post-execution stops after downstream settles', async () => {
  const { post } = setup();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(post(
    execution('terminal_read', { sessionId: 'pty-1' }, controller.signal),
    { isError: false, content: [{ type: 'text', text: MOJIBAKE }] },
    async () => ({ kind: 'accept' }),
  ), { name: 'AbortError' });
});

test('multi-file apply_patch permits one identical retry for the whole call', async () => {
  const { pre } = setup();
  const input = `*** Begin Patch
*** Add File: a.md
+${MOJIBAKE}
*** Add File: b.md
+${MOJIBAKE}
*** End Patch`;
  const exec = execution('apply_patch', { input });
  assert.equal((await pre(exec, allow)).kind, 'deny');
  assert.equal((await pre(exec, allow)).kind, 'allow');
});

test('apply_patch recognizes a whitespace-prefixed operation header', async () => {
  const { pre } = setup();
  const input = `*** Begin Patch
 *** Add File: docs/note.md
+${MOJIBAKE}
*** End Patch`;
  const decision = await pre(execution('apply_patch', { input }), allow);
  assert.equal(decision.kind, 'deny');
  assert.match(decision.reason, /docs\/note\.md/);
});

test('apply_patch keeps a space-prefixed header-looking line as update context', async () => {
  const { pre } = setup();
  const input = `*** Begin Patch
*** Update File: docs/note.md
@@
 *** Add File: fake.md
+${MOJIBAKE}
*** End Patch`;
  const decision = await pre(execution('apply_patch', { input }), allow);
  assert.equal(decision.kind, 'deny');
  assert.match(decision.reason, /docs\/note\.md/);
  assert.doesNotMatch(decision.reason, /fake\.md/);
});
