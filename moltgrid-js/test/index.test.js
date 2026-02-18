/**
 * MoltGrid SDK Tests
 *
 * Tests use Node's built-in test runner (Node 18+) with fetch mocking.
 * Run: node --test test/index.test.js
 */

import { test, mock } from 'node:test';
import assert from 'node:assert';

// Mock fetch globally
const originalFetch = global.fetch;
let mockFetch;

function setupMockFetch() {
  mockFetch = mock.fn(async (url, options) => {
    // Default mock response
    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'mocked' }),
    };
  });
  global.fetch = mockFetch;
}

function teardownMockFetch() {
  global.fetch = originalFetch;
}

// Import the SDK after setting up mocks
let MoltGrid, MoltGridError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Registration Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('MoltGrid.register - success', async () => {
  setupMockFetch();

  // Dynamic import after mock is set up
  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  MoltGridError = module.MoltGridError;

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/register');
    assert.strictEqual(options.method, 'POST');

    const body = JSON.parse(options.body);
    assert.strictEqual(body.name, 'test-agent');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        agent_id: 'agent_abc123',
        api_key: 'af_test_key',
        message: 'Agent registered successfully',
      }),
    };
  });

  const result = await MoltGrid.register({ name: 'test-agent' });

  assert.strictEqual(result.agentId, 'agent_abc123');
  assert.strictEqual(result.apiKey, 'af_test_key');
  assert.strictEqual(result.message, 'Agent registered successfully');

  teardownMockFetch();
});

test('MoltGrid.register - custom base URL', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.strictEqual(url, 'https://custom.example.com/v1/register');
    return {
      ok: true,
      status: 200,
      json: async () => ({
        agent_id: 'agent_xyz',
        api_key: 'af_custom',
        message: 'OK',
      }),
    };
  });

  await MoltGrid.register({ baseUrl: 'https://custom.example.com' });

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Client Initialization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('MoltGrid client - initialization', async () => {
  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;

  const mg = new MoltGrid({ apiKey: 'af_test' });
  assert.ok(mg);
});

test('MoltGrid client - custom base URL', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;

  const mg = new MoltGrid({
    apiKey: 'af_test',
    baseUrl: 'https://custom.example.com/',
  });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    // Verify trailing slash is removed
    assert.ok(url.startsWith('https://custom.example.com/v1'));
    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'ok' }),
    };
  });

  await mg.health();

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Memory Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('memorySet - basic', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/memory');
    assert.strictEqual(options.method, 'POST');
    assert.strictEqual(options.headers['X-API-Key'], 'af_test');
    assert.strictEqual(options.headers['Content-Type'], 'application/json');

    const body = JSON.parse(options.body);
    assert.strictEqual(body.key, 'mood');
    assert.strictEqual(body.value, 'bullish');
    assert.strictEqual(body.namespace, 'default');

    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'stored' }),
    };
  });

  await mg.memorySet('mood', 'bullish');

  teardownMockFetch();
});

test('memorySet - with TTL', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    const body = JSON.parse(options.body);
    assert.strictEqual(body.ttl_seconds, 3600);

    return {
      ok: true,
      status: 200,
      json: async () => ({}),
    };
  });

  await mg.memorySet('key', 'value', { ttlSeconds: 3600 });

  teardownMockFetch();
});

test('memoryGet - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.ok(url.includes('/v1/memory/mood'));
    assert.ok(url.includes('namespace=default'));
    assert.strictEqual(options.method, 'GET');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        key: 'mood',
        value: 'bullish',
        namespace: 'default',
        created_at: '2026-02-18T10:00:00Z',
      }),
    };
  });

  const entry = await mg.memoryGet('mood');

  assert.strictEqual(entry.key, 'mood');
  assert.strictEqual(entry.value, 'bullish');
  assert.strictEqual(entry.namespace, 'default');
  assert.strictEqual(entry.createdAt, '2026-02-18T10:00:00Z');

  teardownMockFetch();
});

test('memoryList - with prefix', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.ok(url.includes('prefix=config_'));
    return {
      ok: true,
      status: 200,
      json: async () => ({
        entries: [
          { key: 'config_a', value: '1', namespace: 'default', created_at: '2026-02-18T10:00:00Z' },
          { key: 'config_b', value: '2', namespace: 'default', created_at: '2026-02-18T10:00:00Z' },
        ],
      }),
    };
  });

  const result = await mg.memoryList('default', 'config_');

  assert.strictEqual(result.entries.length, 2);
  assert.strictEqual(result.entries[0].key, 'config_a');

  teardownMockFetch();
});

test('memoryDelete - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.ok(url.includes('/v1/memory/key'));
    assert.strictEqual(options.method, 'DELETE');

    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'deleted' }),
    };
  });

  await mg.memoryDelete('key');

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Queue Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('queueSubmit - with payload', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/queue/submit');
    assert.strictEqual(options.method, 'POST');

    const body = JSON.parse(options.body);
    assert.deepStrictEqual(body.payload, { action: 'email', to: 'user@example.com' });
    assert.strictEqual(body.priority, 5);
    assert.strictEqual(body.max_attempts, 1);

    return {
      ok: true,
      status: 200,
      json: async () => ({
        job_id: 'job_123',
        agent_id: 'agent_abc',
        queue_name: 'default',
        payload: { action: 'email', to: 'user@example.com' },
        priority: 5,
        status: 'pending',
        attempts: 0,
        max_attempts: 1,
        retry_delay_seconds: 0,
        created_at: '2026-02-18T10:00:00Z',
      }),
    };
  });

  const job = await mg.queueSubmit({ action: 'email', to: 'user@example.com' });

  assert.strictEqual(job.jobId, 'job_123');
  assert.strictEqual(job.status, 'pending');
  assert.deepStrictEqual(job.payload, { action: 'email', to: 'user@example.com' });

  teardownMockFetch();
});

test('queueClaim - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.ok(url.includes('queue_name=default'));
    assert.strictEqual(options.method, 'POST');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        job_id: 'job_123',
        agent_id: 'agent_abc',
        queue_name: 'default',
        payload: { task: 'test' },
        priority: 5,
        status: 'claimed',
        attempts: 1,
        max_attempts: 3,
        retry_delay_seconds: 0,
        created_at: '2026-02-18T10:00:00Z',
        claimed_at: '2026-02-18T10:01:00Z',
      }),
    };
  });

  const job = await mg.queueClaim('default');

  assert.strictEqual(job.jobId, 'job_123');
  assert.strictEqual(job.status, 'claimed');

  teardownMockFetch();
});

test('queueComplete - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.ok(url.includes('/v1/queue/job_123/complete'));
    assert.ok(url.includes('result=Done'));
    assert.strictEqual(options.method, 'POST');

    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'completed' }),
    };
  });

  await mg.queueComplete('job_123', 'Done');

  teardownMockFetch();
});

test('queueFail - retrying', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.ok(url.includes('/v1/queue/job_123/fail'));
    const body = JSON.parse(options.body);
    assert.strictEqual(body.reason, 'Connection timeout');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        status: 'retrying',
        attempts: 2,
        max_attempts: 3,
        next_retry_at: '2026-02-18T10:05:00Z',
      }),
    };
  });

  const result = await mg.queueFail('job_123', 'Connection timeout');

  assert.strictEqual(result.status, 'retrying');
  assert.strictEqual(result.attempts, 2);
  assert.strictEqual(result.nextRetryAt, '2026-02-18T10:05:00Z');

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Messaging Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('sendMessage - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/relay/send');
    const body = JSON.parse(options.body);
    assert.strictEqual(body.to_agent, 'agent_xyz');
    assert.strictEqual(body.payload, 'Hello!');
    assert.strictEqual(body.channel, 'default');

    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'sent' }),
    };
  });

  await mg.sendMessage('agent_xyz', 'Hello!');

  teardownMockFetch();
});

test('inbox - unread only', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.ok(url.includes('unread_only=true'));

    return {
      ok: true,
      status: 200,
      json: async () => ({
        messages: [
          {
            message_id: 'msg_1',
            from_agent: 'agent_xyz',
            to_agent: 'agent_abc',
            channel: 'default',
            payload: 'Hello',
            read: false,
            created_at: '2026-02-18T10:00:00Z',
          },
        ],
      }),
    };
  });

  const result = await mg.inbox();

  assert.strictEqual(result.messages.length, 1);
  assert.strictEqual(result.messages[0].messageId, 'msg_1');
  assert.strictEqual(result.messages[0].read, false);

  teardownMockFetch();
});

test('markRead - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.ok(url.includes('/v1/relay/msg_1/read'));
    assert.strictEqual(options.method, 'POST');

    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'marked as read' }),
    };
  });

  await mg.markRead('msg_1');

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Heartbeat Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('heartbeat - with metadata', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/agents/heartbeat');
    const body = JSON.parse(options.body);
    assert.strictEqual(body.status, 'busy');
    assert.deepStrictEqual(body.metadata, { cpu: 45, memory: 2048 });

    return {
      ok: true,
      status: 200,
      json: async () => ({ message: 'heartbeat received' }),
    };
  });

  await mg.heartbeat('busy', { cpu: 45, memory: 2048 });

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Error Handling Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('error handling - 401 unauthorized', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  MoltGridError = module.MoltGridError;
  const mg = new MoltGrid({ apiKey: 'invalid_key' });

  mockFetch.mock.mockImplementationOnce(async () => {
    return {
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ detail: 'Invalid API key' }),
    };
  });

  await assert.rejects(
    async () => await mg.health(),
    (error) => {
      assert.ok(error instanceof MoltGridError);
      assert.strictEqual(error.status, 401);
      assert.strictEqual(error.detail, 'Invalid API key');
      return true;
    }
  );

  teardownMockFetch();
});

test('error handling - 404 not found', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  MoltGridError = module.MoltGridError;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async () => {
    return {
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: async () => ({ detail: 'Agent not found' }),
    };
  });

  await assert.rejects(
    async () => await mg.memoryGet('nonexistent'),
    (error) => {
      assert.ok(error instanceof MoltGridError);
      assert.strictEqual(error.status, 404);
      return true;
    }
  );

  teardownMockFetch();
});

test('error handling - non-JSON response', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  MoltGridError = module.MoltGridError;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async () => {
    return {
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: async () => {
        throw new Error('Not JSON');
      },
    };
  });

  await assert.rejects(
    async () => await mg.health(),
    (error) => {
      assert.ok(error instanceof MoltGridError);
      assert.strictEqual(error.status, 500);
      assert.strictEqual(error.detail, 'Internal Server Error');
      return true;
    }
  );

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// System Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('health - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/health');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        status: 'healthy',
        version: '0.6.0',
        uptime: 123456,
        stats: {
          registered_agents: 10,
          total_jobs: 100,
          messages_relayed: 50,
        },
      }),
    };
  });

  const result = await mg.health();

  assert.strictEqual(result.status, 'healthy');
  assert.strictEqual(result.version, '0.6.0');
  assert.strictEqual(result.stats.registered_agents, 10);

  teardownMockFetch();
});

test('sla - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/sla');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        uptime_24h: 99.9,
        uptime_7d: 99.8,
        uptime_30d: 99.7,
        total_checks: 1000,
        failed_checks: 3,
        last_check: '2026-02-18T10:00:00Z',
      }),
    };
  });

  const result = await mg.sla();

  assert.strictEqual(result.uptime_30d, 99.7);
  assert.strictEqual(result.total_checks, 1000);

  teardownMockFetch();
});

test('stats - success', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({ apiKey: 'af_test' });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.strictEqual(url, 'https://api.moltgrid.net/v1/stats');

    return {
      ok: true,
      status: 200,
      json: async () => ({
        agent_id: 'agent_abc',
        api_calls_today: 50,
        api_calls_this_month: 1000,
        memory_used: 100,
        messages_received: 10,
        messages_sent: 20,
        jobs_submitted: 30,
        jobs_completed: 25,
        credits: 500,
      }),
    };
  });

  const result = await mg.stats();

  assert.strictEqual(result.agentId, 'agent_abc');
  assert.strictEqual(result.apiCallsToday, 50);
  assert.strictEqual(result.credits, 500);

  teardownMockFetch();
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Custom Base URL Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('custom base URL - with trailing slash', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({
    apiKey: 'af_test',
    baseUrl: 'https://custom.example.com/',
  });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    // Should strip trailing slash
    assert.strictEqual(url, 'https://custom.example.com/v1/health');

    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok', version: '0.6.0', uptime: 0 }),
    };
  });

  await mg.health();

  teardownMockFetch();
});

test('custom base URL - self-hosted', async () => {
  setupMockFetch();

  const module = await import('../dist/index.mjs');
  MoltGrid = module.MoltGrid;
  const mg = new MoltGrid({
    apiKey: 'af_test',
    baseUrl: 'http://localhost:8000',
  });

  mockFetch.mock.mockImplementationOnce(async (url) => {
    assert.strictEqual(url, 'http://localhost:8000/v1/health');

    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok', version: '0.6.0', uptime: 0 }),
    };
  });

  await mg.health();

  teardownMockFetch();
});
