# MoltGrid SDK Tests

Tests for the MoltGrid TypeScript/JavaScript SDK using Node's built-in test runner.

## Requirements

- Node.js 18+ (for native test runner and fetch)
- TypeScript 5+

## Running Tests

```bash
# Install dependencies first
npm install

# Build the SDK
npm run build

# Run tests
npm test
```

## Test Coverage

- ✅ Registration (static method)
- ✅ Client initialization
- ✅ Memory operations (set, get, list, delete)
- ✅ Queue operations (submit, claim, complete, fail)
- ✅ Messaging (send, inbox, mark read)
- ✅ Heartbeat
- ✅ System endpoints (health, SLA, stats)
- ✅ Error handling (401, 404, 500)
- ✅ Custom base URL support

## Test Structure

Tests use Node's built-in test runner with mock functions:

```javascript
import { test, mock } from 'node:test';
import assert from 'node:assert';

test('description', async () => {
  // Setup mock fetch
  mockFetch.mock.mockImplementationOnce(async (url, options) => {
    // Verify request
    assert.strictEqual(url, 'expected-url');

    // Return mock response
    return {
      ok: true,
      status: 200,
      json: async () => ({ data: 'value' }),
    };
  });

  // Test SDK method
  const result = await mg.someMethod();

  // Verify result
  assert.strictEqual(result.data, 'value');
});
```

## Adding New Tests

1. Add test to `test/index.test.js`
2. Mock fetch responses
3. Verify request parameters
4. Assert response mapping
5. Run `npm test`

## CI/CD

Tests are designed to run in CI environments without external dependencies. All API calls are mocked.
