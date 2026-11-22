import test from 'node:test';
import assert from 'node:assert/strict';
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET ??= 'test-only-secret-test-only-secret-0000';
process.env.MONGODB_URI ??= 'mongodb://127.0.0.1:1/unused';
const { createApp } = await import('../src/app.js');
const request = (await import('supertest')).default;
const app = createApp();

for (const [method, path] of [["GET", "/admin/stats"], ["DELETE", "/comments/000000000000000000000000"], ["POST", "/logout"], ["GET", "/posts"], ["POST", "/posts"], ["DELETE", "/posts/000000000000000000000000"], ["GET", "/posts/000000000000000000000000"], ["PATCH", "/posts/000000000000000000000000"], ["PUT", "/posts/000000000000000000000000"], ["GET", "/posts/000000000000000000000000/comments"], ["POST", "/posts/000000000000000000000000/comments"]]) {
  test(`${method} ${path} requires authentication`, async () => {
    const res = await request(app)[method.toLowerCase()]('/api' + path);
    assert.equal(res.status, 401);
  });
}
test('health endpoint is public', async () => assert.equal((await request(app).get('/healthz')).status, 200));
test('unknown routes return 404 JSON', async () => assert.equal((await request(app).get('/nope')).status, 404));
test('malformed JSON is rejected with 400', async () => {
  const res = await request(app).post('/healthz').set('Content-Type', 'application/json').send('{bad');
  assert.equal(res.status, 400);
});
