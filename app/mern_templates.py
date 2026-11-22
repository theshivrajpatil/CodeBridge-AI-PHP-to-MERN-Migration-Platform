"""Static, reviewed templates for generated MERN projects (no project data is interpolated here)."""

ENV_JS = r'''import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  MONGODB_URI: z.string().min(1),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_EXPIRES_IN_SECONDS: z.coerce.number().int().positive().default(3600),
  CORS_ORIGINS: z.string().default(''),
  BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(15).default(12),
  TRUST_PROXY: z.enum(['true', 'false']).default('false'),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}
export const env = parsed.data;
'''

STATIC_SERVER = {
"src/server.js": r'''import mongoose from 'mongoose';
import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './lib/logger.js';

await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
const server = createApp().listen(env.PORT, () => logger.info({ port: env.PORT }, 'server listening'));

async function shutdown(signal) {
  logger.info({ signal }, 'shutting down');
  server.close(async () => { await mongoose.disconnect(); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
''',
"src/app.js": r'''import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import limiter from 'express-rate-limit';
import { env } from './config/env.js';
import { apiRouter } from './routes/api.js';
import { errorHandler, notFound } from './middleware/errorHandler.js';
import { noSqlSanitize } from './middleware/noSqlSanitize.js';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', env.TRUST_PROXY === 'true' ? 1 : false);
  app.use(helmet());
  const origins = env.CORS_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean);
  app.use(cors({ origin: origins.length ? origins : false }));
  app.use(express.json({ limit: '100kb' }));
  app.use(noSqlSanitize);
  app.use(limiter({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  app.use('@@MOUNT@@', apiRouter);
  app.use(notFound);
  app.use(errorHandler);
  return app;
}
''',
"src/config/db.js": "export { default as mongoose } from 'mongoose';\n",
"src/lib/logger.js": r'''import pino from 'pino';
export const logger = pino({ level: process.env.LOG_LEVEL || 'info', redact: ['req.headers.authorization', 'password'] });
''',
"src/lib/httpError.js": r'''export class HttpError extends Error {
  constructor(status, message, errors) {
    super(message);
    this.status = status;
    this.errors = errors;
  }
}
export const notImplemented = (message) => new HttpError(501, message || 'Not implemented');
''',
"src/lib/asyncHandler.js": "export const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);\n",
"src/lib/pick.js": r'''export function pick(source, keys) {
  const out = {};
  for (const key of keys) if (Object.hasOwn(source, key)) out[key] = source[key];
  return out;
}
''',
"src/lib/paginate.js": r'''export async function paginate(query, req, perPage = 15) {
  const page = Math.max(1, Number.parseInt(String(req.query.page), 10) || 1);
  const total = await query.model.countDocuments(query.getFilter());
  const data = await query.skip((page - 1) * perPage).limit(perPage);
  const last = Math.max(1, Math.ceil(total / perPage));
  const url = (p) => `${req.baseUrl}${req.path}?page=${p}`;
  return {
    data,
    links: { first: url(1), last: url(last), prev: page > 1 ? url(page - 1) : null, next: page < last ? url(page + 1) : null },
    meta: { current_page: page, from: total ? (page - 1) * perPage + 1 : null, last_page: last, per_page: perPage,
            to: total ? Math.min(page * perPage, total) : null, total },
  };
}
''',
"src/lib/tokens.js": r'''import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { AccessToken } from '../models/AccessToken.js';

export async function issueToken(user) {
  const jti = crypto.randomUUID();
  const expires_at = new Date(Date.now() + env.JWT_EXPIRES_IN_SECONDS * 1000);
  await AccessToken.create({ jti, user_id: user._id, expires_at });
  return jwt.sign({}, env.JWT_SECRET, { algorithm: 'HS256', subject: String(user._id), jwtid: jti, expiresIn: env.JWT_EXPIRES_IN_SECONDS });
}
''',
"src/models/AccessToken.js": r'''import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  jti: { type: String, required: true, unique: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  expires_at: { type: Date, required: true },
});
schema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });
export const AccessToken = mongoose.model('AccessToken', schema);
''',
"src/middleware/authenticate.js": r'''import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { HttpError } from '../lib/httpError.js';
import { AccessToken } from '../models/AccessToken.js';
import { @@USER@@ } from '../models/@@USER@@.js';

export async function authenticate(req, _res, next) {
  try {
    const [scheme, token] = (req.headers.authorization || '').split(' ');
    if (scheme !== 'Bearer' || !token) throw new HttpError(401, 'Unauthenticated.');
    let payload;
    try { payload = jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }); }
    catch { throw new HttpError(401, 'Unauthenticated.'); }
    const record = await AccessToken.findOne({ jti: payload.jti, user_id: payload.sub });
    const user = record ? await @@USER@@.findById(payload.sub) : null;
    if (!user) throw new HttpError(401, 'Unauthenticated.');
    req.user = user;
    req.auth = { jti: payload.jti };
    next();
  } catch (error) { next(error); }
}
''',
"src/middleware/requireRole.js": r'''import { HttpError } from '../lib/httpError.js';
export const requireRole = (...roles) => (req, _res, next) =>
  (req.user && roles.includes(req.user.role) ? next() : next(new HttpError(403, 'This action is unauthorized.')));
''',
"src/middleware/rateLimit.js": r'''import limiter from 'express-rate-limit';
export const rateLimit = ({ max, windowMinutes }) =>
  limiter({ windowMs: windowMinutes * 60_000, limit: max, standardHeaders: true, legacyHeaders: false,
            message: { message: 'Too Many Attempts.' } });
''',
"src/middleware/validate.js": r'''import { HttpError } from '../lib/httpError.js';

export const validate = (schema, { confirmed = [] } = {}) => (req, _res, next) => {
  const result = schema.safeParse(req.body ?? {});
  const errors = {};
  const add = (key, message) => { (errors[key] ||= []).push(message); };
  if (!result.success) for (const issue of result.error.issues) add(issue.path.join('.') || '_', issue.message);
  else for (const field of confirmed) {
    if (result.data[field] !== result.data[`${field}_confirmation`]) add(`${field}_confirmation`, `The ${field} confirmation does not match.`);
  }
  if (Object.keys(errors).length) return next(new HttpError(422, 'The given data was invalid.', errors));
  req.valid = Object.fromEntries(Object.entries(result.data).filter(([k]) => !k.endsWith('_confirmation')));
  return next();
};
''',
"src/middleware/asyncChecks.js": r'''import { HttpError } from '../lib/httpError.js';

const fail = (field, message) => new HttpError(422, 'The given data was invalid.', { [field]: [message] });

export const unique = (model, column, field) => async (req, _res, next) => {
  try {
    const value = req.valid?.[field];
    if (value !== undefined && value !== null && typeof value !== 'object' && await model.exists({ [column]: value })) {
      return next(fail(field, `The ${field} has already been taken.`));
    }
    return next();
  } catch (error) { return next(error); }
};

export const exists = (model, column, field) => async (req, _res, next) => {
  try {
    const value = req.valid?.[field];
    if (value !== undefined && value !== null && typeof value !== 'object' && !(await model.exists({ [column]: value }))) {
      return next(fail(field, `The selected ${field} is invalid.`));
    }
    return next();
  } catch (error) { return next(error); }
};
''',
"src/middleware/bind.js": r'''import mongoose from 'mongoose';
import { HttpError } from '../lib/httpError.js';

export const bind = (param, model, fqcn) => async (req, _res, next) => {
  try {
    const id = req.params[param];
    const missing = new HttpError(404, `No query results for model [${fqcn}] ${String(id).slice(0, 64)}`);
    if (!mongoose.isValidObjectId(id)) throw missing;
    const doc = await model.findById(id);
    if (!doc) throw missing;
    (req.bound ||= {})[param] = doc;
    next();
  } catch (error) { next(error); }
};
''',
"src/middleware/noSqlSanitize.js": r'''function clean(value) {
  if (Array.isArray(value)) return value.forEach(clean);
  if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      if (key.startsWith('$') || key.includes('.')) delete value[key];
      else clean(value[key]);
    }
  }
  return undefined;
}
export function noSqlSanitize(req, _res, next) {
  clean(req.body);
  clean(req.params);
  next();
}
''',
"src/middleware/errorHandler.js": r'''import { HttpError } from '../lib/httpError.js';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';

export const notFound = (_req, _res, next) => next(new HttpError(404, 'Not Found'));

export function errorHandler(err, req, res, _next) {
  if (err instanceof HttpError) {
    const body = { message: err.message };
    if (err.errors) body.errors = err.errors;
    return res.status(err.status).json(body);
  }
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ message: 'Malformed JSON.' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ message: 'Payload too large.' });
  logger.error({ err, path: req.path }, 'unhandled error');
  return res.status(500).json({ message: env.NODE_ENV === 'production' ? 'Server Error' : String(err?.message || err) });
}
''',
}

DOCKERFILE_SERVER = r'''# syntax=docker/dockerfile:1
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY src ./src
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "src/server.js"]
'''

COMPOSE = r'''# Secrets are never stored in this file: compose fails fast when they are not provided.
services:
  mongo:
    image: mongo:7
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER:?set MONGO_ROOT_USER}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD:?set MONGO_ROOT_PASSWORD}
    volumes: [mongo-data:/data/db]
    healthcheck:
      test: ["CMD", "mongosh", "--quiet", "--eval", "db.adminCommand('ping')"]
      interval: 15s
      timeout: 5s
      retries: 5
  server:
    build: ./server
    restart: unless-stopped
    depends_on:
      mongo: { condition: service_healthy }
    environment:
      NODE_ENV: production
      MONGODB_URI: mongodb://${MONGO_ROOT_USER}:${MONGO_ROOT_PASSWORD}@mongo:27017/@@DB@@?authSource=admin
      JWT_SECRET: ${JWT_SECRET:?set JWT_SECRET (min 32 chars)}
      CORS_ORIGINS: ${CORS_ORIGINS:-}
      TRUST_PROXY: "true"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
  client:
    build: ./client
    restart: unless-stopped
    depends_on: [server]
    ports: ["8080:8080"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
volumes:
  mongo-data:
'''

CLIENT_DOCKERFILE = r'''FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
'''

NGINX = r'''server {
  listen 8080;
  root /usr/share/nginx/html;
  add_header X-Content-Type-Options nosniff always;
  add_header X-Frame-Options DENY always;
  add_header Referrer-Policy no-referrer always;
  location @@MOUNT@@/ { proxy_pass http://server:3000; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; }
  location / { try_files $uri /index.html; }
}
'''

CI = r'''name: ci
on: [push, pull_request]
permissions: { contents: read }
jobs:
  server:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: server } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm, cache-dependency-path: server/package-lock.json }
      - run: npm ci
      - run: npm test
        env: { JWT_SECRET: "ci-only-secret-ci-only-secret-ci-only-0000", NODE_ENV: test, MONGODB_URI: "mongodb://unused" }
      - run: npm audit --omit=dev --audit-level=high
'''

SERVER_PACKAGE = {
    "name": "@@NAME@@-server", "version": "0.1.0", "private": True, "type": "module",
    "engines": {"node": ">=20"},
    "scripts": {"start": "node src/server.js", "dev": "node --watch src/server.js", "test": "node --test tests/"},
    "dependencies": {"bcryptjs": "^2.4.3", "cors": "^2.8.5", "dotenv": "^16.4.5", "express": "^4.21.0",
                     "express-rate-limit": "^7.4.0", "helmet": "^8.0.0", "jsonwebtoken": "^9.0.2",
                     "mongoose": "^8.7.0", "pino": "^9.4.0", "zod": "^3.23.8"},
    "devDependencies": {"mongodb-memory-server": "^10.0.0", "supertest": "^7.0.0"},
}
CLIENT_PACKAGE = {
    "name": "@@NAME@@-client", "version": "0.1.0", "private": True, "type": "module",
    "scripts": {"dev": "vite", "build": "vite build", "preview": "vite preview"},
    "dependencies": {"react": "^18.3.1", "react-dom": "^18.3.1", "react-router-dom": "^6.26.0"},
    "devDependencies": {"@vitejs/plugin-react": "^4.3.1", "vite": "^5.4.0"},
}

CLIENT_FILES = {
"index.html": '<!doctype html>\n<html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>'
              '<title>@@NAME@@</title></head><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>\n',
"vite.config.js": "import { defineConfig } from 'vite';\nimport react from '@vitejs/plugin-react';\n"
                  "export default defineConfig({ plugins: [react()], server: { proxy: { '@@MOUNT@@': 'http://localhost:3000' } } });\n",
"src/main.jsx": r'''import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App.jsx';
import { AuthProvider } from './auth/AuthContext.jsx';

createRoot(document.getElementById('root')).render(
  <React.StrictMode><BrowserRouter><AuthProvider><App /></AuthProvider></BrowserRouter></React.StrictMode>,
);
''',
"src/api/http.js": r'''const BASE = '@@MOUNT@@';
let token = sessionStorage.getItem('token');
export const setToken = (value) => { token = value; value ? sessionStorage.setItem('token', value) : sessionStorage.removeItem('token'); };
export const getToken = () => token;

export async function http(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw Object.assign(new Error(data?.message || response.statusText), { status: response.status, errors: data?.errors });
  return data;
}
''',
"src/auth/AuthContext.jsx": r'''import { createContext, useContext, useMemo, useState } from 'react';
import { getToken, setToken } from '../api/http.js';

const Ctx = createContext(null);
export function AuthProvider({ children }) {
  const [token, setLocal] = useState(getToken());
  const value = useMemo(() => ({
    isAuthenticated: Boolean(token),
    signIn: (t) => { setToken(t); setLocal(t); },
    signOut: () => { setToken(null); setLocal(null); },
  }), [token]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
export const useAuth = () => useContext(Ctx);
''',
}
