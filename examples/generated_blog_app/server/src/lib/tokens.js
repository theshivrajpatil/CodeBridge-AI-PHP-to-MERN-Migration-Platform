import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { AccessToken } from '../models/AccessToken.js';

export async function issueToken(user) {
  const jti = crypto.randomUUID();
  const expires_at = new Date(Date.now() + env.JWT_EXPIRES_IN_SECONDS * 1000);
  await AccessToken.create({ jti, user_id: user._id, expires_at });
  return jwt.sign({}, env.JWT_SECRET, { algorithm: 'HS256', subject: String(user._id), jwtid: jti, expiresIn: env.JWT_EXPIRES_IN_SECONDS });
}
