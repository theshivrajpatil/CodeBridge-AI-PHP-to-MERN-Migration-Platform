import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { HttpError } from '../lib/httpError.js';
import { AccessToken } from '../models/AccessToken.js';
import { User } from '../models/User.js';

export async function authenticate(req, _res, next) {
  try {
    const [scheme, token] = (req.headers.authorization || '').split(' ');
    if (scheme !== 'Bearer' || !token) throw new HttpError(401, 'Unauthenticated.');
    let payload;
    try { payload = jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }); }
    catch { throw new HttpError(401, 'Unauthenticated.'); }
    const record = await AccessToken.findOne({ jti: payload.jti, user_id: payload.sub });
    const user = record ? await User.findById(payload.sub) : null;
    if (!user) throw new HttpError(401, 'Unauthenticated.');
    req.user = user;
    req.auth = { jti: payload.jti };
    next();
  } catch (error) { next(error); }
}
