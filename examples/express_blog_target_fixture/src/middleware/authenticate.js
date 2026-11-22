import jwt from 'jsonwebtoken';
import { HttpError } from '../lib/httpError.js';
export function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return next(new HttpError(401, 'Unauthenticated.'));
  req.user = jwt.verify(token, process.env.JWT_SECRET);
  next();
}
export const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return next(new HttpError(403, 'This action is unauthorized.'));
  next();
};
