import { HttpError } from '../lib/httpError.js';
export const requireRole = (...roles) => (req, _res, next) =>
  (req.user && roles.includes(req.user.role) ? next() : next(new HttpError(403, 'This action is unauthorized.')));
