import mongoose from 'mongoose';
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
