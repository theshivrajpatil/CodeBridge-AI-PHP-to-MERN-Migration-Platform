import { HttpError } from '../lib/httpError.js';

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
