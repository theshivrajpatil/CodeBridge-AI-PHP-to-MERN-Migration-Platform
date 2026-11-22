import { HttpError } from '../lib/httpError.js';

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
