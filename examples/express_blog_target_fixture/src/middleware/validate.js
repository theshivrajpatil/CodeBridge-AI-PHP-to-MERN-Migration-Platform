export const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) return res.status(422).json({ message: 'The given data was invalid.', errors: {} });
  req.valid = result.data;
  next();
};
