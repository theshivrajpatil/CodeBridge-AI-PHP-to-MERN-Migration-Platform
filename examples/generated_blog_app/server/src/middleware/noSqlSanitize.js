function clean(value) {
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
