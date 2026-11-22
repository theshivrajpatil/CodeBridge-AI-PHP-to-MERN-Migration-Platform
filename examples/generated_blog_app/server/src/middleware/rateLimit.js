import limiter from 'express-rate-limit';
export const rateLimit = ({ max, windowMinutes }) =>
  limiter({ windowMs: windowMinutes * 60_000, limit: max, standardHeaders: true, legacyHeaders: false,
            message: { message: 'Too Many Attempts.' } });
