import { z } from 'zod';

const looseBoolean = z.union([z.boolean(), z.literal(1), z.literal(0), z.enum(['1', '0', 'true', 'false'])])
  .transform((v) => v === true || v === 1 || v === '1' || v === 'true');

export const s_ef0bdc66ae7c0379 = z.object({
  "email": z.string().email().min(1),
  "password": z.string().min(1),
});

export const s_5e43084daab6b08d = z.object({
  "title": z.string().min(1).max(255),
  "body": z.string().min(1),
  "status": z.enum(["draft", "published"]).nullish(),
  "tags": z.array(z.string().max(30)).max(10).optional(),
  "published_at": z.coerce.date().nullish(),
});

export const s_266a424a4a5a4ee8 = z.object({
  "title": z.string().max(255).optional(),
  "body": z.string().optional(),
  "status": z.enum(["draft", "published"]).optional(),
});

export const s_a15bc9c2d4e67e4e = z.object({
  "title": z.string().max(255).optional(),
  "body": z.string().optional(),
  "status": z.enum(["draft", "published"]).optional(),
});

export const s_2f889e03a78ea768 = z.object({
  "name": z.string().min(1).max(100),
  "email": z.string().email().min(1),
  "password": z.string().min(8),
  "password_confirmation": z.string(),
});
