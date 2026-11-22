import { z } from 'zod';
export const registerSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email().min(1),
  password: z.string().min(8),
});
export const storePost = z.object({
  title: z.string().min(1).max(255),
  body: z.string().min(1),
  status: z.enum(['draft', 'published']).nullish(),
  tags: z.array(z.string().max(30)).max(10).optional(),
});
