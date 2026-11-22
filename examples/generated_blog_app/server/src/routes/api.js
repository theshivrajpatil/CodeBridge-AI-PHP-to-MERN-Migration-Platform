import { Router } from 'express';
import { asyncHandler } from '../lib/asyncHandler.js';
import { authenticate } from '../middleware/authenticate.js';
import { requireRole } from '../middleware/requireRole.js';
import { rateLimit } from '../middleware/rateLimit.js';
import { validate } from '../middleware/validate.js';
import { bind } from '../middleware/bind.js';
import { unique, exists } from '../middleware/asyncChecks.js';
import * as schemas from '../validators/index.js';
import { Comment } from '../models/Comment.js';
import { Post } from '../models/Post.js';
import { User } from '../models/User.js';
import { AdminController } from '../controllers/AdminController.js';
import { AuthController } from '../controllers/AuthController.js';
import { CommentController } from '../controllers/CommentController.js';
import { PostController } from '../controllers/PostController.js';

export const router = Router();
export const apiRouter = router;

// route:35fbd0317366f4f6
router.get("/admin/stats", authenticate, requireRole("admin"), asyncHandler(AdminController.stats));
// route:49f027c6163ab6a1
router.delete("/comments/:comment", authenticate, bind("comment", Comment, "App\\Models\\Comment"), asyncHandler(CommentController.destroy));
// route:13c82f6834be2e90
router.get("/health", (req, res) => res.json({"status": "ok"}));
// route:ef0bdc66ae7c0379
router.post("/login", rateLimit({ max: 5, windowMinutes: 1 }), validate(schemas.s_ef0bdc66ae7c0379), asyncHandler(AuthController.login));
// route:f1552d0ff81e9d07
router.post("/logout", authenticate, asyncHandler(AuthController.logout));
// route:871bb9ec0ea5eed8
router.get("/posts", authenticate, asyncHandler(PostController.index));
// route:5e43084daab6b08d
router.post("/posts", authenticate, validate(schemas.s_5e43084daab6b08d), asyncHandler(PostController.store));
// route:6a0c7c8008639195
router.delete("/posts/:post", authenticate, bind("post", Post, "App\\Models\\Post"), asyncHandler(PostController.destroy));
// route:1379ad6618c3eb4d
router.get("/posts/:post", authenticate, bind("post", Post, "App\\Models\\Post"), asyncHandler(PostController.show));
// route:266a424a4a5a4ee8
router.patch("/posts/:post", authenticate, bind("post", Post, "App\\Models\\Post"), validate(schemas.s_266a424a4a5a4ee8), asyncHandler(PostController.update));
// route:a15bc9c2d4e67e4e
router.put("/posts/:post", authenticate, bind("post", Post, "App\\Models\\Post"), validate(schemas.s_a15bc9c2d4e67e4e), asyncHandler(PostController.update));
// route:4a691f01da0ebd53
router.get("/posts/:post/comments", authenticate, bind("post", Post, "App\\Models\\Post"), asyncHandler(CommentController.index));
// route:5d841a7f7df5a513
router.post("/posts/:post/comments", authenticate, asyncHandler(CommentController.store));
// route:2f889e03a78ea768
router.post("/register", validate(schemas.s_2f889e03a78ea768, { confirmed: ["password"] }), unique(User, "email", "email"), asyncHandler(AuthController.register));
