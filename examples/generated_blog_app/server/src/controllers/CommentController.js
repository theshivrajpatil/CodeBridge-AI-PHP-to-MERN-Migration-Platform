import { HttpError, notImplemented } from '../lib/httpError.js';
import { Comment } from '../models/Comment.js';

export const CommentController = {
  async destroy(req, res) {
    if (String(req.bound.comment.user_id) !== String(req.user.id)) throw new HttpError(403, "This action is unauthorized.");
    await req.bound.comment.deleteOne();
    return res.status(204).send();
  },
  async index(req, res) {
    const docs = await Comment.find({ post_id: req.bound.post._id }).sort({ created_at: -1 });
    return res.json(docs.map((d) => d.toJSON()));
  },
  async store(req, res) {
    // CODEBRIDGE:STUB 5d841a7f7df5a513
    // reason: authorization rule for 'create' is unresolved (Laravel denies by default)
    // PHP source: app/Http/Controllers/CommentController.php:15
    throw notImplemented("Not implemented: authorization rule for 'create' is unresolved (Laravel denies by default)");
  },
};
