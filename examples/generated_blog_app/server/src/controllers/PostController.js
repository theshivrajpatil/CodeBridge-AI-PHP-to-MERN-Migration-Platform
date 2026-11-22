import { HttpError, notImplemented } from '../lib/httpError.js';
import { Post } from '../models/Post.js';
import { PostResource } from '../resources/PostResource.js';
import { pick } from '../lib/pick.js';
import { paginate } from '../lib/paginate.js';

export const PostController = {
  async destroy(req, res) {
    if (!((String(req.bound.post.user_id) === String(req.user.id) || req.user.role === "admin"))) throw new HttpError(403, 'This action is unauthorized.');
    req.bound.post.deleted_at = new Date();
    await req.bound.post.save();
    return res.status(204).send();
  },
  async index(req, res) {
    const perPage = 15;
    const page = await paginate(Post.find({"status": "published"}).sort({ created_at: -1 }).populate(["user"]), req, perPage);
    return res.json({ data: page.data.map(PostResource), links: page.links, meta: page.meta });
  },
  async show(req, res) {
    await req.bound.post.populate(["user"]);
    return res.json({ data: PostResource(req.bound.post) });
  },
  async store(req, res) {
    const doc = await Post.create(pick({ ...req.valid, user_id: req.user.id }, Post.fillable));
    await doc.populate(["user"]);
    return res.status(201).json({ data: PostResource(doc) });
  },
  async update(req, res) {
    if (!(String(req.bound.post.user_id) === String(req.user.id))) throw new HttpError(403, 'This action is unauthorized.');
    const doc = req.bound.post;
    Object.assign(doc, pick({ ...req.valid }, Post.fillable));
    await doc.save();
    await doc.populate(["user"]);
    return res.json({ data: PostResource(doc) });
  },
};
