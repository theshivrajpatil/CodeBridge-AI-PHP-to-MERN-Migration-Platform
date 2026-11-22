import { Post } from '../models/Post.js';
export const PostController = {
  async index(req, res) {
    const posts = await Post.find({ status: 'published' }).sort({ created_at: -1 }).limit(15);
    return res.json({ data: posts.map((p) => ({ id: p.id, title: p.title })), links: {}, meta: {} });
  },
  async store(req, res) {
    const post = await Post.create({ ...req.valid, user_id: req.user.id });
    return res.status(201).json({ data: { id: post.id, title: post.title } });
  },
  async destroy(req, res) {
    const post = await Post.findById(req.params.post);
    if (!post) return res.status(404).json({ message: 'Not found' });
    if (String(post.user_id) !== String(req.user.id)) return res.status(403).json({ message: 'This action is unauthorized.' });
    await post.deleteOne();
    return res.status(204).send();
  },
};
