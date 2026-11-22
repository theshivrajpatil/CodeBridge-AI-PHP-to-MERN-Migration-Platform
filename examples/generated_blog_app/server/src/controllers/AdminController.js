import { HttpError, notImplemented } from '../lib/httpError.js';
import { Post } from '../models/Post.js';
import { User } from '../models/User.js';

export const AdminController = {
  async stats(req, res) {
    return res.json({ "users": await User.countDocuments(), "posts": await Post.countDocuments() });
  },
};
