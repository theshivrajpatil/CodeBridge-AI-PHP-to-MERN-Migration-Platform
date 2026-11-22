import bcrypt from 'bcryptjs';
import { User } from '../models/User.js';
import { issueToken } from '../lib/tokens.js';
export const AuthController = {
  async register(req, res) {
    const { name, email, password } = req.valid;
    const user = await User.create({ name, email, password: await bcrypt.hash(password, 12) });
    const token = await issueToken(user);
    return res.status(201).json({ user: user.toJSON(), token });
  },
};
