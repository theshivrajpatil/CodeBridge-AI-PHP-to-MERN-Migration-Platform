import { HttpError, notImplemented } from '../lib/httpError.js';
import { User } from '../models/User.js';
import bcrypt from 'bcryptjs';
import { issueToken } from '../lib/tokens.js';
import { AccessToken } from '../models/AccessToken.js';
import { pick } from '../lib/pick.js';
import { env } from '../config/env.js';

export const AuthController = {
  async login(req, res) {
    const user = await User.findOne({ email: req.valid.email }).select('+password');
    const ok = user ? await bcrypt.compare(req.valid.password, user.password) : false;
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    const token = await issueToken(user);
    return res.json({ token });
  },
  async logout(req, res) {
    await AccessToken.deleteOne({ jti: req.auth.jti });
    return res.status(204).send();
  },
  async register(req, res) {
    const user = await User.create(pick({ ...req.valid, password: await bcrypt.hash(req.valid.password, env.BCRYPT_ROUNDS) }, User.fillable));
    const token = await issueToken(user);
    return res.status(201).json({ user: user.toJSON(), token });
  },
};
