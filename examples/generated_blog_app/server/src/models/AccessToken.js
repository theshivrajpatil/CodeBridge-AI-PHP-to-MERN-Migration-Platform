import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  jti: { type: String, required: true, unique: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  expires_at: { type: Date, required: true },
});
schema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });
export const AccessToken = mongoose.model('AccessToken', schema);
