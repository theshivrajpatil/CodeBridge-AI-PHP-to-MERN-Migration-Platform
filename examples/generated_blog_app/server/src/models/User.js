import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  email_verified_at: { type: Date },
  password: { type: String, required: true, select: false },
  role: { type: String, default: "user" },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }, toJSON: { virtuals: false, transform: (_doc, ret) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.__v;
    delete ret.password;
    delete ret.remember_token;
    return ret;
  } } });
schema.virtual("posts", { ref: "Post", localField: "_id", foreignField: "user_id", justOne: false });

export const User = mongoose.models.User || mongoose.model("User", schema, "users");
User.fillable = ["name", "email", "password", "role"];
