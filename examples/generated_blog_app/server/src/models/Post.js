import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  body: { type: String, required: true },
  status: { type: String, default: "draft" },
  tags: { type: mongoose.Schema.Types.Mixed },
  published_at: { type: Date },
  deleted_at: { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }, toJSON: { virtuals: false, transform: (_doc, ret) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.__v;
    return ret;
  } } });
schema.virtual("user", { ref: "User", localField: "user_id", foreignField: "_id", justOne: true });
schema.virtual("comments", { ref: "Comment", localField: "_id", foreignField: "post_id", justOne: false });
for (const hook of ['find', 'findOne', 'countDocuments', 'findOneAndUpdate']) {
  schema.pre(hook, function () { if (!this.getOptions().withTrashed) this.where({ deleted_at: null }); });
}

export const Post = mongoose.models.Post || mongoose.model("Post", schema, "posts");
Post.fillable = ["title", "body", "status", "tags", "published_at", "user_id"];
