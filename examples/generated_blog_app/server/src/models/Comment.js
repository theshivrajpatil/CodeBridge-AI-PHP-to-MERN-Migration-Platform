import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  post_id: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  body: { type: String, required: true },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }, toJSON: { virtuals: false, transform: (_doc, ret) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.__v;
    return ret;
  } } });
schema.virtual("post", { ref: "Post", localField: "post_id", foreignField: "_id", justOne: true });

export const Comment = mongoose.models.Comment || mongoose.model("Comment", schema, "comments");
Comment.fillable = ["body", "user_id", "post_id"];
