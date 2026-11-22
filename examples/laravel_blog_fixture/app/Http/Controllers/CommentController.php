<?php
namespace App\Http\Controllers;

use App\Models\Comment;
use App\Models\Post;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function index(Post $post)
    {
        return response()->json($post->comments()->latest()->get());
    }

    public function store(Request $request, Post $post)
    {
        $data = $request->validate(['body' => 'required|string|max:2000']);
        $comment = $post->comments()->create($data + ['user_id' => $request->user()->id]);
        return response()->json($comment, 201);
    }

    public function destroy(Comment $comment)
    {
        if ($comment->user_id !== auth()->id()) {
            abort(403, 'Forbidden');
        }
        $comment->delete();
        return response()->noContent();
    }
}
