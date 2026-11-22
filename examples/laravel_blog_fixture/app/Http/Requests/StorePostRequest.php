<?php
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StorePostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'title' => 'required|string|max:255',
            'body' => ['required', 'string'],
            'status' => 'nullable|in:draft,published',
            'tags' => 'array|max:10',
            'tags.*' => 'string|max:30',
            'published_at' => 'nullable|date',
        ];
    }
}
