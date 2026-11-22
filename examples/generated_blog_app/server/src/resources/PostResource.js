export function PostResource(doc) {
  return {
    "id": doc.id,
    "title": doc.title,
    "body": doc.body,
    "status": doc.status,
    "author": doc.user?.name ?? null,
    "created_at": doc.created_at,
  };
}
