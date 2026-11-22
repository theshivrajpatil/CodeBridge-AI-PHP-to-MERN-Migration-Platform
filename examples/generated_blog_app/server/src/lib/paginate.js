export async function paginate(query, req, perPage = 15) {
  const page = Math.max(1, Number.parseInt(String(req.query.page), 10) || 1);
  const total = await query.model.countDocuments(query.getFilter());
  const data = await query.skip((page - 1) * perPage).limit(perPage);
  const last = Math.max(1, Math.ceil(total / perPage));
  const url = (p) => `${req.baseUrl}${req.path}?page=${p}`;
  return {
    data,
    links: { first: url(1), last: url(last), prev: page > 1 ? url(page - 1) : null, next: page < last ? url(page + 1) : null },
    meta: { current_page: page, from: total ? (page - 1) * perPage + 1 : null, last_page: last, per_page: perPage,
            to: total ? Math.min(page * perPage, total) : null, total },
  };
}
