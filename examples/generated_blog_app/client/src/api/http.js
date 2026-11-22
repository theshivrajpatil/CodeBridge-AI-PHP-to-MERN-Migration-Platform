const BASE = '/api';
let token = sessionStorage.getItem('token');
export const setToken = (value) => { token = value; value ? sessionStorage.setItem('token', value) : sessionStorage.removeItem('token'); };
export const getToken = () => token;

export async function http(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw Object.assign(new Error(data?.message || response.statusText), { status: response.status, errors: data?.errors });
  return data;
}
