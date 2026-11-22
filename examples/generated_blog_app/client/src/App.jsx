import { useState } from 'react';
import { useAuth } from './auth/AuthContext.jsx';
import * as api from './api/endpoints.js';

export default function App() {
  const { isAuthenticated, signIn, signOut } = useAuth();
  const [form, setForm] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const login = api.post_api_login;
  async function submit(event) {
    event.preventDefault();
    try { const { token } = await login(form); signIn(token); setError(''); }
    catch (e) { setError(e.message); }
  }
  if (!isAuthenticated) {
    return login ? (
      <form onSubmit={submit}>
        <h1>Sign in</h1>
        <input type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input type="password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button type="submit">Sign in</button>
        {error && <p role="alert">{error}</p>}
      </form>
    ) : <p>No login endpoint was generated; see MIGRATION_REPORT.md.</p>;
  }
  return <div><h1>blog</h1><button onClick={signOut}>Sign out</button><p>API client functions: {Object.keys(api).join(', ')}</p></div>;
}
