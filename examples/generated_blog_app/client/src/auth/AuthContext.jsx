import { createContext, useContext, useMemo, useState } from 'react';
import { getToken, setToken } from '../api/http.js';

const Ctx = createContext(null);
export function AuthProvider({ children }) {
  const [token, setLocal] = useState(getToken());
  const value = useMemo(() => ({
    isAuthenticated: Boolean(token),
    signIn: (t) => { setToken(t); setLocal(t); },
    signOut: () => { setToken(null); setLocal(null); },
  }), [token]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
export const useAuth = () => useContext(Ctx);
