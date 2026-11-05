const BASE = '/backend';
export async function api<T=any>(path:string, options:RequestInit={}) : Promise<T> {
  const res = await fetch(`${BASE}${path}`, { ...options, credentials:'include', headers:{'Content-Type':'application/json', ...(options.headers||{})}, cache:'no-store' });
  const data = await res.json().catch(()=>({detail:'Unexpected server response'}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data as T;
}
