// D1 through the Cloudflare binding (env.DB): no internet hop, no API token needed.
let DB = null;
export function setDB(d){ DB = d; }
const clean = (p=[]) => p.map(x => x === undefined ? null : x);
const shape = r => ({ results: r.results || [], success: r.success !== false, meta: r.meta || {} });
export async function query(sql, params=[]){
  if(!DB) throw new Error("Database is not connected (binding DB).");
  return shape(await DB.prepare(sql).bind(...clean(params)).all());
}
export async function first(sql, params=[]){
  if(!DB) throw new Error("Database is not connected (binding DB).");
  return (await DB.prepare(sql).bind(...clean(params)).first()) || null;
}
export async function batch(statements){
  if(!DB) throw new Error("Database is not connected (binding DB).");
  const out = await DB.batch(statements.map(s => DB.prepare(s.sql).bind(...clean(s.params))));
  return out.map(shape);
}
