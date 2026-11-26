
import crypto from "node:crypto";

export const MANAGERS = {
  "lionbridgerewards2026@gmail.com": "FOUNDER",
  "imizamomaquati88@gmail.com": "MANAGER QA",
  "thembelagwala@gmail.com": "MANAGER QA"
};

export function normalizeEmail(v){return String(v||"").trim().toLowerCase();}
export function validEmail(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);}
export function hashPassword(password){
  return crypto.createHash("sha256").update(String(password||"")).digest("hex");
}
async function pbkdf2(secret,salt){
  const k=await globalThis.crypto.subtle.importKey("raw",new TextEncoder().encode(String(secret||"")),"PBKDF2",false,["deriveBits"]);
  return Buffer.from(await globalThis.crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:100000},k,256)).toString("hex");
}
export async function hashSecret(secret){
  const salt=crypto.randomBytes(16);
  return `pbkdf2$100000$${salt.toString("hex")}$${await pbkdf2(secret,salt)}`;
}
// anything that is not the newest format gets upgraded the next time the person logs in
export function isLegacyHash(stored){return !String(stored||"").startsWith("pbkdf2$");}
function same(a,b){const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y);}
export async function verifySecret(secret,stored){
  stored=String(stored||"");
  if(stored.startsWith("pbkdf2$")){const [,,salt,h]=stored.split("$");return same(await pbkdf2(secret,Buffer.from(salt,"hex")),h);}
  if(stored.startsWith("scrypt$")){
    try{const [,salt,h]=stored.split("$");return same(crypto.scryptSync(String(secret||""),salt,32).toString("hex"),h);}catch(e){return false;}
  }
  return hashPassword(secret)===stored;
}
export function json(res,status,data){
  res.status(status).setHeader("Content-Type","application/json; charset=utf-8").setHeader("Cache-Control","no-store");
  return res.end(JSON.stringify(data));
}
export function bearer(req){
  const h=req.headers.authorization||"";
  return h.startsWith("Bearer ")?h.slice(7).trim():null;
}
export function now(){return new Date().toISOString();}
export function referralCode(){
  const chars="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s=""; for(let i=0;i<6;i++) s+=chars[crypto.randomInt(chars.length)];
  return "SOUTH-"+s;
}

// ---- TOTP (authenticator app codes), standard RFC 6238, no extra libraries ----
const B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function newTotpSecret(){
  const b=crypto.randomBytes(20);let bits="",out="";
  for(const x of b) bits+=x.toString(2).padStart(8,"0");
  for(let i=0;i<bits.length;i+=5) out+=B32[parseInt(bits.slice(i,i+5),2)];
  return out;
}
function b32dec(s){
  let bits="";for(const c of String(s).toUpperCase()){const v=B32.indexOf(c);if(v>=0)bits+=v.toString(2).padStart(5,"0");}
  const out=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out);
}
export async function totpAt(secret,step){
  const key=await globalThis.crypto.subtle.importKey("raw",b32dec(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const msg=new ArrayBuffer(8),dv=new DataView(msg);dv.setUint32(0,Math.floor(step/4294967296));dv.setUint32(4,step>>>0);
  const h=new Uint8Array(await globalThis.crypto.subtle.sign("HMAC",key,msg)),o=h[19]&15;
  const n=(((h[o]&0x7f)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|h[o+3])%1000000;
  return String(n).padStart(6,"0");
}
// returns the matched time-step (so a code can't be used twice), or 0 if wrong
export async function verifyTotp(secret,code,lastStep=0){
  const c=String(code||"").replace(/\s/g,"");if(!/^\d{6}$/.test(c))return 0;
  const cur=Math.floor(Date.now()/30000);
  for(const d of [-1,0,1]){const s=cur+d;if(s>lastStep&&await totpAt(secret,s)===c)return s;}
  return 0;
}
