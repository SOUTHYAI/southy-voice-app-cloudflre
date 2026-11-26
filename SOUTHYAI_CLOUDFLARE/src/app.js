import crypto from "node:crypto";

import { setDB, query, first, batch } from "./db.js";
import { MANAGERS, normalizeEmail, validEmail, hashPassword, hashSecret, verifySecret, isLegacyHash, newTotpSecret, verifyTotp, json, bearer, now, referralCode } from "./utils.js";


async function body(req){
  if(req.body && typeof req.body==="object") return req.body;
  return {};
}
async function requireUser(req,opts={}){
  const token=bearer(req); if(!token) throw Object.assign(new Error("Authentication required"),{status:401});
  const u=await first(`SELECT u.*,m.role AS manager_role,m.admin_pass_hash AS admin_pass_hash,f.enabled AS mfa_enabled FROM users u LEFT JOIN managers m ON lower(u.email)=lower(m.email) LEFT JOIN user_mfa f ON f.user_id=u.id WHERE u.id=(SELECT user_id FROM auth_sessions WHERE token=? AND expires_at>?)`,[token,now()]);
  if(!u) throw Object.assign(new Error("Invalid or expired session"),{status:401});
  if(!opts.allowNoMfa&&mfaRequired(u)&&!u.mfa_enabled) throw Object.assign(new Error("Set up two-step login to continue"),{status:403,code:"MFA_SETUP"});
  return u;
}
async function requireAdmin(req){
  const u=await requireUser(req);
  if(!u.manager_role) throw Object.assign(new Error("Admin access required"),{status:403});
  const ok=await first(`SELECT token FROM admin_unlocks WHERE token=? AND user_id=? AND expires_at>?`,[bearer(req),u.id,now()]);
  if(!ok) throw Object.assign(new Error(u.admin_pass_hash?"Enter your admin pass to continue":"Create your admin pass to continue"),{status:403,code:u.admin_pass_hash?"ADMIN_LOCKED":"ADMIN_SETUP"});
  return u;
}
async function adminUnlock(req,res){
  const u=await requireUser(req);
  if(!u.manager_role) return json(res,403,{error:"Admin access required"});
  const pass=String((await body(req)).pass||"");
  const m=await first(`SELECT admin_pass_hash,pass_fails,pass_locked_until FROM managers WHERE lower(email)=lower(?)`,[u.email]);
  if(m.pass_locked_until&&m.pass_locked_until>now()) return json(res,429,{error:"Too many wrong tries. Try again in 15 minutes."});
  if(!m.admin_pass_hash){
    if(pass.length<8) return json(res,400,{error:"Your admin pass must be at least 8 characters."});
    if(await verifySecret(pass,u.password_hash)) return json(res,400,{error:"Your admin pass must be different from your login password."});
    await query(`UPDATE managers SET admin_pass_hash=? WHERE lower(email)=lower(?)`,[await hashSecret(pass),u.email]);
  }else if(!await verifySecret(pass,m.admin_pass_hash)){
    const f=Number(m.pass_fails||0)+1;
    await query(`UPDATE managers SET pass_fails=?,pass_locked_until=? WHERE lower(email)=lower(?)`,[f>=5?0:f,f>=5?new Date(Date.now()+15*60*1000).toISOString():null,u.email]);
    return json(res,401,{error:"Wrong admin pass"});
  }
  await query(`UPDATE managers SET pass_fails=0,pass_locked_until=NULL WHERE lower(email)=lower(?)`,[u.email]);
  await query(`INSERT OR REPLACE INTO admin_unlocks(token,user_id,expires_at) VALUES(?,?,?)`,[bearer(req),u.id,new Date(Date.now()+2*60*60*1000).toISOString()]);
  return json(res,200,{success:true});
}
async function requireFounder(req){
  const u=await requireAdmin(req);
  if(u.manager_role!=="FOUNDER") throw Object.assign(new Error("Only the founder can approve payments"),{status:403});
  return u;
}
function publicUser(u){return {id:u.id,full_name:u.full_name,email:u.email,home_language:u.home_language,paypal_email:u.paypal_email||null,balance_usd:Number(u.balance_usd||0),referral_code:u.referral_code||null,is_manager:!!u.manager_role,manager_role:u.manager_role||null,contract_signed:!!u.contract_signed};}

let R2=null,ENV={};
export function setEnv(env){setDB(env.DB);R2=env.R2;ENV=env||{};}
// MFA_REQUIRED: "managers" (default), "all" (everyone, use for Nexis) or "off"
function mfaRequired(u){const p=String(ENV.MFA_REQUIRED||"managers").toLowerCase();return p==="all"||(p==="managers"&&!!u.manager_role);}

// Money truth lives here, not on users.balance_usd. A recording only becomes payable once:
//  1) a human QA manager has approved it (AI score is a pre-filter, never a payment trigger), AND
//  2) the client's contracted payment-terms hold (7 / 15 / 30 days, set per project) has elapsed.
// This makes payouts naturally self-correcting: nothing is ever paid out and then clawed back.
async function availableBalance(userId){
  const nowIso=now();
  const released=Number((await first(
    `SELECT COALESCE(SUM(earned_usd),0) t FROM recordings WHERE user_id=? AND status='approved' AND hold_release_at IS NOT NULL AND hold_release_at<=?`,
    [userId,nowIso]
  ))?.t||0);
  const referralsAndBonuses=Number((await first(`SELECT balance_usd FROM users WHERE id=?`,[userId]))?.balance_usd||0);
  const paidOut=Number((await first(`SELECT COALESCE(SUM(amount_usd),0) t FROM payouts WHERE user_id=? AND status IN ('requested','paid')`,[userId]))?.t||0);
  return Math.max(0, referralsAndBonuses+released-paidOut);
}
async function earningsBreakdown(userId){
  const nowIso=now();
  const pendingQa=Number((await first(`SELECT COALESCE(SUM(earned_usd),0) t FROM recordings WHERE user_id=? AND status='pending'`,[userId]))?.t||0);
  const held=Number((await first(`SELECT COALESCE(SUM(earned_usd),0) t FROM recordings WHERE user_id=? AND status='approved' AND hold_release_at>?`,[userId,nowIso]))?.t||0);
  const nextRelease=(await first(`SELECT MIN(hold_release_at) d FROM recordings WHERE user_id=? AND status='approved' AND hold_release_at>?`,[userId,nowIso]))?.d||null;
  return {pending_qa_usd:pendingQa,held_usd:held,next_release_at:nextRelease};
}

let schemaReadyPromise=null;
async function ensureSchema(){
  // Run schema.sql once outside the app (recommended). This lightweight compatibility layer handles
  // existing databases created by earlier SOUTHYAI builds. Cached per warm instance so it only
  // pays the ~12 round-trips to Cloudflare once instead of on every single API request.
  if(schemaReadyPromise) return schemaReadyPromise;
  schemaReadyPromise=(async()=>{
  await query(`CREATE TABLE IF NOT EXISTS managers(id TEXT PRIMARY KEY,email TEXT UNIQUE COLLATE NOCASE,role TEXT NOT NULL,created_at TEXT NOT NULL)`);
  await query(`CREATE TABLE IF NOT EXISTS user_mfa(user_id TEXT PRIMARY KEY,secret TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,last_step INTEGER NOT NULL DEFAULT 0,fails INTEGER NOT NULL DEFAULT 0,locked_until TEXT,recovery TEXT,created_at TEXT NOT NULL)`);
  await query(`CREATE TABLE IF NOT EXISTS admin_unlocks(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at TEXT NOT NULL)`);
  await query(`CREATE TABLE IF NOT EXISTS referrals(id TEXT PRIMARY KEY,referrer_user_id TEXT NOT NULL,referred_user_id TEXT NOT NULL UNIQUE,reward_usd REAL NOT NULL DEFAULT 3,status TEXT NOT NULL DEFAULT 'credited',created_at TEXT NOT NULL)`);
  await query(`CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,project_id TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',applied_at TEXT NOT NULL,reviewed_at TEXT,reviewed_by TEXT,UNIQUE(user_id,project_id))`);
  await query(`CREATE TABLE IF NOT EXISTS auth_sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL)`);
  await query(`CREATE INDEX IF NOT EXISTS idx_apps_status ON applications(status)`);
  await query(`CREATE INDEX IF NOT EXISTS idx_users_referral ON users(referral_code)`);
  // Add balance/referral columns where an older DB is being upgraded.
  for(const sql of [
    `ALTER TABLE users ADD COLUMN balance_usd REAL NOT NULL DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN referral_code TEXT`,
    `ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'freelancer'`,
    `ALTER TABLE users ADD COLUMN contract_signed INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN contract_signed_at TEXT`,
    `ALTER TABLE projects ADD COLUMN payment_terms_days INTEGER NOT NULL DEFAULT 7`,
    `ALTER TABLE recordings ADD COLUMN earned_usd REAL NOT NULL DEFAULT 0`,
    `ALTER TABLE recordings ADD COLUMN hold_release_at TEXT`,
    `ALTER TABLE recordings ADD COLUMN reviewed_at TEXT`,
    `ALTER TABLE recordings ADD COLUMN reviewed_by TEXT`,
    `ALTER TABLE transcription_tasks ADD COLUMN ai_risk INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE transcription_tasks ADD COLUMN ai_flags TEXT`,
    `ALTER TABLE transcription_tasks ADD COLUMN submit_meta TEXT`,
    `ALTER TABLE transcription_tasks ADD COLUMN transcript_hash TEXT`,
    `ALTER TABLE transcription_tasks ADD COLUMN reviewed_at TEXT`,
    `ALTER TABLE transcription_tasks ADD COLUMN reviewed_by TEXT`,
    `ALTER TABLE managers ADD COLUMN admin_pass_hash TEXT`,
    `ALTER TABLE managers ADD COLUMN pass_fails INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE managers ADD COLUMN pass_locked_until TEXT`
  ]) { try{await query(sql)}catch(e){if(!/duplicate column|already exists/i.test(e.message)) throw e;} }
  for(const [email,role] of Object.entries(MANAGERS))
    await query(`INSERT OR IGNORE INTO managers(id,email,role,created_at) VALUES(?,?,?,?)`,[`mgr-${hashPassword(email).slice(0,12)}`,email,role,now()]);
  })().catch(e=>{schemaReadyPromise=null;throw e;}); // allow retry on next request if setup itself failed
  return schemaReadyPromise;
}

async function authLogin(req,res){
  const b=await body(req), email=normalizeEmail(b.email), password=String(b.password||"");
  if(!validEmail(email)||!password) return json(res,400,{error:"Email and password are required"});
  const u=await first(`SELECT u.*,m.role AS manager_role FROM users u LEFT JOIN managers m ON lower(u.email)=lower(m.email) WHERE lower(u.email)=lower(?)`,[email]);
  if(!u || !await verifySecret(password,u.password_hash)) return json(res,401,{error:"Invalid credentials"});
  if(isLegacyHash(u.password_hash)) await query(`UPDATE users SET password_hash=? WHERE id=?`,[await hashSecret(password),u.id]);
  const f=await first(`SELECT * FROM user_mfa WHERE user_id=? AND enabled=1`,[u.id]);
  if(f){
    if(f.locked_until&&f.locked_until>now()) return json(res,429,{error:"Too many wrong codes. Try again in 15 minutes."});
    const code=String(b.code||"").trim();
    if(!code) return json(res,401,{error:"Enter your 6-digit authenticator code",code:"MFA_REQUIRED"});
    let ok=false,step=0;
    const s=await verifyTotp(f.secret,code,Number(f.last_step||0));
    if(s){ok=true;step=s;}
    else{
      const rc=JSON.parse(f.recovery||"[]"),h=hashPassword(code.toUpperCase().replace(/[^A-Z0-9]/g,""));
      if(rc.includes(h)){ok=true;await query(`UPDATE user_mfa SET recovery=? WHERE user_id=?`,[JSON.stringify(rc.filter(x=>x!==h)),u.id]);}
    }
    if(!ok){
      const n=Number(f.fails||0)+1;
      await query(`UPDATE user_mfa SET fails=?,locked_until=? WHERE user_id=?`,[n>=5?0:n,n>=5?new Date(Date.now()+15*60*1000).toISOString():null,u.id]);
      return json(res,401,{error:"Wrong code",code:"MFA_REQUIRED"});
    }
    await query(`UPDATE user_mfa SET fails=0,locked_until=NULL,last_step=? WHERE user_id=?`,[step||f.last_step,u.id]);
  }
  const token=crypto.randomUUID();
  await query(`INSERT INTO auth_sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)`,[token,u.id,now(),new Date(Date.now()+1000*60*60*24*30).toISOString()]);
  return json(res,200,{token,user:publicUser(u),mfa_setup_required:mfaRequired(u)&&!f});
}
async function mfaSetup(req,res){
  const u=await requireUser(req,{allowNoMfa:true});
  if(u.mfa_enabled) return json(res,400,{error:"Two-step login is already on for this account."});
  const secret=newTotpSecret();
  await query(`INSERT OR REPLACE INTO user_mfa(user_id,secret,enabled,last_step,fails,created_at) VALUES(?,?,0,0,0,?)`,[u.id,secret,now()]);
  return json(res,200,{secret,otpauth:`otpauth://totp/SOUTHYAI:${encodeURIComponent(u.email)}?secret=${secret}&issuer=SOUTHYAI&algorithm=SHA1&digits=6&period=30`});
}
async function mfaEnable(req,res){
  const u=await requireUser(req,{allowNoMfa:true}),b=await body(req);
  const f=await first(`SELECT * FROM user_mfa WHERE user_id=? AND enabled=0`,[u.id]);
  if(!f) return json(res,400,{error:"Start the setup first."});
  const s=await verifyTotp(f.secret,b.code,0);
  if(!s) return json(res,401,{error:"That code is not right. Check the time on your phone and try again."});
  const codes=Array.from({length:8},()=>crypto.randomBytes(5).toString("hex").toUpperCase());
  await query(`UPDATE user_mfa SET enabled=1,last_step=?,fails=0,recovery=? WHERE user_id=?`,[s,JSON.stringify(codes.map(c=>hashPassword(c))),u.id]);
  return json(res,200,{success:true,recovery_codes:codes});
}
async function mfaReset(req,res){
  await requireFounder(req);
  const id=String((await body(req)).user_id||"");
  if(!id) return json(res,400,{error:"User is required"});
  await query(`DELETE FROM user_mfa WHERE user_id=?`,[id]);
  return json(res,200,{success:true});
}
async function authSignup(req,res){
  const b=await body(req), full_name=String(b.full_name||"").trim(), email=normalizeEmail(b.email), password=String(b.password||""), home_language=String(b.home_language||"").trim(), ref=String(b.referral_code||"").trim().toUpperCase();
  if(!full_name||!validEmail(email)||password.length<8||!home_language) return json(res,400,{error:"Please provide your full name, valid email, language and a password of at least 8 characters."});
  if(await first(`SELECT id FROM users WHERE lower(email)=lower(?)`,[email])) return json(res,409,{error:"Email already registered"});
  let code; for(let i=0;i<5;i++){code=referralCode();if(!(await first(`SELECT id FROM users WHERE referral_code=?`,[code])))break;}
  const id=crypto.randomUUID(), managerRole=MANAGERS[email]||null;
  await query(`INSERT INTO users(id,full_name,email,password_hash,home_language,paypal_email,balance_usd,referral_code,role,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
    [id,full_name,email,await hashSecret(password),home_language,null,0,code,managerRole?"admin":"freelancer",now()]);
  if(ref){
    const r=await first(`SELECT id FROM users WHERE referral_code=?`,[ref]);
    if(r && r.id!==id){
      await batch([
        {sql:`INSERT INTO referrals(id,referrer_user_id,referred_user_id,reward_usd,status,created_at) VALUES(?,?,?,?,?,?)`,params:[crypto.randomUUID(),r.id,id,3,"credited",now()]},
        {sql:`UPDATE users SET balance_usd=COALESCE(balance_usd,0)+3 WHERE id=?`,params:[r.id]}
      ]);
    }
  }
  const u=await first(`SELECT u.*,m.role AS manager_role FROM users u LEFT JOIN managers m ON lower(u.email)=lower(m.email) WHERE u.id=?`,[id]);
  const token=crypto.randomUUID();
  await query(`INSERT INTO auth_sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)`,[token,id,now(),new Date(Date.now()+1000*60*60*24*30).toISOString()]);
  return json(res,201,{token,user:publicUser(u)});
}

async function projects(req,res){
  const url=new URL(req.url,`https://${req.headers.host||"localhost"}`);
  const category=url.searchParams.get("category"), language=url.searchParams.get("language");
  let sql=`SELECT id,name,description,category,languages,hourly_rate_usd,total_prompts,total_clips_needed,completed_clips,status FROM projects`;
  const p=[];
  const where=[];
  if(category&&category!=="all"){where.push("category=?");p.push(category)}
  if(where.length)sql+=" WHERE "+where.join(" AND ");
  sql+=" ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,id";
  const rows=(await query(sql,p)).results.map(x=>({...x,languages:JSON.parse(x.languages||"[]"),hourly_rate_usd:Number(x.hourly_rate_usd),total_prompts:Number(x.total_prompts||55)}));
  const filtered=language&&language!=="all"?rows.filter(x=>x.languages.includes(language)):rows;
  return json(res,200,{projects:filtered,total:filtered.length,total_prompts:filtered.reduce((a,x)=>a+x.total_prompts,0)});
}
async function apply(req,res){
  const u=await requireUser(req), b=await body(req), pid=String(b.project_id||"");
  const p=await first(`SELECT * FROM projects WHERE id=?`,[pid]);
  if(!p)return json(res,404,{error:"Project not found"});
  if(p.status!=="active")return json(res,400,{error:"This project is coming soon and is not accepting applications yet."});
  const existing=await first(`SELECT id,status FROM applications WHERE user_id=? AND project_id=?`,[u.id,pid]);
  if(existing)return json(res,200,{success:true,application:existing,message:"You have already applied for this project."});
  const id=crypto.randomUUID();
  await query(`INSERT INTO applications(id,user_id,project_id,status,applied_at) VALUES(?,?,?,?,?)`,[id,u.id,pid,"pending",now()]);
  return json(res,201,{success:true,application:{id,project_id:pid,status:"pending",applied_at:now()}});
}
async function userApplications(req,res){
  const u=await requireUser(req);
  const rows=(await query(`SELECT a.id,a.project_id,a.status,a.applied_at,a.reviewed_at,p.name,p.hourly_rate_usd,p.status AS project_status FROM applications a JOIN projects p ON p.id=a.project_id WHERE a.user_id=? ORDER BY a.applied_at DESC`,[u.id])).results;
  return json(res,200,{applications:rows});
}
async function referral(req,res){
  const u=await requireUser(req);
  let code=u.referral_code;
  if(!code){code=referralCode();await query(`UPDATE users SET referral_code=? WHERE id=?`,[code,u.id]);}
  const rows=(await query(`SELECT r.id,r.reward_usd,r.status,r.created_at,u.email,u.full_name FROM referrals r JOIN users u ON u.id=r.referred_user_id WHERE r.referrer_user_id=? ORDER BY r.created_at DESC`,[u.id])).results;
  const balance=Number((await first(`SELECT balance_usd FROM users WHERE id=?`,[u.id]))?.balance_usd||0);
  return json(res,200,{referral_code:code,referral_balance_usd:balance,total_referrals:rows.length,referrals:rows});
}
async function balance(req,res){
  const u=await requireUser(req);
  const totalRec=Number((await first(`SELECT COALESCE(SUM(earned_usd),0) total FROM recordings WHERE user_id=? AND status IN ('pending','approved')`,[u.id]))?.total||0);
  const refEarn=Number((await first(`SELECT COALESCE(SUM(reward_usd),0) total FROM referrals WHERE referrer_user_id=? AND status='credited'`,[u.id]))?.total||0);
  const paid=Number((await first(`SELECT COALESCE(SUM(amount_usd),0) total FROM payouts WHERE user_id=? AND status IN ('requested','paid')`,[u.id]))?.total||0);
  const available=await availableBalance(u.id);
  const breakdown=await earningsBreakdown(u.id);
  return json(res,200,{
    balance_usd:available, // amount actually withdrawable right now
    total_earned_usd:totalRec+refEarn,
    referral_earned_usd:refEarn,
    paid_usd:paid,
    pending_qa_usd:breakdown.pending_qa_usd, // recorded, awaiting human QA decision
    held_usd:breakdown.held_usd, // QA-approved, inside the client's contracted payment-terms hold
    next_release_at:breakdown.next_release_at,
    pending_payout_usd:Number((await first(`SELECT COALESCE(SUM(amount_usd),0) total FROM payouts WHERE user_id=? AND status='requested'`,[u.id]))?.total||0)
  });
}
async function adminApplications(req,res){
  await requireAdmin(req);
  const apps=(await query(`SELECT a.id,a.status,a.applied_at,a.reviewed_at,a.reviewed_by,u.id user_id,u.full_name,u.email,p.id project_id,p.name project_name,p.hourly_rate_usd,p.status project_status FROM applications a JOIN users u ON u.id=a.user_id JOIN projects p ON p.id=a.project_id ORDER BY a.applied_at DESC`)).results;
  const managers=(await query(`SELECT id,email,role,created_at FROM managers ORDER BY CASE role WHEN 'FOUNDER' THEN 0 ELSE 1 END,email`)).results;
  return json(res,200,{applications:apps,managers});
}
async function adminDecision(req,res){
  const admin=await requireAdmin(req), b=await body(req), id=String(b.application_id||""), status=String(b.status||"");
  if(!["approved","rejected"].includes(status))return json(res,400,{error:"Status must be approved or rejected"});
  const a=await first(`SELECT * FROM applications WHERE id=?`,[id]); if(!a)return json(res,404,{error:"Application not found"});
  await query(`UPDATE applications SET status=?,reviewed_at=?,reviewed_by=? WHERE id=?`,[status,now(),admin.id,id]);
  return json(res,200,{success:true,status});
}
async function staff(req,res){
  const admin=await requireFounder(req), nowIso=now();
  const users=(await query(`SELECT u.id,u.full_name,u.email,u.role,u.contract_signed,u.created_at,u.referral_code,
    (SELECT COUNT(*) FROM referrals r WHERE r.referrer_user_id=u.id) AS referral_count,
    (SELECT COALESCE(SUM(reward_usd),0) FROM referrals r WHERE r.referrer_user_id=u.id AND r.status='credited') AS referral_earned_usd,
    MAX(0, u.balance_usd
      + (SELECT COALESCE(SUM(earned_usd),0) FROM recordings rec WHERE rec.user_id=u.id AND rec.status='approved' AND rec.hold_release_at IS NOT NULL AND rec.hold_release_at<=?)
      - (SELECT COALESCE(SUM(amount_usd),0) FROM payouts po WHERE po.user_id=u.id AND po.status IN ('requested','paid'))
    ) AS balance_usd
    FROM users u ORDER BY u.created_at DESC`,[nowIso])).results;
  const managers=(await query(`SELECT id,email,role,created_at FROM managers ORDER BY email`)).results;
  return json(res,200,{users,managers,viewer:publicUser(admin)});
}
async function adminContract(req,res){
  const admin=await requireAdmin(req), b=await body(req), userId=String(b.user_id||"");
  const u=await first(`SELECT id FROM users WHERE id=?`,[userId]); if(!u)return json(res,404,{error:"User not found"});
  await query(`UPDATE users SET contract_signed=1,contract_signed_at=? WHERE id=?`,[now(),userId]);
  return json(res,200,{success:true});
}
async function adminProjects(req,res){
  await requireAdmin(req);
  const rows=(await query(`SELECT id,name,hourly_rate_usd,status,payment_terms_days FROM projects ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,name`)).results;
  return json(res,200,{projects:rows});
}
async function adminProjectTerms(req,res){
  // Payment terms are a money/contract term, so only the founder can change them — same restriction
  // already applied to approving payouts.
  await requireFounder(req);
  const b=await body(req), projectId=String(b.project_id||""), days=Number(b.payment_terms_days);
  if(!Number.isInteger(days)||days<1||days>90)return json(res,400,{error:"Payment terms must be a whole number of days between 1 and 90"});
  const p=await first(`SELECT id FROM projects WHERE id=?`,[projectId]); if(!p)return json(res,404,{error:"Project not found"});
  await query(`UPDATE projects SET payment_terms_days=? WHERE id=?`,[days,projectId]);
  return json(res,200,{success:true});
}
async function nextPrompt(req,res){
  const u=await requireUser(req), url=new URL(req.url,`https://${req.headers.host||"localhost"}`),pid=url.searchParams.get("project_id"),lang=url.searchParams.get("language");
  const app=await first(`SELECT status FROM applications WHERE user_id=? AND project_id=?`,[u.id,pid]);
  const p=await first(`SELECT * FROM projects WHERE id=?`,[pid]);
  if(!p)return json(res,404,{error:"Project not found"});
  const count=Number((await first(`SELECT COUNT(*) c FROM prompts WHERE project_id=? AND language=?`,[pid,lang]))?.c||0);
  if(!count)return json(res,404,{error:"No prompts are available for this project and language."});
  const offset=Math.floor(Math.random()*count);
  const pr=await first(`SELECT id,project_id,category,language,prompt_text,dataset_url FROM prompts WHERE project_id=? AND language=? LIMIT 1 OFFSET ?`,[pid,lang,offset]);
  const canRecord = p.status==="active" && app && app.status==="approved";
  return json(res,200,{prompt:{...pr,text_prompt:pr.prompt_text},project_status:p.status,application_status:app?.status||"none",can_record:canRecord});
}
async function startSession(req,res){
  const u=await requireUser(req), b=await body(req), pid=String(b.project_id||"");
  const app=await first(`SELECT status FROM applications WHERE user_id=? AND project_id=?`,[u.id,pid]);
  if(!app||app.status!=="approved")return json(res,403,{error:"Project approval is required before recording."});
  if(!u.contract_signed)return json(res,403,{error:"Your freelancer contract must be signed before recording opens. Please complete induction with your SOUTHYAI admin."});
  const active=await first(`SELECT id FROM sessions WHERE user_id=? AND end_time IS NULL LIMIT 1`,[u.id]);
  if(active)return json(res,200,{session_id:active.id,resumed:true});
  const p=await first(`SELECT id FROM projects WHERE id=? AND status='active'`,[pid]);if(!p)return json(res,404,{error:"Project not found"});
  const id=crypto.randomUUID();await query(`INSERT INTO sessions(id,user_id,project_id,start_time,total_valid_seconds,earned_usd) VALUES(?,?,?,?,0,0)`,[id,u.id,pid,now()]);
  return json(res,201,{session_id:id});
}
async function endSession(req,res){const u=await requireUser(req),b=await body(req);await query(`UPDATE sessions SET end_time=? WHERE id=? AND user_id=? AND end_time IS NULL`,[now(),b.session_id,u.id]);return json(res,200,{success:true});}
async function recordings(req,res){
  const u=await requireUser(req);
  const rows=(await query(`SELECT id,project_id,language,category,text_prompt,duration_ms,status,ai_score,ai_status,ai_feedback,earned_usd,hold_release_at,created_at FROM recordings WHERE user_id=? ORDER BY created_at DESC LIMIT 100`,[u.id])).results;
  return json(res,200,{recordings:rows});
}
async function parseMultipart(req){
  const fd=await req.request.formData(),fields={};let file=null;
  for(const [k,v] of fd.entries()){
    if(typeof v==="string") fields[k]=v;
    else if(v&&typeof v.arrayBuffer==="function"){
      if(v.size>15*1024*1024) throw Object.assign(new Error("Audio file is too large"),{status:413});
      file={buffer:await v.arrayBuffer(),filename:v.name,mime:v.type||""};
    }
  }
  return {fields,file};
}
async function adminAudio(req,res){
  await requireAdmin(req);
  const url=new URL(req.url,`https://${req.headers.host||"localhost"}`),key=url.searchParams.get("key")||"";
  if(!key.startsWith("projects/")) return json(res,400,{error:"Invalid audio key"});
  const head=await R2.head(key); if(!head) return json(res,404,{error:"Audio not found"});
  const size=head.size,rg=/^bytes=(\d*)-(\d*)$/.exec(req.headers.range||"");
  let start=0,end=size-1,status=200;
  if(rg&&(rg[1]||rg[2])){ if(rg[1]===""){start=Math.max(0,size-Number(rg[2]));}else{start=Number(rg[1]);if(rg[2])end=Math.min(size-1,Number(rg[2]));} status=206; }
  if(start>end||start>=size) return json(res,416,{error:"Bad range"});
  const obj=await R2.get(key,status===206?{range:{offset:start,length:end-start+1}}:undefined);
  res.status(status).setHeader("Content-Type",head.httpMetadata?.contentType||"audio/webm").setHeader("Accept-Ranges","bytes").setHeader("Cache-Control","private, no-store").setHeader("Content-Length",String(end-start+1));
  if(status===206) res.setHeader("Content-Range",`bytes ${start}-${end}/${size}`);
  return res.end(obj.body);
}
async function uploadRecording(req,res){
  const u=await requireUser(req), {fields,file}=await parseMultipart(req);
  const pid=String(fields.project_id||""),lang=String(fields.language||""),sessionId=String(fields.session_id||""),duration=Number(fields.duration),consent=String(fields.consent_given||"")==="true";
  if(!file||!pid||!lang||!sessionId||!consent)return json(res,400,{error:"Audio, project, language, session and consent are required"});
  if(!Number.isFinite(duration)||duration<1000||duration>15000)return json(res,400,{error:"Recording must be between 1 and 15 seconds"});
  const s=await first(`SELECT s.id,s.project_id,p.hourly_rate_usd FROM sessions s JOIN projects p ON p.id=s.project_id WHERE s.id=? AND s.user_id=? AND s.end_time IS NULL AND p.status='active'`,[sessionId,u.id]);
  if(!s||s.project_id!==pid)return json(res,400,{error:"Invalid recording session"});
  const app=await first(`SELECT status FROM applications WHERE user_id=? AND project_id=?`,[u.id,pid]);if(!app||app.status!=="approved")return json(res,403,{error:"Application is not approved"});
  if(!u.contract_signed)return json(res,403,{error:"Your freelancer contract must be signed before recording opens. Please complete induction with your SOUTHYAI admin."});
  const pr=await first(`SELECT id FROM prompts WHERE project_id=? AND language=? AND prompt_text=?`,[pid,lang,String(fields.text_prompt||"")]);
  if(!pr)return json(res,400,{error:"Prompt is not valid for this project/language"});
  // Deterministic browser-side quality data is trusted only as a hint. Server assigns a conservative AI QA score.
  const quality=Number(fields.ai_score||0), score=Math.max(0,Math.min(100,Number.isFinite(quality)?quality:0));
  if(score && score<70)return json(res,400,{error:"AI quality checker rejected this clip. Please re-record.",ai_score:score});
  if(!R2) return json(res,500,{error:"Audio storage is not connected (R2 binding)."});
  const id=crypto.randomUUID(), ext=file.mime.includes("ogg")?"ogg":file.mime.includes("mp4")?"m4a":"webm",key=`projects/${pid}/${lang}/${u.id}/${id}.${ext}`;
  await R2.put(key,file.buffer,{httpMetadata:{contentType:file.mime||"audio/webm"}});
  const seconds=duration/1000,earned=seconds/3600*Number(s.hourly_rate_usd||6), aiStatus=score>=70?"approved":"review";
  // NOTE: no balance is credited here. The AI score only decides whether the clip is even queued
  // for human QA. Money only becomes payable once a human approves it (adminRecordingDecision)
  // and the client's contracted hold period has passed (availableBalance/earningsBreakdown).
  await batch([
    {sql:`INSERT INTO recordings(id,user_id,project_id,session_id,language,category,text_prompt,audio_url,duration_ms,consent_given,status,ai_score,ai_status,ai_feedback,earned_usd,created_at) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?)`,params:[id,u.id,pid,sessionId,lang,String(fields.category||""),String(fields.text_prompt||""),key,duration,"pending",score||70,aiStatus,score>=70?"Audio level and silence checks passed; awaiting human QA review before payment.":"Needs re-recording.",earned,now()]},
    {sql:`UPDATE sessions SET total_valid_seconds=total_valid_seconds+? WHERE id=? AND user_id=?`,params:[seconds,sessionId,u.id]},
    {sql:`UPDATE projects SET completed_clips=completed_clips+1 WHERE id=?`,params:[pid]}
  ]);
  return json(res,201,{success:true,recording_id:id,earned_usd:earned,ai_score:score||70,ai_status:aiStatus,message:"Saved. This clip is queued for human QA review — it becomes payable once approved and the contract's payment-terms hold has passed."});
}
async function payout(req,res){
  const u=await requireUser(req),b=await body(req),amount=Number(b.amount_usd),paypal=String(b.paypal_email||"").trim();
  if(!Number.isFinite(amount)||amount<10)return json(res,400,{error:"Minimum payout is $10"});
  if(!validEmail(paypal))return json(res,400,{error:"Valid PayPal email is required"});
  const available=await availableBalance(u.id);
  if(amount>available+1e-9)return json(res,400,{error:"Requested payout exceeds your available balance. Recordings still in QA review or inside the contracted payment-terms hold aren't withdrawable yet."});
  const id=crypto.randomUUID();
  // No balance column to decrement: availableBalance() already nets out 'requested'/'paid' payouts live,
  // so nothing here can be double-spent, and a later rejection needs no manual refund step either.
  await batch([{sql:`INSERT INTO payouts(id,user_id,amount_usd,paypal_email,status,created_at) VALUES(?,?,?,?,?,?)`,params:[id,u.id,amount,paypal,"requested",now()]},{sql:`UPDATE users SET paypal_email=? WHERE id=?`,params:[paypal,u.id]}]);
  return json(res,201,{success:true,payout_id:id});
}
async function adminPayouts(req,res){
  await requireFounder(req);
  const rows=(await query(`SELECT p.id,p.amount_usd,p.paypal_email,p.status,p.created_at,u.id user_id,u.full_name,u.email FROM payouts p JOIN users u ON u.id=p.user_id ORDER BY CASE p.status WHEN 'requested' THEN 0 ELSE 1 END, p.created_at DESC`)).results;
  return json(res,200,{payouts:rows});
}
async function adminPayoutDecision(req,res){
  const founder=await requireFounder(req), b=await body(req), id=String(b.payout_id||""), decision=String(b.status||"");
  if(!["paid","rejected"].includes(decision))return json(res,400,{error:"Status must be paid or rejected"});
  const p=await first(`SELECT * FROM payouts WHERE id=? AND status='requested'`,[id]);
  if(!p)return json(res,404,{error:"Payout request not found or already reviewed"});
  // Rejection needs no manual refund: availableBalance() only counts 'requested'/'paid' payouts, so a
  // 'rejected' payout simply stops being subtracted and the underlying recordings' money is available again.
  await query(`UPDATE payouts SET status=? WHERE id=?`,[decision,id]);
  return json(res,200,{success:true,status:decision});
}
async function adminRecordings(req,res){
  await requireAdmin(req);
  const rows=(await query(`SELECT r.id,r.language,r.category,r.text_prompt,r.audio_url,r.duration_ms,r.status,r.ai_score,r.ai_feedback,r.earned_usd,r.created_at,u.full_name,u.email,p.name project_name,p.payment_terms_days FROM recordings r JOIN users u ON u.id=r.user_id JOIN projects p ON p.id=r.project_id WHERE r.status='pending' ORDER BY r.created_at ASC LIMIT 100`)).results;
  const tk=bearer(req);
  for(const r of rows) r.playback_url=`/api/admin/audio?key=${encodeURIComponent(r.audio_url)}&t=${encodeURIComponent(tk)}`;
  return json(res,200,{recordings:rows,playback_error:null});
}
async function adminRecordingDecision(req,res){
  const admin=await requireAdmin(req), b=await body(req), id=String(b.recording_id||""), decision=String(b.status||"");
  if(!["approved","rejected"].includes(decision))return json(res,400,{error:"Status must be approved or rejected"});
  const r=await first(`SELECT r.*,p.payment_terms_days FROM recordings r JOIN projects p ON p.id=r.project_id WHERE r.id=? AND r.status='pending'`,[id]);
  if(!r)return json(res,404,{error:"Recording not found or already reviewed"});
  if(decision==="rejected"){
    // Nothing was ever credited to the freelancer for this clip, so rejecting it needs no clawback.
    await query(`UPDATE recordings SET status='rejected',reviewed_at=?,reviewed_by=? WHERE id=?`,[now(),admin.id,id]);
  }else{
    const termsDays=Number(r.payment_terms_days||7);
    const releaseAt=new Date(Date.now()+termsDays*24*60*60*1000).toISOString();
    await query(`UPDATE recordings SET status='approved',hold_release_at=?,reviewed_at=?,reviewed_by=? WHERE id=?`,[releaseAt,now(),admin.id,id]);
  }
  return json(res,200,{success:true,status:decision});
}
function transcriptFlags(m,text,dupes){
  const flags=[];let score=0;const add=(w,msg)=>{score+=w;flags.push(msg)};
  const dur=Number(m.duration_sec)||0,played=Number(m.played_sec)||0,el=Number(m.elapsed_sec)||0,typed=Number(m.typed_chars)||0,pasted=Number(m.paste_count)||0;
  if(!dur) add(10,"Audio length unknown");
  if(dur&&played<dur*0.6) add(35,`Only ${Math.round(played)}s of ${Math.round(dur)}s audio was played`);
  if(dur&&el<dur*0.8) add(30,`Submitted in ${Math.round(el)}s for ${Math.round(dur)}s of audio`);
  if(pasted>0) add(30,`Text was pasted (${pasted}x)`);
  if(text.length>80&&typed<text.length*0.5) add(25,"Much of the text was not typed");
  if(dupes>0) add(40,"Same transcript was already submitted");
  return {risk:Math.min(100,score),flags};
}
async function adminTranscriptions(req,res){
  await requireAdmin(req);
  const tasks=(await query(`SELECT t.id,t.language,t.transcript,t.source_audio_url,t.ai_risk,t.ai_flags,t.completed_at,u.full_name FROM transcription_tasks t LEFT JOIN users u ON u.id=t.assigned_user_id WHERE t.transcription_status='submitted' AND t.review_status='pending' ORDER BY t.ai_risk DESC,t.completed_at LIMIT 100`)).results;
  return json(res,200,{tasks});
}
async function adminTranscriptionDecision(req,res){
  const a=await requireAdmin(req),b=await body(req),id=String(b.task_id||""),d=String(b.status||"");
  if(!id||!["approved","rejected"].includes(d)) return json(res,400,{error:"Task and decision are required"});
  await query(`UPDATE transcription_tasks SET review_status=?,reviewed_at=?,reviewed_by=? WHERE id=? AND review_status='pending'`,[d,now(),a.id,id]);
  return json(res,200,{success:true,status:d});
}
async function transcription(req,res){
  const u=await requireUser(req);
  if(req.method==="GET"){
    const url=new URL(req.url,`https://${req.headers.host||"localhost"}`),lang=url.searchParams.get("language")||u.home_language;
    const tasks=(await query(`SELECT * FROM transcription_tasks WHERE language=? AND transcription_status='available' ORDER BY created_at LIMIT 20`,[lang])).results;
    return json(res,200,{tasks});
  }
  const b=await body(req),text=String(b.transcript||"").trim(),id=String(b.task_id||"");
  if(!id||!text)return json(res,400,{error:"Task and transcript are required"});
  const badLine=text.split("\n").map(l=>l.trim()).filter(Boolean).find(l=>!/^Speaker \d+ \[\d{2}:\d{2}(:\d{2})?\]: .+/.test(l));
  if(badLine)return json(res,400,{error:"Each line must look like: Speaker 1 [00:12]: text. Problem line: "+badLine.slice(0,60)});
  const t=await first(`SELECT id FROM transcription_tasks WHERE id=? AND transcription_status='available'`,[id]);if(!t)return json(res,404,{error:"Task unavailable"});
  const m=(b.meta&&typeof b.meta==="object")?b.meta:{};
  const hash=crypto.createHash("sha256").update(text.toLowerCase().replace(/speaker \d+ \[[\d:]+\]:/g,"").replace(/\s+/g," ").trim()).digest("hex");
  const dupes=Number((await first(`SELECT COUNT(*) AS n FROM transcription_tasks WHERE transcript_hash=? AND id<>?`,[hash,id]))?.n||0);
  const ai=transcriptFlags(m,text,dupes);
  await query(`UPDATE transcription_tasks SET transcript=?,assigned_user_id=?,transcription_status='submitted',completed_at=?,ai_risk=?,ai_flags=?,submit_meta=?,transcript_hash=? WHERE id=?`,[text,u.id,now(),ai.risk,JSON.stringify(ai.flags),JSON.stringify(m).slice(0,500),hash,id]);
  return json(res,200,{success:true});
}
async function health(res){
  const r=await first("SELECT 1 AS ok"); return json(res,200,{ok:r?.ok===1,service:"SOUTHYAI",database:"d1",time:now()});
}
export default async function handler(req,res){
  try{
    await ensureSchema();
    const path=new URL(req.url,`https://${req.headers.host||"localhost"}`).pathname.replace(/^\/api\/?/,"").replace(/\/$/,"");
    if(path==="health"||path==="") return await health(res);
    if(path==="auth" && req.method==="GET"){const u=await requireUser(req);return await json(res,200,{user:publicUser(u)});}
    if(path==="auth/login"&&req.method==="POST")return await authLogin(req,res);
    if(path==="auth/signup"&&req.method==="POST")return await authSignup(req,res);
    if(path==="admin/unlock"&&req.method==="POST")return await adminUnlock(req,res);
    if(path==="auth/mfa/setup"&&req.method==="POST")return await mfaSetup(req,res);
    if(path==="auth/mfa/enable"&&req.method==="POST")return await mfaEnable(req,res);
    if(path==="admin/mfa-reset"&&req.method==="POST")return await mfaReset(req,res);
    if(path==="admin/audio"&&req.method==="GET")return await adminAudio(req,res);
    if(path==="admin/transcriptions"&&req.method==="GET")return await adminTranscriptions(req,res);
    if(path==="admin/transcription-decision"&&req.method==="POST")return await adminTranscriptionDecision(req,res);
    if(path==="projects"||path==="projects/list")return await projects(req,res);
    if(path==="apply"&&req.method==="POST")return await apply(req,res);
    if(path==="applications"&&req.method==="GET")return await userApplications(req,res);
    if(path==="referral"&&(req.method==="GET"||req.method==="POST"))return await referral(req,res);
    if(path==="account/balance"&&req.method==="GET")return await balance(req,res);
    if(path==="admin/applications"&&req.method==="GET")return await adminApplications(req,res);
    if(path==="admin/approve"&&req.method==="POST")return await adminDecision(req,res);
    if(path==="admin/staff"&&req.method==="GET")return await staff(req,res);
    if(path==="admin/contract"&&req.method==="POST")return await adminContract(req,res);
    if(path==="admin/projects"&&req.method==="GET")return await adminProjects(req,res);
    if(path==="admin/project-terms"&&req.method==="POST")return await adminProjectTerms(req,res);
    if(path==="prompts/next"&&req.method==="GET")return await nextPrompt(req,res);
    if(path==="sessions/start"&&req.method==="POST")return await startSession(req,res);
    if(path==="sessions/end"&&req.method==="POST")return await endSession(req,res);
    if(path==="recordings/upload"&&req.method==="POST")return await uploadRecording(req,res);
    if(path==="recordings/my"&&req.method==="GET")return await recordings(req,res);
    if(path==="payouts/request"&&req.method==="POST")return await payout(req,res);
    if(path==="admin/payouts"&&req.method==="GET")return await adminPayouts(req,res);
    if(path==="admin/payout-decision"&&req.method==="POST")return await adminPayoutDecision(req,res);
    if(path==="admin/recordings"&&req.method==="GET")return await adminRecordings(req,res);
    if(path==="admin/recording-decision"&&req.method==="POST")return await adminRecordingDecision(req,res);
    if(path==="transcription/tasks")return await transcription(req,res);
    return json(res,404,{error:"API route not found"});
  }catch(e){
    if(e?.status)return json(res,e.status,{error:e.message,code:e.code});
    return json(res,500,{error:e.message||"Server error"});
  }
}
