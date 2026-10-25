import { NextResponse } from 'next/server'; import type { NextRequest } from 'next/server'; import jwt from 'jsonwebtoken';
function getSecret(){ const s=process.env.JWT_SECRET; if(!s||s.length<32) throw new Error('JWT_SECRET 32자 필수'); return s; }
export function middleware(req: NextRequest){
  const res=NextResponse.next();
  res.headers.set('X-Frame-Options','DENY'); res.headers.set('X-Content-Type-Options','nosniff');
  res.headers.set('Strict-Transport-Security','max-age=31536000; includeSubDomains; preload');
  res.headers.set('Content-Security-Policy',"default-src 'self'");
  const token=req.cookies.get('re100_token')?.value;
  if(token){ try{ const SECRET=getSecret(); const d:any=jwt.verify(token,SECRET); const now=Date.now(); if(now-(d.lastActive||now)>1800000){ const r=NextResponse.redirect(new URL('/login?reason=timeout',req.url)); r.cookies.delete('re100_token'); return r; } const nt=jwt.sign({...d,lastActive:now},SECRET,{expiresIn:'30m'}); res.cookies.set('re100_token',nt,{httpOnly:true,secure:true,sameSite:'strict',maxAge:1800}); }catch{ const r=NextResponse.redirect(new URL('/login',req.url)); r.cookies.delete('re100_token'); return r; } }
  return res;
}
export const config={matcher:['/dashboard/:path*','/admin/:path*']};
