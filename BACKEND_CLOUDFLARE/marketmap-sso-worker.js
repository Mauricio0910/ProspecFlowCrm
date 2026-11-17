/**
 * Cloudflare Worker - login único MarketMap a partir de identidade Cloudflare Access VALIDADA.
 * Nunca coloque SERVICE_ACCOUNT_PRIVATE_KEY ou ALLOWED_EMAIL_UIDS_JSON no GitHub Pages.
 * Implemente no MESMO domínio personalizado que hospeda o CRM, por rota /api/marketmap-sso.
 * Proteja a rota pelo Cloudflare Access. Requer Cloudflare Access JWT assinado.
 */
const enc = new TextEncoder();
const fromB64Url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
const toB64Url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const jsonTokenPart = obj => toB64Url(enc.encode(JSON.stringify(obj)));
function readJwt(jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw Error('Invalid token');
  return {parts, header:JSON.parse(new TextDecoder().decode(fromB64Url(parts[0]))), claims:JSON.parse(new TextDecoder().decode(fromB64Url(parts[1])))};
}
async function authenticatedAccessEmail(assertion, env) {
  if (!assertion) throw Error('Cloudflare Access authentication required');
  const {parts,header,claims} = readJwt(assertion);
  if (header.alg !== 'RS256' || !header.kid) throw Error('Unsupported Access token');
  const issuer=`https://${env.CF_TEAM_DOMAIN}.cloudflareaccess.com`;
  if(claims.iss !== issuer || !(Array.isArray(claims.aud)?claims.aud.includes(env.CF_APPLICATION_AUD):claims.aud===env.CF_APPLICATION_AUD))
    throw Error('Wrong issuer/audience');
  const now=Math.floor(Date.now()/1000);
  if(!claims.exp || claims.exp<=now || !claims.iat || claims.iat>now+60) throw Error('Expired Access token');
  const response=await fetch(`${issuer}/cdn-cgi/access/certs`, {cf:{cacheTtl:1800}});
  if(!response.ok)throw Error('Access key unavailable');
  const keys=await response.json();
  const jwk=(keys.keys||[]).find(k=>k.kid===header.kid&&k.kty==='RSA');
  if(!jwk)throw Error('Unknown Access signing key');
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  const signed=enc.encode(parts[0]+'.'+parts[1]);
  if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,fromB64Url(parts[2]),signed)) throw Error('Access signature invalid');
  const email=String(claims.email||'').trim().toLowerCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw Error('Access identity has no email');
  return email;
}
async function firebaseCustomToken(uid,env) {
  const now=Math.floor(Date.now()/1000);
  const header={alg:'RS256',typ:'JWT'};
  const payload={iss:env.FIREBASE_SERVICE_ACCOUNT_EMAIL,sub:env.FIREBASE_SERVICE_ACCOUNT_EMAIL,
    aud:'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat:now,exp:now+3600,uid};
  const input=jsonTokenPart(header)+'.'+jsonTokenPart(payload);
  const pem=env.FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY.replace(/\\n/g,'\n').replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g,'');
  const der=Uint8Array.from(atob(pem),c=>c.charCodeAt(0));
  const key=await crypto.subtle.importKey('pkcs8',der,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
  const signature=new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,enc.encode(input)));
  return input+'.'+toB64Url(signature);
}
export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if(request.method!=='GET'||url.pathname!=='/api/marketmap-sso')
      return new Response('Not found',{status:404});
    const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, max-age=0',
      'X-Content-Type-Options':'nosniff'};
    const origin=request.headers.get('Origin');
    if (origin && origin!==env.PUBLIC_CRM_ORIGIN) return new Response('Forbidden',{status:403,headers});
    try {
      const email=await authenticatedAccessEmail(request.headers.get('Cf-Access-Jwt-Assertion'),env);
      const allowed=JSON.parse(env.ALLOWED_EMAIL_UIDS_JSON||'{}');
      // Mapear e-mail do Cloudflare para UID EXISTENTE do Firebase MarketMap.
      // Assim não se perde histórico de checkpoints e permissões ligadas ao UID.
      const uid=allowed[email];
      if(typeof uid!=='string'||!uid||uid.length>128) return new Response(JSON.stringify({error:'not-authorized'}),{status:403,headers});
      const token=await firebaseCustomToken(uid,env);
      return new Response(JSON.stringify({token}),{status:200,headers});
    }catch(err){
      console.error('MarketMap SSO denied:',String(err?.message||'unknown'));
      return new Response(JSON.stringify({error:'authentication-unavailable'}),{status:401,headers});
    }
  }
};
