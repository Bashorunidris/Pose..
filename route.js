// Cloudflare Pages Function. Env: VATAR_SECRET (secret). Binding: WALLET (KV namespace).
// Coin packs here must match the productIds you create in the Vatar dashboard.
const API = 'https://lagoslife.app/api/games/v1';
const PACKS = { coins_20: 20, coins_50: 55, coins_120: 135, coins_300: 350 };
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json' } });
const vt = async (env, path, body) => {
  const r = await fetch(API + path, {
    method: body ? 'POST' : 'GET',
    headers: { Authorization: 'Bearer ' + env.VATAR_SECRET, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { ok: r.ok, ...(await r.json().catch(() => ({}))) };
};

const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const enc = (o) => b64(new TextEncoder().encode(JSON.stringify(o)));
async function fbToken(env, uid) { // Firebase custom token, signed with your service account
  const n = Math.floor(Date.now() / 1000);
  const h = enc({ alg: 'RS256', typ: 'JWT' });
  const p = enc({ iss: env.FB_CLIENT_EMAIL, sub: env.FB_CLIENT_EMAIL, aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit', iat: n, exp: n + 3600, uid });
  const pem = env.FB_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/-----[^-]+-----|\s/g, '');
  const k = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  return h + '.' + p + '.' + b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', k, new TextEncoder().encode(h + '.' + p)));
}

export async function onRequestPost({ request, env, params }) {
  const route = params.route?.[0];
  const b = await request.json().catch(() => ({}));
  const me = await vt(env, '/session/verify', { session: b.session });
  if (!me.ok) return J({ error: 'auth' }, 401);
  if (route === 'token') return J({ token: await fbToken(env, me.playerId) });

  const key = 'bal:' + me.playerId;
  const bal = +((await env.WALLET.get(key)) || 0);

  if (route === 'wallet') return J({ coins: bal });

  if (route === 'spend') {
    const a = Math.floor(+b.amount);
    if (!(a > 0) || a > bal) return J({ error: 'low' }, 402);
    await env.WALLET.put(key, String(bal - a));
    return J({ coins: bal - a });
  }

  if (route === 'claim') {
    const p = await vt(env, '/purchases/' + encodeURIComponent(b.purchaseId));
    if (!p.ok || p.playerId !== me.playerId) return J({ error: 'forbidden' }, 403);
    if (p.status === 'refunded') return J({ error: 'refunded' }, 409);
    const n = PACKS[p.productId];
    if (!n) return J({ error: 'unknown_product' }, 400);
    const done = 'done:' + p.id;
    if (!(await env.WALLET.get(done))) {
      await env.WALLET.put(done, '1');
      await env.WALLET.put(key, String(bal + n));
    }
    await vt(env, '/purchases/' + p.id + '/deliver', {});
    return J({ coins: +((await env.WALLET.get(key)) || 0) });
  }
  return J({ error: 'not_found' }, 404);
  }
