// functions/api/r2-presign.js
// Cloudflare Pages Function — uses Web Crypto API (NO Node.js modules)

export async function onRequestPost(context) {
  const { request, env } = context;

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  const accountId = env.R2_ACCOUNT_ID;
  const bucket = env.R2_BUCKET_NAME;
  const accessKeyId = env.R2_ACCESS_KEY_ID;
  const secretAccessKey = env.R2_SECRET_ACCESS_KEY;
  const publicDomain = env.R2_PUBLIC_DOMAIN;

  if (!accountId || !bucket || !accessKeyId || !secretAccessKey) {
    return new Response(JSON.stringify({
      error: 'R2 credentials not configured',
      missing: {
        accountId: !accountId,
        bucket: !bucket,
        accessKeyId: !accessKeyId,
        secretAccessKey: !secretAccessKey
      }
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  try {
    const body = await request.json();
    const me = await (await fetch('https://lagoslife.app/api/games/v1/session/verify', { method: 'POST', headers: { Authorization: 'Bearer ' + env.VATAR_SECRET, 'Content-Type': 'application/json' }, body: JSON.stringify({ session: body.session }) })).json();
    if (!me.playerId) return new Response(JSON.stringify({ error: 'auth' }), { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    if (!/^(image|video|audio)\//.test(body.contentType || '')) return new Response(JSON.stringify({ error: 'type' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    body.folder = 'lagoslife/' + me.playerId;
    const { filename, contentType = 'application/octet-stream', folder = 'general' } = body;

    if (!filename) {
      return new Response(JSON.stringify({ error: 'Missing filename' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Generate unique key
    const uniqueId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const timestamp = Date.now();
    const cleanFilename = filename.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const key = `${folder}/${timestamp}_${uniqueId}_${cleanFilename}`;

    const host = `${accountId}.r2.cloudflarestorage.com`;
    const endpoint = `https://${host}`;

    const canonicalUri = '/' + [bucket, ...key.split('/')]
      .map(part => encodeURIComponent(part).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase()))
      .join('/');

    const now = new Date();
    const datetime = now.toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
    const date = datetime.slice(0, 8);
    const region = 'auto';
    const credentialScope = `${date}/${region}/s3/aws4_request`;
    const expiresIn = 3600;

    const queryParams = {
      'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
      'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
      'X-Amz-Date': datetime,
      'X-Amz-Expires': String(expiresIn),
      'X-Amz-SignedHeaders': 'host'
    };

    const sortedQueryString = Object.keys(queryParams)
      .sort()
      .map(q => `${encodeURIComponent(q)}=${encodeURIComponent(queryParams[q])}`)
      .join('&');

    const canonicalRequest = [
      'PUT',
      canonicalUri,
      sortedQueryString,
      `host:${host}\n`,
      'host',
      'UNSIGNED-PAYLOAD'
    ].join('\n');

    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalRequest));
    const hashedCanonicalRequest = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const stringToSign = [
      'AWS4-HMAC-SHA256',
      datetime,
      credentialScope,
      hashedCanonicalRequest
    ].join('\n');

    async function hmac(key, message) {
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        typeof key === 'string' ? encoder.encode(key) : key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
      return new Uint8Array(sig);
    }

    const kDate = await hmac(encoder.encode('AWS4' + secretAccessKey), date);
    const kRegion = await hmac(kDate, region);
    const kService = await hmac(kRegion, 's3');
    const kSigning = await hmac(kService, 'aws4_request');

    const sigBuffer = await hmac(kSigning, stringToSign);
    const signature = Array.from(new Uint8Array(sigBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const uploadUrl = `${endpoint}${canonicalUri}?${sortedQueryString}&X-Amz-Signature=${signature}`;

    const basePublicDomain = publicDomain
      ? publicDomain.replace(/^https?:\/\//, '')
      : `${bucket}.${accountId}.r2.dev`;
    const publicUrl = `https://${basePublicDomain}/${key}`;

    return new Response(JSON.stringify({ uploadUrl, publicUrl, key }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (err) {
    console.error('r2-presign error:', err);
    return new Response(JSON.stringify({
      error: 'Failed to generate presigned URL',
      detail: err.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
                                                                                                                   }
