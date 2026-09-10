export const config = {
  runtime: 'nodejs',
};

export default async function handler(req) {
  try {
    const url = new URL(req.url);
    const targetUrlStr = url.searchParams.get('url') || url.pathname.replace(/^\/api\/proxy\//, '');
    
    if (!targetUrlStr) {
      return new Response('Missing target URL', { status: 400 });
    }

    let targetUrl;
    try {
      targetUrl = new URL(targetUrlStr);
    } catch (e) {
      // Decode encoded URLs if needed
      try {
        targetUrl = new URL(decodeURIComponent(targetUrlStr));
      } catch (e2) {
        return new Response('Invalid target URL', { status: 400 });
      }
    }

    // Prepare headers for upstream request
    const headers = new Headers(req.headers);
    
    // Strip unnecessary headers to prevent fingerprinting or overhead
    headers.delete('host');
    headers.delete('cookie'); // remove extension cookies
    
    // Remove Vercel internal headers
    for (const key of headers.keys()) {
      if (key.startsWith('x-vercel-') || key.startsWith('x-forwarded-')) {
        headers.delete(key);
      }
    }

    // Set Origin/Referer to match target to satisfy CORS/CSRF protections on target site
    headers.set('origin', targetUrl.origin);
    headers.set('referer', targetUrl.origin + '/');

    // Fetch from upstream
    const upstream = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: headers,
      body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
      redirect: 'manual'
    });

    // Prepare response headers
    const resHeaders = new Headers(upstream.headers);
    
    // Cache static assets at edge (e.g. 1 hour)
    const contentType = resHeaders.get('content-type') || '';
    if (
      contentType.includes('javascript') || 
      contentType.includes('css') || 
      contentType.includes('image/') || 
      contentType.includes('font/')
    ) {
      resHeaders.set('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');
    }

    // Remove restrictive CSP or X-Frame-Options to allow framing in extension
    resHeaders.delete('x-frame-options');
    resHeaders.delete('content-security-policy');
    
    // Also remove CORS headers and replace with permissive ones
    resHeaders.delete('access-control-allow-origin');
    resHeaders.set('Access-Control-Allow-Origin', '*');

    // Return the response directly as a streaming dumb pipe
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: resHeaders
    });

  } catch (error) {
    console.error('Proxy Error:', error);
    return new Response(JSON.stringify({ error: 'Proxy fetch failed', details: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
