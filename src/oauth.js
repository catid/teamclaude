import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
import { exec } from 'node:child_process';
import { createInterface } from 'node:readline';
import http from 'node:http';

/**
 * Import OAuth credentials from a Claude Code credentials file.
 */
export async function importCredentials(filePath) {
  const resolvedPath = filePath.replace(/^~/, homedir());
  const raw = JSON.parse(await readFile(resolvedPath, 'utf-8'));

  // Claude Code stores credentials nested under "claudeAiOauth"
  const data = raw.claudeAiOauth || raw;
  return {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresAt: data.expiresAt,
    subscriptionType: data.subscriptionType,
    rateLimitTier: data.rateLimitTier,
  };
}

const PROFILE_URL = 'https://api.anthropic.com/api/oauth/profile';
const DEFAULT_TOKEN_ENDPOINT = 'https://platform.claude.com/v1/oauth/token';
const DEFAULT_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';

/**
 * Refresh an expired OAuth access token using the refresh token.
 * Retries on 5xx and network errors with exponential backoff.
 */
export async function refreshAccessToken(refreshToken, endpoint = DEFAULT_TOKEN_ENDPOINT) {
  const maxRetries = 2;
  const baseDelayMs = 500;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      if (attempt > 0) {
        const delay = baseDelayMs * 2 ** (attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/plain, */*',
          'User-Agent': 'axios/1.13.6',
        },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: DEFAULT_CLIENT_ID,
        }),
      });

      if (!res.ok) {
        if (res.status >= 500 && attempt < maxRetries) {
          await res.body?.cancel();
          continue;
        }
        const text = await res.text();
        throw new Error(`Token refresh failed (${res.status}): ${text}`);
      }

      const data = await res.json();
      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || refreshToken,
        expiresAt: normalizeExpiresAt(data.expires_at) || (Date.now() + (data.expires_in || 3600) * 1000),
      };
    } catch (err) {
      const isNetworkError = err instanceof Error &&
        (err.message.includes('fetch failed') ||
          (err.code === 'ECONNRESET' || err.code === 'ECONNREFUSED' ||
           err.code === 'ETIMEDOUT' || err.code === 'UND_ERR_CONNECT_TIMEOUT'));

      if (attempt < maxRetries && isNetworkError) {
        continue;
      }
      throw err;
    }
  }
}

/**
 * Normalize an expires_at value to milliseconds.
 * OAuth endpoints may return seconds; Claude Code credentials use milliseconds.
 */
export function normalizeExpiresAt(expiresAt) {
  if (!expiresAt) return expiresAt;
  // If the value is plausibly in seconds (< 10^12 ≈ year 2001 in ms, year 33658 in s),
  // convert to milliseconds
  return expiresAt < 1e12 ? expiresAt * 1000 : expiresAt;
}

/**
 * Check if an OAuth token is expiring within the given threshold.
 */
export function isTokenExpiringSoon(expiresAt, thresholdMs = 5 * 60 * 1000) {
  if (!expiresAt) return false;
  return Date.now() + thresholdMs >= normalizeExpiresAt(expiresAt);
}

/**
 * Fetch account profile for an OAuth token.
 * Returns { email, name, orgName, orgType, ... } on success,
 * or { error: 'reason' } on failure.
 */
export async function fetchProfile(accessToken) {
  try {
    const res = await fetch(PROFILE_URL, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      let detail = '';
      try {
        const body = await res.json();
        detail = body?.error?.message || JSON.stringify(body).slice(0, 200);
      } catch {
        detail = await res.text().catch(() => '');
      }
      return { error: `HTTP ${res.status}${detail ? ': ' + detail : ''}` };
    }
    const data = await res.json();
    return {
      accountUuid: data.account?.uuid,
      email: data.account?.email,
      name: data.account?.display_name,
      orgUuid: data.organization?.uuid,
      orgName: data.organization?.name,
      orgType: data.organization?.organization_type,
      billingType: data.organization?.billing_type,
      rateLimitTier: data.organization?.rate_limit_tier,
      hasClaudeMax: data.account?.has_claude_max,
      hasClaudePro: data.account?.has_claude_pro,
    };
  } catch (err) {
    return { error: err.message || String(err) };
  }
}

// OAuth config (extracted from Claude Code)
const OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const OAUTH_AUTHORIZE = 'https://claude.com/cai/oauth/authorize';
const OAUTH_TOKEN = 'https://platform.claude.com/v1/oauth/token';
const OAUTH_MANUAL_REDIRECT_URI = 'https://platform.claude.com/oauth/code/callback';
const OAUTH_SCOPES = 'org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload';

/**
 * Perform OAuth login via browser with PKCE flow.
 * Opens the user's browser, waits for the callback, exchanges the code for tokens.
 */
export async function loginOAuth() {
  // Generate PKCE
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const state = randomBytes(32).toString('base64url');

  // Start local callback server on a random port
  const { port, codePromise, server } = await startCallbackServer(state);
  const automaticRedirectUri = `http://localhost:${port}/callback`;

  // Build authorization URL
  const automaticAuthUrl = buildAuthUrl({ redirectUri: automaticRedirectUri, codeChallenge, state });
  const manualAuthUrl = buildAuthUrl({ redirectUri: OAUTH_MANUAL_REDIRECT_URI, codeChallenge, state });

  // Open browser
  console.log('Opening browser for authentication...');
  console.log(`If it doesn't open, visit this URL on any machine:\n  ${manualAuthUrl.toString()}\n`);
  openBrowser(automaticAuthUrl.toString());

  // Wait for either the callback server or manual paste from stdin
  let authResult;
  try {
    authResult = await raceWithStdinCode(codePromise, state);
  } finally {
    server.close();
  }

  // Exchange code for tokens
  console.log('Exchanging authorization code for tokens...');
  const tokenRes = await fetch(OAUTH_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code: authResult.code,
      state,
      grant_type: 'authorization_code',
      client_id: OAUTH_CLIENT_ID,
      redirect_uri: authResult.redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`Token exchange failed (${tokenRes.status}): ${text}`);
  }

  const tokens = await tokenRes.json();
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: normalizeExpiresAt(tokens.expires_at) || (Date.now() + (tokens.expires_in || 3600) * 1000),
  };
}

function buildAuthUrl({ redirectUri, codeChallenge, state }) {
  const authUrl = new URL(OAUTH_AUTHORIZE);
  authUrl.searchParams.set('code', 'true');
  authUrl.searchParams.set('client_id', OAUTH_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', OAUTH_SCOPES);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);
  return authUrl;
}

/**
 * Race the callback server promise against manual code entry from stdin.
 * The user can paste the full callback URL or just the authorization code.
 */
function raceWithStdinCode(callbackPromise, expectedState) {
  if (!process.stdin.isTTY) return callbackPromise;

  return new Promise((resolve, reject) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    let settled = false;

    const settle = (fn, val) => {
      if (settled) return;
      settled = true;
      rl.close();
      fn(val);
    };

    rl.question('Paste authorization code here (or wait for browser callback): ', answer => {
      try {
        const result = parseManualAuthInput(answer, expectedState);
        if (!result) return; // empty input, keep waiting for callback
        settle(resolve, result);
      } catch (err) {
        settle(reject, err);
      }
    });

    callbackPromise.then(
      code => settle(resolve, code),
      err => settle(reject, err),
    );
  });
}

function parseManualAuthInput(input, expectedState) {
  const trimmed = input.trim();
  if (!trimmed) return null;

  try {
    const url = new URL(trimmed);
    const query = new URLSearchParams(url.search);
    const fragment = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : url.hash);
    const code = query.get('code') || fragment.get('code');
    const state = query.get('state') || fragment.get('state');
    if (code) {
      assertOAuthState(state, expectedState);
      return {
        code,
        redirectUri: `${url.origin}${url.pathname}`,
      };
    }
  } catch {}

  if (trimmed.includes('=') && trimmed.includes('&')) {
    const params = new URLSearchParams(trimmed);
    const code = params.get('code');
    if (code) {
      assertOAuthState(params.get('state'), expectedState);
      return { code, redirectUri: OAUTH_MANUAL_REDIRECT_URI };
    }
  }

  const hashIndex = trimmed.lastIndexOf('#');
  if (hashIndex > 0) {
    const code = trimmed.slice(0, hashIndex);
    const state = trimmed.slice(hashIndex + 1);
    assertOAuthState(state, expectedState);
    return { code, redirectUri: OAUTH_MANUAL_REDIRECT_URI };
  }

  return { code: trimmed, redirectUri: OAUTH_MANUAL_REDIRECT_URI };
}

function assertOAuthState(actualState, expectedState) {
  if (expectedState && actualState && actualState !== expectedState) {
    throw new Error('OAuth state mismatch');
  }
}

function startCallbackServer(expectedState) {
  return new Promise((resolve, reject) => {
    let resolveCode, rejectCode;
    const codePromise = new Promise((res, rej) => { resolveCode = res; rejectCode = rej; });

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://localhost`);

      if (url.pathname === '/callback') {
        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');
        const state = url.searchParams.get('state');

        if (error) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h2>Authentication failed</h2><p>You can close this tab.</p></body></html>');
          rejectCode(new Error(`OAuth error: ${error} - ${url.searchParams.get('error_description') || ''}`));
          return;
        }

        if (expectedState && state !== expectedState) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h2>Authentication failed</h2><p>State mismatch. You can close this tab.</p></body></html>');
          rejectCode(new Error('OAuth state mismatch'));
          return;
        }

        if (code) {
          res.writeHead(302, { 'Location': 'https://platform.claude.com/oauth/code/success?app=claude-code' });
          res.end();
          resolveCode({
            code,
            redirectUri: `http://localhost:${server.address().port}/callback`,
          });
          return;
        }
      }

      res.writeHead(404);
      res.end('Not found');
    });

    server.listen(0, () => {
      resolve({ port: server.address().port, codePromise, server });
    });
    server.on('error', reject);

    // Timeout after 2 minutes (unref so it doesn't keep the process alive)
    const timer = setTimeout(() => {
      rejectCode(new Error('Login timed out after 2 minutes'));
      server.close();
    }, 120_000);
    timer.unref();
  });
}

function openBrowser(url) {
  const platform = process.platform;
  const cmd = platform === 'darwin' ? 'open'
    : platform === 'win32' ? 'start'
    : 'xdg-open';
  exec(`${cmd} ${JSON.stringify(url)}`, () => {});
}
