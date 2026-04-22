import { randomBytes } from 'node:crypto';

export const OIDC_ENV = {
  ENABLED: process.env.OIDC_ENABLED === 'true',
  ISSUER: process.env.OIDC_ISSUER || '',
  CLIENT_ID: process.env.OIDC_CLIENT_ID || '',
  CLIENT_SECRET: process.env.OIDC_CLIENT_SECRET || '',
  REDIRECT_URI: process.env.OIDC_REDIRECT_URI || '',
  SCOPES: process.env.OIDC_SCOPES || 'openid profile email',
};

type DiscoveryDoc = {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
};

let cachedDiscovery: DiscoveryDoc | null = null;

export async function getDiscovery(): Promise<DiscoveryDoc> {
  if (cachedDiscovery) return cachedDiscovery;
  const res = await fetch(
    `${OIDC_ENV.ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`
  );
  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status}`);
  }
  cachedDiscovery = (await res.json()) as DiscoveryDoc;
  return cachedDiscovery;
}

export function generateState(): string {
  return randomBytes(24).toString('hex');
}

export async function buildAuthorizeUrl(state: string): Promise<string> {
  const disco = await getDiscovery();
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: OIDC_ENV.CLIENT_ID,
    redirect_uri: OIDC_ENV.REDIRECT_URI,
    scope: OIDC_ENV.SCOPES,
    state,
  });
  return `${disco.authorization_endpoint}?${params}`;
}

export async function exchangeCode(code: string): Promise<{ id_token: string; access_token: string }> {
  const disco = await getDiscovery();
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: OIDC_ENV.REDIRECT_URI,
  });
  const basic = Buffer.from(`${OIDC_ENV.CLIENT_ID}:${OIDC_ENV.CLIENT_SECRET}`).toString('base64');
  const res = await fetch(disco.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${basic}`,
    },
    body,
  });
  if (!res.ok) {
    throw new Error(`OIDC token exchange failed: ${res.status}`);
  }
  return res.json() as Promise<{ id_token: string; access_token: string }>;
}

export async function fetchUserInfo(accessToken: string): Promise<{ email?: string; preferred_username?: string; name?: string }> {
  const disco = await getDiscovery();
  const res = await fetch(disco.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    throw new Error(`OIDC userinfo failed: ${res.status}`);
  }
  return res.json() as Promise<{ email?: string; preferred_username?: string; name?: string }>;
}
