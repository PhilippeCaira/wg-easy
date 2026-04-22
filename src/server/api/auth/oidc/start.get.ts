import { OIDC_ENV, buildAuthorizeUrl, generateState } from '~~/server/utils/oidc';

export default defineEventHandler(async (event) => {
  if (!OIDC_ENV.ENABLED) {
    throw createError({ statusCode: 404, statusMessage: 'OIDC disabled' });
  }
  const state = generateState();
  setCookie(event, 'wg-easy-oidc-state', state, {
    httpOnly: true,
    secure: !WG_ENV.INSECURE,
    sameSite: 'lax',
    maxAge: 600,
    path: '/',
  });
  const url = await buildAuthorizeUrl(state);
  return sendRedirect(event, url, 302);
});
