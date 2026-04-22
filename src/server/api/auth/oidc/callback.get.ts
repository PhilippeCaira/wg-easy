import { randomBytes } from 'node:crypto';
import { OIDC_ENV, exchangeCode, fetchUserInfo } from '~~/server/utils/oidc';

export default defineEventHandler(async (event) => {
  if (!OIDC_ENV.ENABLED) {
    throw createError({ statusCode: 404, statusMessage: 'OIDC disabled' });
  }

  const { code, state } = getQuery(event);
  if (typeof code !== 'string' || typeof state !== 'string') {
    throw createError({ statusCode: 400, statusMessage: 'Missing code or state' });
  }

  const expectedState = getCookie(event, 'wg-easy-oidc-state');
  if (!expectedState || expectedState !== state) {
    throw createError({ statusCode: 400, statusMessage: 'State mismatch' });
  }
  deleteCookie(event, 'wg-easy-oidc-state');

  const tokens = await exchangeCode(code);
  const userinfo = await fetchUserInfo(tokens.access_token);

  const username = userinfo.preferred_username || userinfo.email;
  if (!username) {
    throw createError({ statusCode: 400, statusMessage: 'No username claim' });
  }

  let dbUser = await Database.users.getByUsername(username);
  if (!dbUser) {
    // Create a local user backed by OIDC (random password never used since SSO only)
    const randomPw = randomBytes(32).toString('hex');
    const created = await Database.users.create(username, randomPw);
    if (!created.success) {
      throw createError({ statusCode: 500, statusMessage: 'User create failed' });
    }
    dbUser = await Database.users.getByUsername(username);
    if (!dbUser) {
      throw createError({ statusCode: 500, statusMessage: 'User create failed (not found after insert)' });
    }
  }

  const session = await useWGSession(event, true);
  await session.update({ userId: dbUser.id });

  return sendRedirect(event, '/', 302);
});
