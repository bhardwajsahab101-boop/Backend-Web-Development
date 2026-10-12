require('dotenv').config();
const crypto = require('crypto');

const sessions = new Map();
const DEFAULT_SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 60 * 60 * 1000);

function purgeExpiredSessions() {
  const now = Date.now();

  for (const [sessionId, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(sessionId);
    }
  }
}

function createSession(userId) {
  purgeExpiredSessions();

  const sessionId = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + DEFAULT_SESSION_TTL_MS;

  sessions.set(sessionId, { userId, expiresAt });

  return { id: sessionId, userId, expiresAt };
}

function getSession(sessionId) {
  purgeExpiredSessions();

  const session = sessions.get(sessionId);
  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  return { ...session };
}

function destroySession(sessionId) {
  sessions.delete(sessionId);
  return true;
}

module.exports = {
  createSession,
  getSession,
  destroySession,
  getTTL: () => DEFAULT_SESSION_TTL_MS,
};
