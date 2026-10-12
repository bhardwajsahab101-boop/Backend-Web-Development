const prisma = require('../db/prisma');
const sessionStore = require('../session/sessionStore');

module.exports = async function requireSession(req, res, next) {
  try {
    const sessionId = req.signedCookies?.sid;

    if (!sessionId) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
    }

    const session = sessionStore.getSession(sessionId);
    if (!session) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { id: true, name: true, email: true },
    });

    if (!user) {
      sessionStore.destroySession(sessionId);
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
    }

    req.session = session;
    req.user = user;
    return next();
  } catch (error) {
    return next(error);
  }
};
