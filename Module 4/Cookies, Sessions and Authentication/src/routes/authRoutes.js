const express = require('express');
const bcrypt = require('bcryptjs');

const prisma = require('../db/prisma');
const sessionStore = require('../session/sessionStore');
const requireSession = require('../middleware/requireSession');

const router = express.Router();

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.COOKIE_SECURE === 'true',
  signed: true,
  path: '/',
};

router.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body?.email ?? '').trim().toLowerCase();
    const password = String(req.body?.password ?? '');

    if (!email || !password) {
      return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Email and password are required' } });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid email or password' } });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid email or password' } });
    }

    const session = sessionStore.createSession(user.id);
    const maxAge = Math.max(1, session.expiresAt - Date.now());

    res.cookie('sid', session.id, {
      ...cookieOptions,
      maxAge,
    });

    return res.status(200).json({
      message: 'Login successful',
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/me', requireSession, async (req, res) => {
  return res.status(200).json({ user: req.user });
});

router.post('/logout', requireSession, async (req, res) => {
  const sessionId = req.signedCookies?.sid;

  if (sessionId) {
    sessionStore.destroySession(sessionId);
  }

  res.clearCookie('sid', {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    path: '/',
  });

  return res.status(200).json({ message: 'Logout successful' });
});

module.exports = router;
