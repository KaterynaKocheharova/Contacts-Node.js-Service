import bcrypt from 'bcrypt';
import createHttpError from 'http-errors';
import jwt from 'jsonwebtoken';
import path from 'node:path';
import fs from 'node:fs/promises';
import Handlebars from 'handlebars';
import { env } from '../utils/env.js';
import { User } from '../db/models/user.js';
import { Session } from '../db/models/session.js';
import { createSession } from '../utils/authUtils.js';
import { sendEmail } from '../utils/sendMail.js';
import { SMTP } from '../constants/index.js';
import { TEMPLATES_DIR } from '../constants/index.js';
import { validateCode } from '../utils/googleOAuth2.js';
import { randomBytes } from 'node:crypto';
import { getFullNameFromGoogleTokenPayload } from '../utils/googleOAuth2.js';

export const findSessionByToken = (token) =>
  Session.findOne({
    accessToken: token,
  });

export const findUserById = (id) => User.findById(id);

// ======================================= REGISTER

export const registerUser = async (userData) => {
  const alreadyExistingUser = await User.findOne({ email: userData.email });
  if (alreadyExistingUser !== null) {
    throw createHttpError(409, 'Email in use');
  }
  const encryptedPassword = await bcrypt.hash(userData.password, 10);
  const newUser = await User.create({
    ...userData,
    password: encryptedPassword,
  });
  const newSession = createSession(newUser._id);
  return await Session.create(newSession);
};

// ========================================= LOGIN

export const loginUser = async (userData) => {
  const user = await User.findOne({
    email: userData.email,
  });
  if (!user) {
    throw createHttpError(401, 'Anauthorized');
  }
  const isCorrectPassowrd = await bcrypt.compare(
    userData.password,
    user.password,
  );
  if (!isCorrectPassowrd) {
    throw createHttpError(401, 'Anauthorized');
  }

  await Session.deleteOne({
    userId: user._id,
  });

  const newSession = createSession(user._id);
  const session = await Session.create(newSession);
  return {
    session,
    name: user.name,
  };
};

// =================================== REFRESH

export const refreshUsersSession = async ({ refreshToken, sessionId }) => {
  const session = await Session.findOne({
    _id: sessionId,
    refreshToken,
  });
  if (!session) {
    throw createHttpError(401, 'Session not found');
  }
  const isRefreshTokenExpired =
    new Date() > new Date(session.refreshTokenValidUntil);
  if (isRefreshTokenExpired) {
    throw createHttpError(401, 'Session token expired');
  }

  await Session.deleteOne({
    _id: sessionId,
    refreshToken,
  });

  const newSession = createSession(session.userId);

  return Session.create(newSession);
};

// ===================================== LOGOUT

export const logOut = (sessionId) => Session.deleteOne({ _id: sessionId });

// ==================================== REQUEST RESET PASSWORD EMAIL

export const requestResetEmail = async (email) => {
  const user = await User.findOne({ email });
  if (!user) {
    throw createHttpError(404, 'User not found');
  }

  const resetToken = jwt.sign(
    {
      sub: user._id,
      email,
    },
    env('JWT_SECRET'),
    {
      expiresIn: '5m',
    },
  );

  const resetPasswordTemplatePath = path.join(
    TEMPLATES_DIR,
    'reset-password-email.html',
  );

  const resetPasswordTemplateSource = (
    await fs.readFile(resetPasswordTemplatePath)
  ).toString();

  const resetPasswordTemplate = Handlebars.compile(resetPasswordTemplateSource);
  const html = resetPasswordTemplate({
    name: user.name,
    link: `${env('APP_DOMAIN')}/reset-password?token=${resetToken}`,
  });

  const messageContent = {
    from: env(SMTP.SMTP_FROM),
    to: email,
    subject: 'Reset password',
    html,
  };

  try {
    await sendEmail(messageContent);
  } catch {
    throw createHttpError(
      500,
      'Failed to send the email, please try again later.',
    );
  }
};

// ============================== RESET PASSWORD

export const resetPassword = async (userData) => {
  const { password, token } = userData;

  let entries;

  try {
    entries = jwt.verify(token, env('JWT_SECRET'));
  } catch (error) {
    if (error instanceof Error)
      throw createHttpError(401, 'Token is expired or invalid');
    throw error;
  }

  const user = await User.findOne({
    _id: entries.sub,
    email: entries.email,
  });

  if (!user) throw createHttpError(404, 'User not found');

  const encryptedPassword = await bcrypt.hash(password, 10);

  await Session.deleteOne({
    userId: user._id,
  });

  await User.updateOne(
    {
      _id: user._id,
    },
    { password: encryptedPassword },
  );
};

// ========================== LOGIN OR SIGNUP WITH GOOGLE

export const loginOrSignupWithGoogle = async (code) => {
  const loginTicket = await validateCode(code);
  const payload = loginTicket.getPayload();
  if (!payload) throw createHttpError(401);

  let user = await User.findOne({ email: payload.email });

  if (!user) {
    const password = bcrypt.hash(randomBytes(10), 10);
    user = User.create({
      email: payload.email,
      password,
      name: getFullNameFromGoogleTokenPayload(payload),
    });
  }

  console.log(user);

  await Session.deleteOne({
    userId: user._id,
  });

  const newSession = createSession(user._id);

  return await Session.create(newSession);
};
