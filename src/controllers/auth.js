import {
  registerUser,
  loginUser,
  logOut,
  refreshUsersSession,
  requestResetEmail,
  resetPassword,
  loginOrSignupWithGoogle,
} from '../services/auth.js';
import { setupCookies } from '../utils/authUtils.js';
import { generateAuthUrl } from '../utils/googleOAuth2.js';

// ========================================== REGISTER

export const registerUserController = async (req, res) => {
  const { name, email, password } = req.body;
  const userData = {
    name,
    email,
    password,
  };

  const createdUser = await registerUser(userData);

  res.status(201).json({ createdUser });
};

// ======================================= LOGIN

export const loginUserController = async (req, res) => {
  const { email, password } = req.body;
  const userData = {
    email,
    password,
  };
  const session = await loginUser(userData);

  setupCookies(res, session);

  res.status(200).json({
    accessToken: session.accessToken,
  });
};

// ============================== REFRESH

export const refreshUserSessionController = async (req, res) => {
  const session = await refreshUsersSession({
    sessionId: req.cookies.sessionId,
    refreshToken: req.cookies.refreshToken,
  });

  setupCookies(res, session);

  res.status(200).json({
    accessToken: session.accessToken,
  });
};

// =============================== LOGOUT

export const logOutController = async (req, res) => {
  const { sessionId } = req.cookies;
  if (sessionId) {
    await logOut(sessionId);
  }

  res.clearCookie('sessionId');
  res.clearCookie('refreshToken');

  res.status(204).send();
};

// ============================ REQUEST RESET PASSWORD

export const requestResetEmailController = async (req, res) => {
  const { email } = req.body;
  await requestResetEmail(email);
  res.status(200).json({
    message: 'Reset password email has been successfully sent.',
  });
};

//  ============================ RESET PASSWORD

export const resetPasswordController = async (req, res) => {
  await resetPassword({ password: req.body.password, token: req.body.token });
  res.status(200).json({
    message: 'Password has been successfully reset.',
  });
};

// ============================= GOOGLE AUTH

export const getGoogleOAuthUrlController = (req, res) => {
  const url = generateAuthUrl();

  res.status(200).json({
    message: 'Successfully got Google OAuth url',
    url,
  });
};

// ============================ LOGIN OR SIGN UP WITH AUTH

export const loginOrSignupWithGoogleController = async (req, res) => {
  const session = await loginOrSignupWithGoogle(req.body.code);
  setupCookies(res, session);

  res.status(200).json({
    accessToken: session.accessToken,
  });
};
