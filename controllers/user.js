const crypto = require('crypto');
const passport = require('passport');
const validator = require('validator');
const mailChecker = require('mailchecker');
const User = require('../models/User');
<<<<<<< HEAD
const Race = require('../models/Race');

const randomBytesAsync = promisify(crypto.randomBytes);

/**
 * Helper Function to Send Mail.
 */
const sendMail = (settings) => {
  const transportConfig = {
    host: process.env.SMTP_HOST,
    port: 465,
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD
    }
  };

  let transporter = nodemailer.createTransport(transportConfig);

  return transporter.sendMail(settings.mailOptions)
    .then(() => {
      settings.req.flash(settings.successfulType, { msg: settings.successfulMsg });
    })
    .catch((err) => {
      if (err.message === 'self signed certificate in certificate chain') {
        console.log('AVISO: Certificado autoassinado na cadeia de certificados. Tentando novamente com o certificado autoassinado. Use um certificado válido se estiver em produção.');
        transportConfig.tls = transportConfig.tls || {};
        transportConfig.tls.rejectUnauthorized = false;
        transporter = nodemailer.createTransport(transportConfig);
        return transporter.sendMail(settings.mailOptions)
          .then(() => {
            settings.req.flash(settings.successfulType, { msg: settings.successfulMsg });
          });
      }
      console.log(settings.loggingError, err);
      settings.req.flash(settings.errorType, { msg: settings.errorMsg });
      return err;
    });
};
=======
const Session = require('../models/Session');
const nodemailerConfig = require('../config/nodemailer');
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

/**
 * GET /login
 * Login page.
 */
exports.getLogin = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login', {
    title: 'Login',
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = async (req, res, next) => {
  const validationErrors = [];
<<<<<<< HEAD
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });
  if (validator.isEmpty(req.body.password)) validationErrors.push({ msg: 'A chave não pode ficar em branco.' });
=======
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/login');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });

  // Check if user wants to login by email link
  if (req.body.loginByEmailLink === 'on') {
    try {
      const user = await User.findOne({ email: { $eq: req.body.email } });
      if (!user) {
        console.log('Login by email link: User not found');
        // we need to show the same message as successfulMsg to avoid an enumeration vulnerability
        req.flash('info', { msg: 'We are sending further instructions to the email you provided, if there is an account with that email address in our system.' });
        return res.redirect('/login');
      }

      const token = await User.generateToken();
      user.loginToken = token;
      user.loginExpires = Date.now() + 900000; // 15 min
      user.loginIpHash = User.hashIP(req.ip);
      await user.save();

      const mailOptions = {
        to: user.email,
        from: process.env.SITE_CONTACT_EMAIL,
        subject: 'Login Link',
        text: `Hello,
Please click on the following link to log in:

${process.env.BASE_URL}/login/verify/${token}

If you didn't request this login, please ignore this email and make sure you can still access your account.

For security:
- Never share this link with anyone
- We'll never ask you to send us this link
- Only use this link on the same device/browser where you requested it
- This link will expire in 15 minutes and can only be used once

Thank you!\n`,
      };

      await nodemailerConfig.sendMail({
        mailOptions,
        successfulType: 'info',
        successfulMsg: 'We are sending further instructions to the email you provided, if there is an account with that email address in our system.',
        loggingError: 'ERROR: Could not send login by email link.',
        errorType: 'errors',
        errorMsg: 'We encountered an issue sending instructions. Please try again later.',
        req,
      });

      return res.redirect('/login');
    } catch (err) {
      next(err);
    }
  }

  // Regular password login
  if (validator.isEmpty(req.body.password)) {
    req.flash('errors', 'Password cannot be blank.');
    return res.redirect('/login');
  }
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
<<<<<<< HEAD
      if (err) { return next(err); }
      req.flash('success', { msg: 'Sucesso! Você está logado.' });
=======
      if (err) {
        return next(err);
      }
      req.flash('success', { msg: 'Success! You are logged in.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
      res.redirect(req.session.returnTo || '/');
    });
  })(req, res, next);
};

/**
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {
  req.logout((err) => {
    if (err) console.log('Erro: Falha ao sair.', err);
    req.session.destroy((err) => {
      if (err) console.log('Erro: Falha ao destruir a sessão durante o logout.', err);
      req.user = null;
      res.redirect('/');
    });
  });
};

/**
 * GET /signup
 * Signup page.
 */
exports.getSignup = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/signup', {
    title: 'Create Account',
  });
};

/**
 * Helper to send passwordless login link if a user is trying to create an account
 * but we already have an account for that email address.
 * This process with ambigious flash messages is a part of the security measure to
 * mitigate account enumeration attacks.
 */
async function sendPasswordlessLoginLinkIfUserExists(user, req) {
  const token = await User.generateToken();
  user.loginToken = token;
  user.loginExpires = Date.now() + 900000; // 15 min
  user.loginIpHash = User.hashIP(req.ip);
  await user.save();

  const mailOptions = {
    to: user.email,
    from: process.env.SITE_CONTACT_EMAIL,
    subject: 'Login Link',
    text: `Hello,
We found an existing account for this email. Please use the following link to log in:

${process.env.BASE_URL}/login/verify/${token}

If you didn't request this login, please ignore this email.

Once logged in, you can go to your profile page to set or change your password.

Thank you!\n`,
  };
  await nodemailerConfig.sendMail({
    mailOptions,
    successfulType: 'info',
    successfulMsg: 'An email has been sent to the email address you provided with further instructions.',
    loggingError: 'ERROR: Could not send login by email link.',
    errorType: 'errors',
    errorMsg: 'We encountered an issue sending instructions. Please try again later.',
    req,
  });
}

/**
 * Helper to send passwordless signup link for new users.
 */
async function sendPasswordlessSignupLink(user, req) {
  const token = await User.generateToken();
  user.loginToken = token;
  user.loginExpires = Date.now() + 900000; // 15 min
  user.loginIpHash = User.hashIP(req.ip);
  await user.save();

  const mailOptions = {
    to: user.email,
    from: process.env.SITE_CONTACT_EMAIL,
    subject: 'Login Link',
    text: `Hello,
Please click on the following link to log in:

${process.env.BASE_URL}/login/verify/${token}

If you didn't request this login, please ignore this email and make sure you can still access your account.

For security:
- Never share this link with anyone
- We'll never ask you to send us this link
- Only use this link on the same device/browser where you requested it
- This link will expire in 15 minutes and can only be used once

Thank you!\n`,
  };

  await nodemailerConfig.sendMail({
    mailOptions,
    successfulType: 'info',
    successfulMsg: 'An email has been sent to the email address you provided with further instructions.',
    loggingError: 'ERROR: Could not send login by email link.',
    errorType: 'errors',
    errorMsg: 'Error sending login email. Please try again later.',
    req,
  });
}

/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = async (req, res, next) => {
  const validationErrors = [];
<<<<<<< HEAD
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'A chave deve ter pelo menos 8 caracteres' });
  if (validator.escape(req.body.password) !== validator.escape(req.body.confirmPassword)) validationErrors.push({ msg: 'As chaves não coincidem' });
=======
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });

  if (!req.body.passwordless) {
    if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'Password must be at least 8 characters long' });
    if (validator.escape(req.body.password) !== validator.escape(req.body.confirmPassword)) validationErrors.push({ msg: 'Passwords do not match' });
  }

>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/signup');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
  if (!mailChecker.isValid(req.body.email)) {
    req.flash('errors', { msg: 'The email address is invalid or disposable and can not be verified.  Please update your email address and try again.' });
    return res.redirect('/signup');
  }

  try {
    const existingUser = await User.findOne({ email: { $eq: req.body.email } });

    if (existingUser) {
<<<<<<< HEAD
      req.flash('errors', { msg: 'Já existe uma conta com esse endereço de e-mail.' });
      return res.redirect('/signup');
=======
      // Always send login link and generic message if email exists
      await sendPasswordlessLoginLinkIfUserExists(existingUser, req);
      return res.redirect('/login');
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    }

    // For passwordless signup, generate a random password
    const password = req.body.passwordless ? crypto.randomBytes(16).toString('hex') : req.body.password;
    const user = new User({
      email: req.body.email,
      password,
    });

    await user.save();

    if (req.body.passwordless) {
      await sendPasswordlessSignupLink(user, req);
      return res.redirect('/');
    }

    // For regular signup, log the user in
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      req.flash('success', { msg: 'Success! You are logged in.' });
      res.redirect('/');
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /account
 * Profile page.
 */
exports.getAccount = (req, res) => {
  res.render('account/profile', {
    title: 'Account Management',
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
exports.postUpdateProfile = async (req, res, next) => {
  const validationErrors = [];
<<<<<<< HEAD
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });

=======
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Please enter a valid email address.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
  if (!mailChecker.isValid(req.body.email)) {
    req.flash('errors', { msg: 'The email address is invalid or disposable and can not be verified.  Please update your email address and try again.' });
    return res.redirect('/account');
  }
  try {
    const user = await User.findById(req.user.id);
    if (user.email !== req.body.email) user.emailVerified = false;
    user.email = req.body.email || '';
    user.profile.name = req.body.name || '';
    user.profile.gender = req.body.gender || '';
    user.profile.location = req.body.location || '';
    user.profile.website = req.body.website || '';
    await user.save();
    req.flash('success', { msg: 'As informações do perfil foram atualizadas.' });
    res.redirect('/account');
  } catch (err) {
    if (err.code === 11000) {
<<<<<<< HEAD
      req.flash('errors', { msg: 'O endereço de e-mail que você digitou já está associado a uma conta.' });
      return res.redirect('/account');
=======
      console.log('Duplicate email address when trying to update the profile email.');
    } else {
      console.log('Error updating profile', err);
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    }
    // Generic error message for the user. Do not reveal the cause of the error tsuch as
    // the new email being in the system to the user to avoid enumeration vulenrability.
    req.flash('errors', {
      msg: "We encountered an issue updating your email address. If you suspect you have duplicate accounts, please log in with the other email address you've used or contact support for assistance. You can delete duplicate accounts from your account settings.",
    });
    return res.redirect('/account');
  }
};

/**
 * POST /account/password
 * Update current password.
 */
exports.postUpdatePassword = async (req, res, next) => {
  const validationErrors = [];
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'A chave deve ter pelo menos 8 caracteres' });
  if (validator.escape(req.body.password) !== validator.escape(req.body.confirmPassword)) validationErrors.push({ msg: 'As chaves não coincidem' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }
  try {
    const user = await User.findById(req.user.id);
    user.password = req.body.password;
    await user.save();
    req.flash('success', { msg: 'A chave foi alterada.' });
    res.redirect('/account');
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/delete
 * Delete user account.
 */
exports.postDeleteAccount = async (req, res, next) => {
  try {
    await User.deleteOne({ _id: req.user.id });
    req.logout((err) => {
      if (err) console.log('Erro: Falha ao sair.', err);
      req.session.destroy((err) => {
        if (err) console.log('Erro: Falha ao destruir a sessão durante a exclusão da conta.', err);
        req.user = null;
        res.redirect('/');
      });
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
exports.getOauthUnlink = async (req, res, next) => {
  try {
    let { provider } = req.params;
    provider = validator.escape(provider);
    const user = await User.findById(req.user.id);
    user[provider.toLowerCase()] = undefined;
    const tokensWithoutProviderToUnlink = user.tokens.filter((token) => token.kind !== provider.toLowerCase());
    // Some auth providers do not provide an email address in the user profile.
    // As a result, we need to verify that unlinking the provider is safe by ensuring
    // that another login method exists.
    if (!(user.email && user.password) && tokensWithoutProviderToUnlink.length === 0) {
      req.flash('errors', {
<<<<<<< HEAD
        msg: `${_.startCase(_.toLower(provider))} a conta não pode ser desvinculada sem outra forma de login habilitada.`
        + ' Vincule outra conta ou adicione um endereço de e-mail e chave.'
=======
        msg: `The ${provider.charAt(0).toUpperCase() + provider.slice(1).toLowerCase()} account cannot be unlinked without another form of login enabled. Please link another account or add an email address and password.`,
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
      });
      return res.redirect('/account');
    }
    user.tokens = tokensWithoutProviderToUnlink;
    await user.save();
    req.flash('info', {
<<<<<<< HEAD
      msg: `${_.startCase(_.toLower(provider))} a conta foi desvinculada.`,
=======
      msg: `${provider.charAt(0).toUpperCase() + provider.slice(1).toLowerCase()} account has been unlinked.`,
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    });
    res.redirect('/account');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /login/verify/:token
 * Login by email link
 */
exports.getLoginByEmail = async (req, res, next) => {
  if (req.user) {
    return res.redirect('/');
  }
  const validationErrors = [];
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Invalid or expired login link.' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/login');
  }

  try {
    const user = await User.findOne({ loginToken: { $eq: req.params.token } });

    if (!user || !user.verifyTokenAndIp(user.loginToken, req.ip, 'login')) {
      req.flash('errors', { msg: 'Invalid or expired login link.' });
      return res.redirect('/login');
    }

    user.emailVerified = true; // Mark email as verified since they also proved ownership
    await user.save();

    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      req.flash('success', { msg: 'Success! You are logged in.' });
      res.redirect(req.session.returnTo || '/');
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getReset = async (req, res, next) => {
  try {
    if (req.isAuthenticated()) {
      return res.redirect('/');
    }
    const validationErrors = [];
<<<<<<< HEAD
    if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Token inválido.  Por favor, tente novamente.' });
=======
    if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Invalid or expired password reset link.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    if (validationErrors.length) {
      req.flash('errors', validationErrors);
      return res.redirect('/forgot');
    }

<<<<<<< HEAD
    const user = await User.findOne({
      passwordResetToken: req.params.token,
      passwordResetExpires: { $gt: Date.now() }
    }).exec();
    if (!user) {
      req.flash('errors', { msg: 'O token de redefinição de senha é inválido ou expirou.' });
=======
    const user = await User.findOne({ passwordResetToken: { $eq: req.params.token } });
    if (!user || !user.verifyTokenAndIp(user.passwordResetToken, req.ip, 'passwordReset')) {
      req.flash('errors', { msg: 'Invalid or expired password reset link.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
      return res.redirect('/forgot');
    }
    res.render('account/reset', {
      title: 'Password Reset',
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /account/verify/:token
 * Verify email address
 */
exports.getVerifyEmailToken = async (req, res, next) => {
  if (req.user.emailVerified) {
    req.flash('info', { msg: 'O endereço de e-mail foi verificado.' });
    return res.redirect('/account');
  }

  const validationErrors = [];
<<<<<<< HEAD
  if (validator.escape(req.params.token) && (!validator.isHexadecimal(req.params.token))) validationErrors.push({ msg: 'Token inválido.  Por favor, tente novamente.' });
=======
  if (validator.escape(req.params.token) && !validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Invalid or expired verification link.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }

<<<<<<< HEAD
  if (req.params.token === req.user.emailVerificationToken) {
    User
      .findOne({ email: req.user.email })
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'Ocorreu um erro ao carregar seu perfil.' });
          return res.redirect('back');
        }
        user.emailVerificationToken = '';
        user.emailVerified = true;
        user = user.save();
        req.flash('info', { msg: 'Obrigado por verificar seu endereço de e-mail.' });
        return res.redirect('/account');
      })
      .catch((error) => {
        console.log('Erro ao salvar o perfil do usuário no banco de dados após verificação por e-mail', error);
        req.flash('errors', { msg: 'Ocorreu um erro ao atualizar seu perfil.  Por favor, tente novamente mais tarde.' });
        return res.redirect('/account');
      });
  } else {
    req.flash('errors', { msg: 'O link de verificação era inválido ou refere-se a uma conta diferente.' });
=======
  try {
    if (!req.user.verifyTokenAndIp(req.user.emailVerificationToken, req.ip, 'emailVerification')) {
      req.flash('errors', { msg: 'Invalid or expired verification link.' });
      return res.redirect('/account');
    }

    req.user.emailVerified = true;
    await req.user.save();

    req.flash('success', { msg: 'Thank you for verifying your email address.' });
    return res.redirect('/account');
  } catch (err) {
    console.log('Error saving the user profile to the database after email verification', err);
    req.flash('errors', { msg: 'There was an error verifying your email. Please try again.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    return res.redirect('/account');
  }
};

/**
 * GET /account/verify
 * Verify email address
 */
exports.getVerifyEmail = async (req, res, next) => {
  if (req.user.emailVerified) {
<<<<<<< HEAD
    req.flash('info', { msg: 'O endereço de e-mail foi verificado.' });
=======
    req.flash('info', { msg: 'The email address has already been verified.' });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    return res.redirect('/account');
  }

  if (!mailChecker.isValid(req.user.email)) {
    req.flash('errors', { msg: 'O endereço de e-mail é inválido ou descartável e não pode ser verificado.  Atualize seu endereço de e-mail e tente novamente.' });
    return res.redirect('/account');
  }

  try {
    const token = await User.generateToken();
    req.user.emailVerificationToken = token;
    req.user.emailVerificationExpires = Date.now() + 900000; // 15 minutes
    req.user.emailVerificationIpHash = User.hashIP(req.ip);
    await req.user.save();

    const mailOptions = {
      to: req.user.email,
      from: process.env.SITE_CONTACT_EMAIL,
<<<<<<< HEAD
      subject: 'Verifique seu endereço de e-mail no ModuloApp',
      text: `Obrigado por se registrar no ModuloApp\n\n
        Para verificar seu endereço de e-mail, clique no link a seguir ou cole-o em seu navegador:\n\n
        http://${req.headers.host}/account/verify/${token}\n\n
        \n\n
        Obrigado!`
    };
    const mailSettings = {
      successfulType: 'info',
      successfulMsg: `Um e-mail foi enviado para ${req.user.email} com mais instruções.`,
      loggingError: 'ERRO: não foi possível enviar o e-mail verifyEmail após o downgrade de segurança.\n',
      errorType: 'errors',
      errorMsg: 'Erro ao enviar a mensagem de verificação por e-mail. Por favor, tente novamente em breve.',
      mailOptions,
      req
    };
    return sendMail(mailSettings);
  };
=======
      subject: 'Please verify your email address',
      text: `Hello,
Please verify your email address by clicking on the following link:
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

${process.env.BASE_URL}/account/verify/${token}

For security:
- Never share this link with anyone
- We'll never ask you to send us this link
- Only use this link on the same device/browser where you requested it
- This link will expire in 15 minutes and can only be used once
  
Thank you!\n`,
    };

    await nodemailerConfig.sendMail({
      mailOptions,
      successfulType: 'info',
      successfulMsg: `An email has been sent to ${req.user.email} with verification instructions.`,
      loggingError: 'ERROR: Could not send verification email.',
      errorType: 'errors',
      errorMsg: 'Error sending verification email. Please try again later.',
      req,
    });

    return res.redirect('/account');
  } catch (err) {
    next(err);
  }
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = async (req, res, next) => {
  const validationErrors = [];
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'A chaves deve ter pelo menos 8 caracteres' });
  if (validator.escape(req.body.password) !== validator.escape(req.body.confirm)) validationErrors.push({ msg: 'As chaves não coincidem' });
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Token inválido.  Por favor, tente novamente.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect(req.get('Referrer') || '/');
  }

<<<<<<< HEAD
  const resetPassword = () =>
    User
      .findOne({ passwordResetToken: req.params.token })
      .where('passwordResetExpires').gt(Date.now())
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'O token de redefinição de senha é inválido ou expirou.' });
          return res.redirect('back');
        }
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        return user.save().then(() => new Promise((resolve, reject) => {
          req.logIn(user, (err) => {
            if (err) { return reject(err); }
            resolve(user);
          });
        }));
      });
=======
  try {
    const user = await User.findOne({ passwordResetToken: { $eq: req.params.token } });
    if (!user || !user.verifyTokenAndIp(user.passwordResetToken, req.ip, 'passwordReset')) {
      req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
      return res.redirect(user.get('Referrer') || '/');
    }
    user.password = req.body.password;
    user.emailVerified = true; // Mark email as verified as well since they proved ownership
    await user.save();
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

    const mailOptions = {
      to: user.email,
      from: process.env.SITE_CONTACT_EMAIL,
<<<<<<< HEAD
      subject: 'Sua senha do ModuloApp foi alterada',
      text: `Olá,\n\nEsta é uma confirmação de que a chave da sua conta ${user.email} acabou de ser alterada.\n`
=======
      subject: 'Your password has been changed',
      text: `This is a confirmation that the password for your account ${user.email} has just been changed.\n`,
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    };

    await nodemailerConfig.sendMail({
      mailOptions,
      successfulType: 'success',
<<<<<<< HEAD
      successfulMsg: 'Sucesso! Sua cahve foi alterada.',
      loggingError: 'ERRO: Não foi possível enviar o e-mail de confirmação de redefinição de senha após o downgrade de segurança.\n',
      errorType: 'warning',
      errorMsg: 'Sua chave foi alterada, porém não foi possível enviar um e-mail de confirmação. Estaremos investigando isso em breve.',
      mailOptions,
      req
    };
    return sendMail(mailSettings);
  };
=======
      successfulMsg: 'Success! Your password has been changed.',
      loggingError: 'ERROR: Could not send password reset confirmation email.',
      errorType: 'warning',
      errorMsg: 'Your password has been changed, but we could not send you a confirmation email. We will be looking into it.',
      req,
    });
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

    res.redirect('/');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /forgot
 * Forgot Password page.
 */
exports.getForgot = (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('account/forgot', {
    title: 'Forgot Password',
  });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = async (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/forgot');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });

  try {
    const user = await User.findOne({ email: { $eq: req.body.email.toLowerCase() } });
    if (!user) {
      console.log('Forgot password: User not found');
      // Generic message to avoid enumeration vunerability
      req.flash('info', { msg: 'If an account with that email exists, you will receive password reset instructions.' });
      return res.redirect('/forgot');
    }

<<<<<<< HEAD
  const setRandomToken = (token) =>
    User
      .findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'A conta com esse endereço de e-mail não existe.' });
        } else {
          user.passwordResetToken = token;
          user.passwordResetExpires = Date.now() + 3600000; // 1 hour
          user = user.save();
        }
        return user;
      });
=======
    const token = await User.generateToken();
    user.passwordResetToken = token;
    user.passwordResetExpires = Date.now() + 900000; // 15 minutes
    user.passwordResetIpHash = User.hashIP(req.ip);
    await user.save();
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

    const mailOptions = {
      to: user.email,
      from: process.env.SITE_CONTACT_EMAIL,
<<<<<<< HEAD
      subject: 'Redefina sua senha no ModuloApp',
      text: `Você está recebendo este e-mail porque você (ou outra pessoa) solicitou a redefinição da chave da sua conta.\n\n
        Clique no link a seguir ou cole-o em seu navegador para concluir o processo:\n\n
        http://${req.headers.host}/reset/${token}\n\n
        Se você não solicitou isso, ignore este e-mail e sua chave permanecerá inalterada.\n`
    };
    const mailSettings = {
      successfulType: 'info',
      successfulMsg: `Um e-mail foi enviado para ${user.email} com mais instruções.`,
      loggingError: 'ERRO: Não foi possível enviar e-mail com chave esquecida após o downgrade de segurança.\n',
      errorType: 'errors',
      errorMsg: 'Erro ao enviar a mensagem de redefinição de chave. Por favor, tente novamente em breve.',
      mailOptions,
      req
    };
    return sendMail(mailSettings);
  };
=======
      subject: 'Reset your password',
      text: `Hello,
You are receiving this email because you (or someone else) requested a password reset. Please click on the following link to complete the process:
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

${process.env.BASE_URL}/reset/${token}

If you did not request this, please ignore this email and your password will remain unchanged.

For security:
- Never share this link with anyone
- We'll never ask you to send us this link
- Only use this link on the same device/browser where you requested it
- This link will expire in 15 minutes and can only be used once

Thank you!\n`,
    };

    await nodemailerConfig.sendMail({
      mailOptions,
      successfulType: 'info',
      successfulMsg: `If an account with that email exists, you will receive password reset instructions.`,
      loggingError: 'ERROR: Could not send password reset email.',
      errorType: 'errors',
      errorMsg: 'We encountered an issue sending instructions. Please try again later.',
      req,
    });

    return res.redirect('/forgot');
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/logout-everywhere
 * Logout current user from all devices
 */
exports.postLogoutEverywhere = async (req, res, next) => {
  const userId = req.user.id;
  try {
    await Session.removeSessionByUserId(userId);
    req.logout((err) => {
      if (err) {
        return next(err);
      }
      req.flash('info', { msg: 'You have been logged out of all sessions.' });
      res.redirect('/');
    });
  } catch (err) {
    return next(err);
  }
};

exports.getCarteira = async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('carteira.historico.corrida', 'titulo');

    res.render('account/carteira', {
      title: 'Minha Carteira',
      user: user
    });
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao carregar carteira' });
    res.redirect('/');
  }
};

exports.comprarPontos = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const custoEmReais = 10; // Custo fixo de R$ 10 por 100 pontos
    
    // Verifica se tem saldo suficiente em prêmios
    if (user.carteira.premios >= custoEmReais) {
      // Deduz do saldo de prêmios
      user.carteira.premios -= custoEmReais;
      // Adiciona os pontos
      user.carteira.pontos += 100;
      
      // Registra a compra no histórico
      user.carteira.historico.push({
        tipo: 'compra',
        quantidade: 100,
        data: new Date(),
        isPremio: true, // Marca que usou prêmio para comprar
        valorPago: custoEmReais
      });

      await user.save();
      req.flash('success', { msg: `Compra realizada com sucesso! Você usou R$ ${custoEmReais.toFixed(2)} dos seus prêmios para comprar 100 pontos.` });
    } else {
      // Não tem saldo suficiente em prêmios
      req.flash('info', { 
        msg: `Você precisa depositar R$ ${custoEmReais.toFixed(2)} para comprar 100 pontos. 
              Seu saldo atual em prêmios é R$ ${user.carteira.premios.toFixed(2)}.` 
      });
    }
    
    res.redirect('/carteira');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao processar a compra de pontos' });
    res.redirect('/carteira');
  }
};

exports.depositarDinheiro = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const valorDeposito = 10; // Valor fixo de R$ 10,00
    
    // Adiciona o valor ao saldo de prêmios
    user.carteira.premios += valorDeposito;
    
    // Registra o depósito no histórico
    user.carteira.historico.push({
      tipo: 'deposito',
      quantidade: valorDeposito,
      data: new Date(),
      isPremio: true
    });

    await user.save();
    req.flash('success', { msg: `Depósito de R$ ${valorDeposito.toFixed(2)} realizado com sucesso!` });
    res.redirect('/carteira');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao processar o depósito' });
    res.redirect('/carteira');
  }
};

exports.sacarDinheiro = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const valorSaque = 10; // Valor fixo de R$ 10,00
    
    // Verifica se tem saldo suficiente
    if (user.carteira.premios < valorSaque) {
      req.flash('error', { msg: 'Saldo insuficiente para saque' });
      return res.redirect('/carteira');
    }
    
    // Deduz o valor do saldo
    user.carteira.premios -= valorSaque;
    
    // Registra o saque no histórico
    user.carteira.historico.push({
      tipo: 'saque',
      quantidade: -valorSaque,
      data: new Date(),
      isPremio: true,
      adminNote: 'Saque realizado com sucesso'
    });

    await user.save();
    req.flash('success', { msg: `Saque de R$ ${valorSaque.toFixed(2)} realizado com sucesso!` });
    res.redirect('/carteira');
  } catch (err) {
    console.error('Erro ao processar saque:', err);
    req.flash('error', { msg: 'Erro ao processar o saque' });
    res.redirect('/carteira');
  }
};

// Função auxiliar para gerar URL do Gravatar
const getGravatarUrl = (email, size = 200) => {
  if (!email) {
    return `https://gravatar.com/avatar/00000000000000000000000000000000?s=${size}&d=retro`;
  }
  const md5 = crypto.createHash('md5').update(email.toLowerCase()).digest('hex');
  return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

exports.getRanking = async (req, res) => {
  try {
    // Busca todos os usuários e ordena por total de premiações
    const users = await User.find({})
      .select('profile email carteira.premios carteira.pontos')
      .sort({ 'carteira.premios': -1 }); // Ordena por prêmios, do maior para o menor

    // Para cada usuário, calcula o total de premiações e adiciona URL do gravatar
    const usersWithStats = await Promise.all(users.map(async (user) => {
      // Calcula total de premiações (soma de todos os prêmios recebidos)
      const totalPremiacoes = user.carteira.historico
        .filter(t => t.tipo === 'premio')
        .reduce((acc, t) => acc + t.quantidade, 0);

      // Conta vitórias
      const vitorias = await Race.countDocuments({
        'podium.usuario': user._id,
        'podium.posicao': 1
      });

      // Busca última vitória
      const ultimaVitoria = await Race.findOne({
        'podium.usuario': user._id,
        'podium.posicao': 1
      })
      .sort({ createdAt: -1 })
      .select('createdAt');

      return {
        ...user.toObject(),
        totalPremiacoes,
        vitorias,
        ultimaVitoria: ultimaVitoria?.createdAt,
        gravatarUrl: getGravatarUrl(user.email)
      };
    }));

    res.render('ranking', {
      title: 'Ranking',
      users: usersWithStats,
      currentUser: req.user,
      isAdmin: req.user?.isAdmin // Passa se o usuário é admin para a view
    });
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao carregar ranking' });
    res.redirect('/');
  }
};
