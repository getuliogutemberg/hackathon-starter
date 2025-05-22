const { promisify } = require('util');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const _ = require('lodash');
const validator = require('validator');
const mailChecker = require('mailchecker');
const User = require('../models/User');
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

/**
 * GET /login
 * Login page.
 */
exports.getLogin = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login', {
    title: 'Login'
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });
  if (validator.isEmpty(req.body.password)) validationErrors.push({ msg: 'A chave não pode ficar em branco.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/login');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });

  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Sucesso! Você está logado.' });
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
    title: 'Create Account'
  });
};

/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = async (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'A chave deve ter pelo menos 8 caracteres' });
  if (validator.escape(req.body.password) !== validator.escape(req.body.confirmPassword)) validationErrors.push({ msg: 'As chaves não coincidem' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/signup');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      req.flash('errors', { msg: 'Já existe uma conta com esse endereço de e-mail.' });
      return res.redirect('/signup');
    }
    const user = new User({
      email: req.body.email,
      password: req.body.password
    });
    await user.save();
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
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
    title: 'Account Management'
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
exports.postUpdateProfile = async (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });
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
      req.flash('errors', { msg: 'O endereço de e-mail que você digitou já está associado a uma conta.' });
      return res.redirect('/account');
    }
    next(err);
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
    const tokensWithoutProviderToUnlink = user.tokens.filter((token) =>
      token.kind !== provider.toLowerCase());
    // Some auth providers do not provide an email address in the user profile.
    // As a result, we need to verify that unlinking the provider is safe by ensuring
    // that another login method exists.
    if (
      !(user.email && user.password)
      && tokensWithoutProviderToUnlink.length === 0
    ) {
      req.flash('errors', {
        msg: `${_.startCase(_.toLower(provider))} a conta não pode ser desvinculada sem outra forma de login habilitada.`
        + ' Vincule outra conta ou adicione um endereço de e-mail e chave.'
      });
      return res.redirect('/account');
    }
    user.tokens = tokensWithoutProviderToUnlink;
    await user.save();
    req.flash('info', {
      msg: `${_.startCase(_.toLower(provider))} a conta foi desvinculada.`,
    });
    res.redirect('/account');
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
    if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Token inválido.  Por favor, tente novamente.' });
    if (validationErrors.length) {
      req.flash('errors', validationErrors);
      return res.redirect('/forgot');
    }

    const user = await User.findOne({
      passwordResetToken: req.params.token,
      passwordResetExpires: { $gt: Date.now() }
    }).exec();
    if (!user) {
      req.flash('errors', { msg: 'O token de redefinição de senha é inválido ou expirou.' });
      return res.redirect('/forgot');
    }
    res.render('account/reset', {
      title: 'Password Reset'
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * GET /account/verify/:token
 * Verify email address
 */
exports.getVerifyEmailToken = (req, res, next) => {
  if (req.user.emailVerified) {
    req.flash('info', { msg: 'O endereço de e-mail foi verificado.' });
    return res.redirect('/account');
  }

  const validationErrors = [];
  if (validator.escape(req.params.token) && (!validator.isHexadecimal(req.params.token))) validationErrors.push({ msg: 'Token inválido.  Por favor, tente novamente.' });
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }

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
    return res.redirect('/account');
  }
};

/**
 * GET /account/verify
 * Verify email address
 */
exports.getVerifyEmail = (req, res, next) => {
  if (req.user.emailVerified) {
    req.flash('info', { msg: 'O endereço de e-mail foi verificado.' });
    return res.redirect('/account');
  }

  if (!mailChecker.isValid(req.user.email)) {
    req.flash('errors', { msg: 'O endereço de e-mail é inválido ou descartável e não pode ser verificado.  Atualize seu endereço de e-mail e tente novamente.' });
    return res.redirect('/account');
  }

  const createRandomToken = randomBytesAsync(16)
    .then((buf) => buf.toString('hex'));

  const setRandomToken = (token) => {
    User
      .findOne({ email: req.user.email })
      .then((user) => {
        user.emailVerificationToken = token;
        user = user.save();
      });
    return token;
  };

  const sendVerifyEmail = (token) => {
    const mailOptions = {
      to: req.user.email,
      from: process.env.SITE_CONTACT_EMAIL,
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

  createRandomToken
    .then(setRandomToken)
    .then(sendVerifyEmail)
    .then(() => res.redirect('/account'))
    .catch(next);
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isLength(req.body.password, { min: 8 })) validationErrors.push({ msg: 'A chaves deve ter pelo menos 8 caracteres' });
  if (validator.escape(req.body.password) !== validator.escape(req.body.confirm)) validationErrors.push({ msg: 'As chaves não coincidem' });
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({ msg: 'Token inválido.  Por favor, tente novamente.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('back');
  }

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

  const sendResetPasswordEmail = (user) => {
    if (!user) { return; }
    const mailOptions = {
      to: user.email,
      from: process.env.SITE_CONTACT_EMAIL,
      subject: 'Sua senha do ModuloApp foi alterada',
      text: `Olá,\n\nEsta é uma confirmação de que a chave da sua conta ${user.email} acabou de ser alterada.\n`
    };
    const mailSettings = {
      successfulType: 'success',
      successfulMsg: 'Sucesso! Sua cahve foi alterada.',
      loggingError: 'ERRO: Não foi possível enviar o e-mail de confirmação de redefinição de senha após o downgrade de segurança.\n',
      errorType: 'warning',
      errorMsg: 'Sua chave foi alterada, porém não foi possível enviar um e-mail de confirmação. Estaremos investigando isso em breve.',
      mailOptions,
      req
    };
    return sendMail(mailSettings);
  };

  resetPassword()
    .then(sendResetPasswordEmail)
    .then(() => { if (!res.finished) res.redirect('/'); })
    .catch((err) => next(err));
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
    title: 'Forgot Password'
  });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/forgot');
  }
  req.body.email = validator.normalizeEmail(req.body.email, { gmail_remove_dots: false });

  const createRandomToken = randomBytesAsync(16)
    .then((buf) => buf.toString('hex'));

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

  const sendForgotPasswordEmail = (user) => {
    if (!user) { return; }
    const token = user.passwordResetToken;
    const mailOptions = {
      to: user.email,
      from: process.env.SITE_CONTACT_EMAIL,
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

  createRandomToken
    .then(setRandomToken)
    .then(sendForgotPasswordEmail)
    .then(() => res.redirect('/forgot'))
    .catch(next);
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
