/**
 * Module dependencies.
 */
const path = require('path');
const express = require('express');
const compression = require('compression');
const session = require('express-session');
const bodyParser = require('body-parser');
const logger = require('morgan');
const errorHandler = require('errorhandler');
const lusca = require('lusca');
const dotenv = require('dotenv');
const MongoStore = require('connect-mongo');
const flash = require('express-flash');
const mongoose = require('mongoose');
const passport = require('passport');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const User = require('./models/User');
const chatController = require('./controllers/chat');
const Message = require('./models/Message');
const sharedsession = require('express-socket.io-session');
const adminController = require('./controllers/admin');
const cookieParser = require('cookie-parser');
const rankingController = require('./controllers/ranking');
const bankController = require('./controllers/bank');

/**
 * Create Express server.
 */
const app = express();
const server = require('http').Server(app);
const io = require('socket.io')(server);

const upload = multer({ dest: path.join(__dirname, 'uploads') });

/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.config({ path: '.env' });

/**
 * Set config values
 */
const secureTransfer = (process.env.BASE_URL.startsWith('https'));

// Consider adding a proxy such as cloudflare for production.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per `window` (here, per 15 minutes)
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// This logic fornumberOfProxies works for local testing, ngrok use, single host deployments
// behind cloudflare, etc. You may need to change it for more complex network settings.
// See readme.md for more info.
let numberOfProxies;
if (secureTransfer) numberOfProxies = 1; else numberOfProxies = 0;

/**
 * Controllers (route handlers).
 */
const homeController = require('./controllers/home');
const userController = require('./controllers/user');
const apiController = require('./controllers/api');
const contactController = require('./controllers/contact');

/**
 * API keys and Passport configuration.
 */
const passportConfig = require('./config/passport');

/**
 * Connect to MongoDB.
 */
mongoose.connect(process.env.MONGODB_URI);
mongoose.connection.on('error', (err) => {
  console.error(err);
  console.log('%s Erro de conexão do MongoDB. Certifique-se de que o MongoDB esteja em execução.');
  process.exit();
});

/**
 * Express configuration.
 */
app.set('host', process.env.OPENSHIFT_NODEJS_IP || '0.0.0.0');
app.set('port', process.env.PORT || process.env.OPENSHIFT_NODEJS_PORT || 8080);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.set('trust proxy', numberOfProxies);
app.use(compression());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(limiter);

// Configuração da sessão
const sessionMiddleware = session({
  resave: true,
  saveUninitialized: true,
  secret: process.env.SESSION_SECRET,
  name: 'startercookie',
  cookie: {
    maxAge: 1209600000,
    secure: secureTransfer
  },
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI })
});

// Usar a sessão no Express
app.use(sessionMiddleware);

// Usar a sessão no Socket.IO
io.use(sharedsession(sessionMiddleware, {
  autoSave: true
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Adicionar cookie-parser e middleware de tema ANTES do CSRF
app.use(cookieParser());

// Middleware para gerenciar tema
app.use((req, res, next) => {
  // Define o tema padrão como dark se não existir no cookie
  if (!req.cookies.theme) {
    res.cookie('theme', 'dark', { 
      maxAge: 31536000000, // 1 ano
      httpOnly: false,
      path: '/'
    });
  }
  // Passa o tema para todas as views
  res.locals.theme = req.cookies.theme || 'dark';
  next();
});

// Rota para alterar tema (deve vir ANTES do CSRF)
app.post('/theme/toggle', (req, res) => {
  const currentTheme = req.cookies.theme || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  
  // Define o cookie com opções adequadas
  res.cookie('theme', newTheme, { 
    maxAge: 31536000000, // 1 ano
    httpOnly: false,
    path: '/'
  });
  
  res.json({ theme: newTheme });
});

// DEPOIS vem o CSRF e outras configurações
app.use((req, res, next) => {
  if (req.path === '/api/upload' || 
      req.path === '/theme/toggle' || 
      req.path.includes('/corrida/') && req.path.includes('/mensagem')) {
    next();
  } else {
    lusca.csrf()(req, res, next);
  }
});

app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.xssProtection(true));
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});
app.use((req, res, next) => {
  // After successful login, redirect back to the intended page
  if (!req.user
    && req.path !== '/login'
    && req.path !== '/signup'
    && !req.path.match(/^\/auth/)
    && !req.path.match(/\./)) {
    req.session.returnTo = req.originalUrl;
  } else if (req.user
    && (req.path === '/account' || req.path.match(/^\/api/))) {
    req.session.returnTo = req.originalUrl;
  }
  next();
});
app.use('/', express.static(path.join(__dirname, 'public'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/chart.js/dist'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/@popperjs/core/dist/umd'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/js'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/jquery/dist'), { maxAge: 31557600000 }));
app.use('/webfonts', express.static(path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free/webfonts'), { maxAge: 31557600000 }));

/**
 * Primary app routes.
 */
app.get('/', homeController.index);
app.get('/login', userController.getLogin);
app.post('/login', userController.postLogin);
app.get('/logout', userController.logout);
app.get('/forgot', userController.getForgot);
app.post('/forgot', userController.postForgot);
app.get('/reset/:token', userController.getReset);
app.post('/reset/:token', userController.postReset);
app.get('/signup', userController.getSignup);
app.post('/signup', userController.postSignup);
app.get('/contact', contactController.getContact);
app.post('/contact', contactController.postContact);
app.get('/account/verify', passportConfig.isAuthenticated, userController.getVerifyEmail);
app.get('/account/verify/:token', passportConfig.isAuthenticated, userController.getVerifyEmailToken);
app.get('/account', passportConfig.isAuthenticated, userController.getAccount);
app.post('/account/profile', passportConfig.isAuthenticated, userController.postUpdateProfile);
app.post('/account/password', passportConfig.isAuthenticated, userController.postUpdatePassword);
app.post('/account/delete', passportConfig.isAuthenticated, userController.postDeleteAccount);
app.get('/account/unlink/:provider', passportConfig.isAuthenticated, userController.getOauthUnlink);

// Rotas da corrida
app.post('/corrida/criar', passportConfig.isAuthenticated, homeController.criarCorrida);
app.get('/corrida/:id', passportConfig.isAuthenticated, homeController.getSalaCorreda);
app.post('/corrida/:id/participar', passportConfig.isAuthenticated, homeController.participarCorrida);
app.post('/corrida/:id/interagir', passportConfig.isAuthenticated, homeController.interagirCorrida);
app.post('/corrida/:id/sair', passportConfig.isAuthenticated, homeController.sairCorrida);
app.post('/corrida/:id/iniciar', passportConfig.isAuthenticated, homeController.iniciarCorrida);
app.post('/corrida/:id/cancelar-contagem', passportConfig.isAuthenticated, homeController.cancelarContagem);
app.post('/corrida/:id/pausar', passportConfig.isAuthenticated, homeController.pausarCorrida);
app.post('/corrida/:id/retomar', passportConfig.isAuthenticated, homeController.retomarCorrida);
app.post('/corrida/:id/excluir', passportConfig.isAuthenticated, homeController.excluirCorrida);
app.post('/corrida/:id/mensagem', passportConfig.isAuthenticated, homeController.postMensagem);

// Rotas da carteira
app.get('/carteira', passportConfig.isAuthenticated, userController.getCarteira);
app.post('/carteira/comprar', passportConfig.isAuthenticated, userController.comprarPontos);
app.post('/carteira/depositar', passportConfig.isAuthenticated, userController.depositarDinheiro);
app.post('/carteira/sacar', passportConfig.isAuthenticated, userController.sacarDinheiro);

// Rota do ranking (acessível para todos)
app.get('/ranking', rankingController.getRanking);

// Rotas do chat
app.get('/chat', passportConfig.isAuthenticated, chatController.getUsers);
app.get('/chat/:userId', passportConfig.isAuthenticated, chatController.getConversation);

// Rota do relatório bancário (apenas admin)
app.get('/bank', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) {
    req.flash('error', { msg: 'Acesso restrito a administradores' });
    return res.redirect('/');
  }
  next();
}, bankController.getBankReport);

/**
 * API examples routes.
 */
app.get('/api', apiController.getApi);
app.get('/api/lastfm', apiController.getLastfm);
app.get('/api/nyt', apiController.getNewYorkTimes);
app.get('/api/steam', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getSteam);
app.get('/api/stripe', apiController.getStripe);
app.post('/api/stripe', apiController.postStripe);
app.get('/api/scraping', apiController.getScraping);
app.get('/api/twilio', apiController.getTwilio);
app.post('/api/twilio', apiController.postTwilio);
app.get('/api/foursquare', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getFoursquare);
app.get('/api/tumblr', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getTumblr);
app.get('/api/facebook', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getFacebook);
app.get('/api/github', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getGithub);
app.get('/api/twitch', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getTwitch);
app.get('/api/paypal', apiController.getPayPal);
app.get('/api/paypal/success', apiController.getPayPalSuccess);
app.get('/api/paypal/cancel', apiController.getPayPalCancel);
app.get('/api/lob', apiController.getLob);
app.get('/api/upload', lusca({ csrf: true }), apiController.getFileUpload);
app.post('/api/upload', upload.single('myFile'), lusca({ csrf: true }), apiController.postFileUpload);
app.get('/api/pinterest', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getPinterest);
app.post('/api/pinterest', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.postPinterest);
app.get('/api/here-maps', apiController.getHereMaps);
app.get('/api/google-maps', apiController.getGoogleMaps);
app.get('/api/google/drive', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getGoogleDrive);
app.get('/api/chart', apiController.getChart);
app.get('/api/google/sheets', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getGoogleSheets);
app.get('/api/quickbooks', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getQuickbooks);

/**
 * OAuth authentication routes. (Sign in)
 */
app.get('/auth/snapchat', passport.authenticate('snapchat'));
app.get('/auth/snapchat/callback', passport.authenticate('snapchat', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'public_profile'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/github', passport.authenticate('github'));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email', 'https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/spreadsheets.readonly'], accessType: 'offline', prompt: 'consent' }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/twitter', passport.authenticate('twitter'));
app.get('/auth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/linkedin', passport.authenticate('linkedin', { state: 'SOME STATE' }));
app.get('/auth/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/twitch', passport.authenticate('twitch', {}));
app.get('/auth/twitch/callback', passport.authenticate('twitch', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});

/**
 * OAuth authorization routes. (API examples)
 */
app.get('/auth/foursquare', passport.authorize('foursquare'));
app.get('/auth/foursquare/callback', passport.authorize('foursquare', { failureRedirect: '/api' }), (req, res) => {
  res.redirect('/api/foursquare');
});
app.get('/auth/tumblr', passport.authorize('tumblr'));
app.get('/auth/tumblr/callback', passport.authorize('tumblr', { failureRedirect: '/api' }), (req, res) => {
  res.redirect('/api/tumblr');
});
app.get('/auth/steam', passport.authorize('steam-openid', { state: 'SOME STATE' }));
app.get('/auth/steam/callback', passport.authorize('steam-openid', { failureRedirect: '/api' }), (req, res) => {
  res.redirect(req.session.returnTo);
});
app.get('/auth/pinterest', passport.authorize('pinterest', { scope: 'read_public write_public' }));
app.get('/auth/pinterest/callback', passport.authorize('pinterest', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/api/pinterest');
});
app.get('/auth/quickbooks', passport.authorize('quickbooks', { scope: ['com.intuit.quickbooks.accounting'], state: 'SOME STATE' }));
app.get('/auth/quickbooks/callback', passport.authorize('quickbooks', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo);
});

// Rota para tornar usuário admin (requer chave secreta)
app.post('/make-admin', async (req, res) => {
  try {
    const { userId, secretKey } = req.body;

    // Verifica se a chave secreta está correta
    if (secretKey !== process.env.ADMIN_SECRET_KEY) {
      req.flash('error', { msg: 'Chave secreta inválida' });
      return res.redirect('/');
    }

    // Atualiza o usuário para admin
    const user = await User.findById(userId);
    if (!user) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/');
    }

    user.isAdmin = true;
    await user.save();

    req.flash('success', { msg: 'Usuário promovido a administrador com sucesso!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao promover usuário a administrador' });
    res.redirect('/');
  }
});

// Rota para remover admin
app.post('/remove-admin', async (req, res) => {
  try {
    const { userId, secretKey } = req.body;

    // Verifica se a chave secreta está correta
    if (secretKey !== process.env.ADMIN_SECRET_KEY) {
      req.flash('error', { msg: 'Chave secreta inválida' });
      return res.redirect('/');
    }

    // Atualiza o usuário removendo admin
    const user = await User.findById(userId);
    if (!user) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/');
    }

    user.isAdmin = false;
    await user.save();

    req.flash('success', { msg: 'Privilégios de administrador removidos com sucesso!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao remover privilégios de administrador' });
    res.redirect('/');
  }
});

// Rotas admin
app.get('/admin/user/:userId', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) {
    req.flash('error', { msg: 'Acesso restrito a administradores' });
    return res.redirect('/');
  }
  next();
}, adminController.getUserPanel);

app.post('/admin/user/:userId/send-points', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) return res.redirect('/');
  next();
}, adminController.sendPoints);

app.post('/admin/user/:userId/send-prize', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) return res.redirect('/');
  next();
}, adminController.sendPrize);

app.post('/admin/user/:userId/disable', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) return res.redirect('/');
  next();
}, adminController.toggleUserStatus);

app.post('/admin/user/:userId/enable', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) return res.redirect('/');
  next();
}, adminController.toggleUserStatus);

// Rotas de admin para gerenciar corridas
app.get('/races', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) {
    req.flash('error', { msg: 'Acesso restrito a administradores' });
    return res.redirect('/');
  }
  next();
}, adminController.getRaces);

app.post('/races/:id/update', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) return res.redirect('/');
  next();
}, adminController.updateRace);

app.post('/races/:id/delete', passportConfig.isAuthenticated, (req, res, next) => {
  if (!req.user.isAdmin) return res.redirect('/');
  next();
}, adminController.deleteRace);

/**
 * Error Handler.
 */
app.use((req, res, next) => {
  const err = new Error('Not Found');
  err.status = 404;
  res.status(404).send('Página não encontrada');
});

if (process.env.NODE_ENV === 'development') {
  // only use in development
  app.use(errorHandler());
} else {
  app.use((err, req, res) => {
    console.error(err);
    res.status(500).send('Erro no servidor');
  });
}

/**
 * Start Express server.
 */
server.listen(app.get('port'), () => {
  const { BASE_URL } = process.env;
  const colonIndex = BASE_URL.lastIndexOf(':');
  const port = parseInt(BASE_URL.slice(colonIndex + 1), 10);

  if (!BASE_URL.startsWith('http://localhost')) {
    console.log(`A variável BASE_URL está definida como ${BASE_URL}.Se você testar diretamente o aplicativo por meio http://localhost:${app.get('port')} em vez de BASE_URL, pode causar uma incompatibilidade de CSRF ou uma falha de autenticação Oauth. Para evitar problemas, altere BASE_URL ou configure seu proxy para corresponder a ele.\n`);
  } else if (app.get('port') !== port) {
    console.warn(`AVISO: A variável de ambiente BASE_URL e o aplicativo têm uma incompatibilidade de porta. Se você planeja visualizar o aplicativo em seu navegador usando o endereço localhost, pode ser necessário ajustar uma das portas para que correspondam. BASE_URL: ${BASE_URL}\n`);
  }

  console.log(`O aplicativo está sendo executado em http://localhost:${app.get('port')} em modo ${app.get('env')}.`);
  console.log('Pressione CTRL-C para parar.');
});

// Socket.io connection handling
io.on('connection', async (socket) => {
  // Armazena o ID do usuário no socket usando a sessão compartilhada
  if (socket.handshake.session.passport) {
    const User = require('./models/User');
    const user = await User.findById(socket.handshake.session.passport.user);
    socket.user = user;
  }

  console.log(`Novo usuário conectado: ${socket.user?.profile?.name}`);

  // Handler para mensagens privadas
  socket.on('private-message', async (data) => {
    if (!socket.user) return;

    try {
      const message = new Message({
        sender: socket.user._id,
        recipient: data.recipient,
        content: data.content,
        createdAt: new Date()
      });
      await message.save();

      io.emit('private-message', {
        messageId: message._id,
        sender: socket.user._id,
        recipient: data.recipient,
        content: data.content,
        createdAt: message.createdAt
      });

    } catch (err) {
      console.error('Erro ao salvar mensagem:', err);
    }
  });

  // Handler para notificação de digitação
  socket.on('typing', (data) => {
    if (!socket.user) return;
    socket.broadcast.emit('user-typing', {
      sender: socket.user._id,
      recipient: data.recipient
    });
  });

  socket.on('stop-typing', (data) => {
    if (!socket.user) return;
    socket.broadcast.emit('user-stop-typing', {
      sender: socket.user._id,
      recipient: data.recipient
    });
  });

  socket.on('disconnect', () => {
    console.log('Usuário desconectado');
  });
});

// Inicializa o io no controlador home
homeController.initIO(io);

module.exports = { app, io, server };
