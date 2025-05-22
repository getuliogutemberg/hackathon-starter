const validator = require('validator');
const nodemailerConfig = require('../config/nodemailer');

async function validateReCAPTCHA(token) {
  const response = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
    },
  });
  return response.json();
}

/**
 * GET /contact
 * Contact form page.
 */
exports.getContact = (req, res) => {
  const unknownUser = !req.user;

  if (!process.env.RECAPTCHA_SITE_KEY) {
    console.warn('\x1b[33mWARNING: RECAPTCHA_SITE_KEY is missing. Add a key to your .env, env variable, or use a WebApp Firewall with an interactive challenge before going to production.\x1b[0m');
  }

  res.render('contact', {
<<<<<<< HEAD
    title: 'Contato',
    sitekey: process.env.RECAPTCHA_SITE_KEY,
=======
    title: 'Contact',
    sitekey: process.env.RECAPTCHA_SITE_KEY || null, // Pass null if the key is missing
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
    unknownUser,
  });
};

/**
 * POST /contact
 * Send a contact form via Nodemailer.
 */
exports.postContact = async (req, res, next) => {
  const validationErrors = [];
  let fromName;
  let fromEmail;
  if (!req.user) {
    if (validator.isEmpty(req.body.name)) validationErrors.push({ msg: 'Por favor digite seu nome' });
    if (!validator.isEmail(req.body.email)) validationErrors.push({ msg: 'Insira um endereço de e-mail válido.' });
  }
  if (validator.isEmpty(req.body.message)) validationErrors.push({ msg: 'Por favor, digite sua mensagem.' });

  if (!process.env.RECAPTCHA_SITE_KEY) {
    console.warn('\x1b[33mWARNING: RECAPTCHA_SITE_KEY is missing. Add a key to your .env or use a WebApp Firewall for CAPTCHA validation before going to production.\x1b[0m');
  } else if (!validator.isEmpty(req.body['g-recaptcha-response'])) {
    try {
      const reCAPTCHAResponse = await validateReCAPTCHA(req.body['g-recaptcha-response']);
      if (!reCAPTCHAResponse.success) {
        validationErrors.push({ msg: 'reCAPTCHA validation failed.' });
      }
    } catch (error) {
      console.error('Error validating reCAPTCHA:', error);
      validationErrors.push({ msg: 'Error validating reCAPTCHA. Please try again.' });
    }
  } else {
    validationErrors.push({ msg: 'reCAPTCHA response was missing.' });
  }

<<<<<<< HEAD
  try {
    const validateReCAPTCHA = await getValidateReCAPTCHA(req.body['g-recaptcha-response']);
    if (!validateReCAPTCHA.data.success) {
      validationErrors.push({ msg: 'A validação do reCAPTCHA falhou.' });
    }
=======
  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/contact');
  }
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242

  if (!req.user) {
    fromName = req.body.name;
    fromEmail = req.body.email;
  } else {
    fromName = req.user.profile.name || '';
    fromEmail = req.user.email;
  }

  const sendContactEmail = async () => {
    const mailOptions = {
      to: process.env.SITE_CONTACT_EMAIL,
      from: `${fromName} <${fromEmail}>`,
<<<<<<< HEAD
      subject: 'Contato | ModuloApp',
      text: req.body.message
    };

    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('success', { msg: 'O e-mail foi enviado com sucesso!' });
        res.redirect('/contact');
      })
      .catch((err) => {
        if (err.message === 'self signed certificate in certificate chain') {
          console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
          transportConfig.tls = transportConfig.tls || {};
          transportConfig.tls.rejectUnauthorized = false;
          transporter = nodemailer.createTransport(transportConfig);
          return transporter.sendMail(mailOptions);
        }
        console.log('ERROR: Could not send contact email after security downgrade.\n', err);
        req.flash('errors', { msg: 'Erro ao enviar a mensagem. Por favor, tente novamente em breve.' });
        return false;
      })
      .then((result) => {
        if (result) {
          req.flash('success', { msg: 'O e-mail foi enviado com sucesso!' });
          return res.redirect('/contact');
        }
      })
      .catch((err) => {
        console.log('ERROR: Could not send contact email.\n', err);
        req.flash('errors', { msg: 'Erro ao enviar a mensagem. Por favor, tente novamente em breve.' });
        return res.redirect('/contact');
      });
  } catch (err) {
    console.log(err);
=======
      subject: 'Contact Form | Hackathon Starter',
      text: req.body.message,
    };

    const mailSettings = {
      successfulType: 'info',
      successfulMsg: 'Email has been sent successfully!',
      loggingError: 'ERROR: Could not send contact email after security downgrade.\n',
      errorType: 'errors',
      errorMsg: 'Error sending the message. Please try again shortly.',
      mailOptions,
      req,
    };

    return nodemailerConfig.sendMail(mailSettings);
  };

  try {
    await sendContactEmail();
    res.redirect('/contact');
  } catch (error) {
    next(error);
>>>>>>> 1d136821bb80d251688e80ebce8407700fe1d242
  }
};
