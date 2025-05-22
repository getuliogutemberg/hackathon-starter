const crypto = require('crypto');
const bcrypt = require('@node-rs/bcrypt');
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  passwordResetToken: String,
  passwordResetExpires: Date,
  emailVerificationToken: String,
  emailVerified: Boolean,

  snapchat: String,
  facebook: String,
  twitter: String,
  google: String,
  github: String,
  linkedin: String,
  steam: String,
  twitch: String,
  quickbooks: String,
  tokens: Array,

  profile: {
    name: String,
    gender: String,
    location: String,
    website: String,
    picture: String
  },

  isAdmin: {
    type: Boolean,
    default: false
  },

  carteira: {
    pontos: { type: Number, default: 0 },
    premios: { type: Number, default: 0 },
    historico: [{
      tipo: { 
        type: String, 
        enum: ['compra', 'uso', 'bonus', 'premio', 'deposito', 'admin', 'saque']
      },
      quantidade: Number,
      corrida: { type: mongoose.Schema.Types.ObjectId, ref: 'Race' },
      data: { type: Date, default: Date.now },
      isPremio: { type: Boolean, default: false },
      posicao: { type: Number },
      adminNote: String
    }]
  }
}, { timestamps: true });

/**
 * Password hash middleware.
 */
userSchema.pre('save', async function save(next) {
  const user = this;
  if (!user.isModified('password')) { return next(); }
  try {
    user.password = await bcrypt.hash(user.password, 10);
    next();
  } catch (err) {
    next(err);
  }
});

/**
 * Helper method for validating user's password.
 */
userSchema.methods.comparePassword = async function comparePassword(candidatePassword, cb) {
  try {
    cb(null, await bcrypt.verify(candidatePassword, this.password));
  } catch (err) {
    cb(err);
  }
};

/**
 * Helper method for getting user's gravatar.
 */
userSchema.methods.gravatar = function gravatar(size) {
  if (!size) {
    size = 200;
  }
  if (!this.email) {
    return `https://gravatar.com/avatar/00000000000000000000000000000000?s=${size}&d=retro`;
  }
  const md5 = crypto.createHash('md5').update(this.email).digest('hex');
  
  return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
