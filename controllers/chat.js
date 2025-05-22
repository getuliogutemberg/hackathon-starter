const User = require('../models/User');
const Message = require('../models/Message');
const crypto = require('crypto');

// Função auxiliar para gerar URL do Gravatar
const getGravatarUrl = (email, size = 200) => {
  if (!email) {
    return `https://gravatar.com/avatar/00000000000000000000000000000000?s=${size}&d=retro`;
  }
  const md5 = crypto.createHash('md5').update(email.toLowerCase()).digest('hex');
  return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find({})
      .select('profile email online lastSeen');

    // Conta mensagens não lidas para cada usuário
    const usersWithUnread = await Promise.all(users.map(async (otherUser) => {
      const unreadCount = await Message.countDocuments({
        sender: otherUser._id,
        recipient: req.user._id,
        read: false
      });

      return {
        ...otherUser.toObject(),
        unreadCount,
        gravatarUrl: getGravatarUrl(otherUser.email)
      };
    }));

    res.render('chat/users', {
      title: 'Chat',
      users: usersWithUnread
    });
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao carregar usuários' });
    res.redirect('/');
  }
};

exports.getConversation = async (req, res) => {
  try {
    const otherUser = await User.findById(req.params.userId)
      .select('profile email online lastSeen');

    if (!otherUser) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/chat');
    }

    // Busca mensagens da conversa
    const messages = await Message.find({
      $or: [
        { sender: req.user._id, recipient: otherUser._id },
        { sender: otherUser._id, recipient: req.user._id }
      ]
    }).sort('createdAt');

    // Marca mensagens como lidas
    await Message.updateMany(
      { sender: otherUser._id, recipient: req.user._id, read: false },
      { read: true }
    );

    res.render('chat/conversation', {
      title: `Chat com ${otherUser.profile.name || otherUser.email}`,
      otherUser: {
        ...otherUser.toObject(),
        gravatarUrl: getGravatarUrl(otherUser.email)
      },
      messages
    });
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao carregar conversa' });
    res.redirect('/chat');
  }
}; 