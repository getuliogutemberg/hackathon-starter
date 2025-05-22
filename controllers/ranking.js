const User = require('../models/User');
const Race = require('../models/Race');
const crypto = require('crypto');

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
    // Busca todos os usuários com populate completo do histórico
    const users = await User.find({})
      .select('profile email carteira')
      .lean(); // Usa lean() para melhor performance

    // Para cada usuário, calcula o total de premiações e adiciona URL do gravatar
    const usersWithStats = await Promise.all(users.map(async (user) => {
      // Garante que o objeto profile existe
      user.profile = user.profile || {};
      
      // Calcula total de premiações (soma de todos os prêmios recebidos)
      const totalPremiacoes = user.carteira?.historico
        ? user.carteira.historico
            .filter(t => t.tipo === 'premio')
            .reduce((acc, t) => acc + (t.quantidade || 0), 0)
        : 0;

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
        ...user,
        totalPremiacoes,
        vitorias,
        ultimaVitoria: ultimaVitoria?.createdAt,
        gravatarUrl: getGravatarUrl(user.email)
      };
    }));

    // Ordena por total de premiações (do maior para o menor)
    usersWithStats.sort((a, b) => b.totalPremiacoes - a.totalPremiacoes);

    res.render('ranking', {
      title: 'Ranking',
      users: usersWithStats,
      currentUser: req.user,
      isAdmin: req.user?.isAdmin
    });
  } catch (err) {
    console.error('Erro ao carregar ranking:', err);
    req.flash('error', { msg: 'Erro ao carregar ranking' });
    res.redirect('/');
  }
}; 