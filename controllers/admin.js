const User = require('../models/User');
const Race = require('../models/Race');
let io; // Declaração global do io

// Função para inicializar o io
exports.initIO = (socketIO) => {
  io = socketIO;
};

exports.getUserPanel = async (req, res) => {
  try {
    const targetUser = await User.findById(req.params.userId)
      .populate('carteira.historico.corrida', 'titulo');

    if (!targetUser) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/ranking');
    }

    res.render('admin/user-panel', {
      title: 'Painel Admin',
      targetUser
    });
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao carregar painel do usuário' });
    res.redirect('/ranking');
  }
};

exports.sendPoints = async (req, res) => {
  try {
    // Verifica se está tentando enviar pontos para si mesmo
    if (req.params.userId === req.user.id) {
      req.flash('error', { msg: 'Não é possível enviar pontos para si mesmo' });
      return res.redirect(`/admin/user/${req.params.userId}`);
    }

    const targetUser = await User.findById(req.params.userId);
    if (!targetUser) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/ranking');
    }

    const points = parseInt(req.body.points, 10);
    if (isNaN(points) || points <= 0) {
      req.flash('error', { msg: 'Quantidade de pontos inválida' });
      return res.redirect(`/admin/user/${targetUser._id}`);
    }

    // Remove os pontos do admin
    const adminUser = await User.findById(req.user.id);
    if (adminUser.carteira.pontos < points) {
      req.flash('error', { msg: 'Você não tem pontos suficientes para enviar' });
      return res.redirect(`/admin/user/${targetUser._id}`);
    }

    // Deduz os pontos do admin
    adminUser.carteira.pontos -= points;
    adminUser.carteira.historico.push({
      tipo: 'admin',
      quantidade: -points,
      data: new Date(),
      adminNote: `Pontos enviados para ${targetUser.profile.name || targetUser.email}`
    });
    await adminUser.save();

    // Adiciona os pontos ao usuário alvo
    targetUser.carteira.pontos += points;
    targetUser.carteira.historico.push({
      tipo: 'admin',
      quantidade: points,
      data: new Date(),
      adminNote: `Pontos recebidos do admin ${req.user.profile.name}`
    });
    await targetUser.save();

    req.flash('success', { msg: `${points} pontos enviados com sucesso para ${targetUser.profile.name || targetUser.email}!` });
    res.redirect(`/admin/user/${targetUser._id}`);
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao enviar pontos' });
    res.redirect(`/admin/user/${req.params.userId}`);
  }
};

exports.sendPrize = async (req, res) => {
  try {
    // Verifica se está tentando enviar prêmio para si mesmo
    if (req.params.userId === req.user.id) {
      req.flash('error', { msg: 'Não é possível enviar prêmio para si mesmo' });
      return res.redirect(`/admin/user/${req.params.userId}`);
    }

    const targetUser = await User.findById(req.params.userId);
    if (!targetUser) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/ranking');
    }

    const prize = parseFloat(req.body.prize);
    if (isNaN(prize) || prize <= 0) {
      req.flash('error', { msg: 'Valor do prêmio inválido' });
      return res.redirect(`/admin/user/${targetUser._id}`);
    }

    // Remove o prêmio do admin
    const adminUser = await User.findById(req.user.id);
    if (adminUser.carteira.premios < prize) {
      req.flash('error', { msg: 'Você não tem saldo suficiente para enviar' });
      return res.redirect(`/admin/user/${targetUser._id}`);
    }

    // Deduz o prêmio do admin
    adminUser.carteira.premios -= prize;
    adminUser.carteira.historico.push({
      tipo: 'admin',
      quantidade: -prize,
      data: new Date(),
      isPremio: true,
      adminNote: `Prêmio enviado para ${targetUser.profile.name || targetUser.email}`
    });
    await adminUser.save();

    // Adiciona o prêmio ao usuário alvo
    targetUser.carteira.premios += prize;
    targetUser.carteira.historico.push({
      tipo: 'admin',
      quantidade: prize,
      data: new Date(),
      isPremio: true,
      adminNote: `Prêmio recebido do admin ${req.user.profile.name}`
    });
    await targetUser.save();

    req.flash('success', { msg: `Prêmio de R$ ${prize.toFixed(2)} enviado com sucesso para ${targetUser.profile.name || targetUser.email}!` });
    res.redirect(`/admin/user/${targetUser._id}`);
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao enviar prêmio' });
    res.redirect(`/admin/user/${req.params.userId}`);
  }
};

exports.toggleUserStatus = async (req, res) => {
  try {
    // Verifica se está tentando alterar status de si mesmo
    if (req.params.userId === req.user.id) {
      req.flash('error', { msg: 'Não é possível alterar seu próprio status' });
      return res.redirect(`/admin/user/${req.params.userId}`);
    }

    const user = await User.findById(req.params.userId);
    if (!user) {
      req.flash('error', { msg: 'Usuário não encontrado' });
      return res.redirect('/ranking');
    }

    // Inverte o status atual
    user.isActive = !user.isActive;
    await user.save();

    const msg = user.isActive ? 'Usuário habilitado com sucesso!' : 'Usuário desabilitado com sucesso!';
    req.flash('success', { msg });
    res.redirect(`/admin/user/${user._id}`);
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao alterar status do usuário' });
    res.redirect(`/admin/user/${req.params.userId}`);
  }
};

exports.getRaces = async (req, res) => {
  try {
    const corridas = await Race.find({})
      .populate('criador', 'profile.name')
      .sort('-createdAt');

    res.render('admin/races', {
      title: 'Gerenciar Corridas',
      corridas
    });
  } catch (err) {
    console.error('Erro ao buscar corridas:', err);
    req.flash('error', { msg: 'Erro ao carregar corridas' });
    res.redirect('/');
  }
};

exports.updateRace = async (req, res) => {
  try {
    const { titulo, descricao, premioTotal } = req.body;
    const corrida = await Race.findById(req.params.id)
      .populate('criador', 'profile.name')
      .populate('participantes.usuario', 'profile.name');

    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      return res.redirect('/races');
    }

    // Só permite editar se estiver em espera
    if (corrida.status !== 'espera') {
      req.flash('error', { msg: 'Só é possível editar corridas que ainda não começaram' });
      return res.redirect('/races');
    }

    corrida.titulo = titulo;
    corrida.descricao = descricao;
    corrida.premioTotal = premioTotal;

    await corrida.save();

    // Emite evento de atualização para todos os usuários
    if (io) {
      io.emit('race-update', {
        type: 'race-updated',
        raceId: corrida._id.toString(),
        data: {
          corrida: {
            _id: corrida._id,
            titulo: corrida.titulo,
            descricao: corrida.descricao,
            premioTotal: corrida.premioTotal,
            status: corrida.status,
            participantes: corrida.participantes,
            criador: corrida.criador,
            pontuacaoMaxima: corrida.pontuacaoMaxima,
            pontuacaoAtual: corrida.pontuacaoAtual
          }
        }
      });
    }

    req.flash('success', { msg: 'Corrida atualizada com sucesso!' });
    res.redirect('/races');
  } catch (err) {
    console.error('Erro ao atualizar corrida:', err);
    req.flash('error', { msg: 'Erro ao atualizar corrida' });
    res.redirect('/races');
  }
};

exports.deleteRace = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('criador', 'profile.name')
      .populate('participantes.usuario', 'profile.name');

    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      return res.redirect('/races');
    }

    // Remove a corrida sem verificar status
    await Race.deleteOne({ _id: corrida._id });

    // Emite evento de exclusão para todos os usuários
    if (io) {
      io.emit('race-update', {
        type: 'race-deleted',
        raceId: corrida._id.toString(),
        data: {
          corridaId: corrida._id,
          message: `A corrida "${corrida.titulo}" foi excluída por um administrador.`
        }
      });
    }

    req.flash('success', { msg: 'Corrida excluída com sucesso!' });
    res.redirect('/races');
  } catch (err) {
    console.error('Erro ao excluir corrida:', err);
    req.flash('error', { msg: 'Erro ao excluir corrida' });
    res.redirect('/races');
  }
};

exports.createRace = async (req, res) => {
  try {
    const { titulo, descricao, premioTotal } = req.body;
    
    const corrida = new Race({
      titulo,
      descricao,
      premioTotal: parseFloat(premioTotal) || 0,
      criador: req.user._id,
      status: 'espera'
    });

    await corrida.save();
    await corrida.populate('criador', 'profile.name');

    // Emite evento de nova corrida criada
    if (io) {
      io.emit('race-update', {
        type: 'race-created',
        raceId: corrida._id.toString(),
        data: {
          corrida: {
            _id: corrida._id,
            titulo: corrida.titulo,
            descricao: corrida.descricao,
            premioTotal: corrida.premioTotal,
            status: corrida.status,
            participantes: [],
            criador: corrida.criador,
            pontuacaoMaxima: corrida.pontuacaoMaxima,
            pontuacaoAtual: 0
          }
        }
      });
    }

    req.flash('success', { msg: 'Nova corrida criada com sucesso!' });
    res.redirect('/races');
  } catch (err) {
    console.error('Erro ao criar corrida:', err);
    req.flash('error', { msg: 'Erro ao criar corrida' });
    res.redirect('/races');
  }
}; 