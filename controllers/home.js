const Race = require('../models/Race');
const User = require('../models/User');
let io; // Declaração global do io

// Função para inicializar o io
exports.initIO = (socketIO) => {
  io = socketIO;
};

/**
 * GET /
 * Home page.
 */
exports.index = async (req, res) => {
  try {
    const corridas = await Race.find({})
      .populate({
        path: 'participantes.usuario',
        select: '_id profile email gravatar',
        populate: {
          path: 'profile',
          select: 'name picture'
        }
      })
      .populate('criador', '_id profile.name')
      .populate({
        path: 'podium.usuario',
        select: '_id profile email gravatar',
        populate: {
          path: 'profile',
          select: 'name picture'
        }
      })
      .sort('-createdAt')
      .limit(10);

    // Log para debug dos participantes e pódium
    console.log('Dados detalhados:', corridas.map(c => ({
      id: c._id,
      podium: c.podium?.map(p => ({
        id: p.usuario?._id,
        name: p.usuario?.profile?.name,
        picture: p.usuario?.profile?.picture,
        gravatar: p.usuario?.gravatar?.()
      })),
      participantes: c.participantes.map(p => ({
        id: p.usuario?._id,
        name: p.usuario?.profile?.name,
        picture: p.usuario?.profile?.picture,
        gravatar: p.usuario?.gravatar?.()
      }))
    })));

    const theme = req.cookies?.theme || 'light';

    res.render('home', {
      title: 'Dashboard',
      corridas,
      isAdmin: req.user && req.user.isAdmin,
      theme
    });
  } catch (err) {
    console.error('Erro ao carregar corridas:', err);
    req.flash('error', { msg: 'Erro ao carregar corridas' });
    res.redirect('/');
  }
};

exports.criarCorrida = async (req, res) => {
  try {
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    const premioTotal = req.body.premioTotal ? parseFloat(req.body.premioTotal) : 0;

    // Verifica se o prêmio é válido
    if (premioTotal > 0 && premioTotal < 10) {
      return res.status(400).json({ error: 'O prêmio mínimo deve ser R$ 10,00' });
    }

    const corrida = new Race({
      titulo: req.body.titulo,
      descricao: req.body.descricao,
      premioTotal: premioTotal,
      pontuacaoMaxima: premioTotal >= 10 ? premioTotal * 15 : 0,
      criador: req.user._id
    });

    await corrida.save();

    // Busca a corrida populada para enviar via socket
    const corridaPopulada = await Race.findById(corrida._id)
      .populate('criador', '_id profile.name');

    // Emite evento para todos os usuários
    io.emit('race-event', {
      type: 'race-created',
      data: {
        corrida: corridaPopulada
      }
    });

    

  } catch (err) {
    console.error('Erro ao criar corrida:', err);
    return res.status(500).json({ error: 'Erro ao criar corrida' });
  }
};

/**
 * POST /corrida/:id/participar
 * Participar de uma corrida.
 */
exports.participarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', '_id profile email gravatar')
      .populate('criador', '_id profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      return res.redirect('/');
    }

    // Verifica se o usuário já está participando
    const jaParticipando = corrida.participantes.some(p => 
      p.usuario && p.usuario._id.equals(req.user._id)
    );

    if (jaParticipando) {
      req.flash('error', { msg: 'Você já está participando desta corrida' });
      return res.redirect('/');
    }

    // Adiciona o usuário aos participantes
    corrida.participantes.push({
      usuario: req.user._id,
      pontuacao: 0,
      pontosDisponiveis: req.user.carteira.pontos
    });

    await corrida.save();

    // Busca a corrida atualizada e populada para enviar via socket
    const corridaAtualizada = await Race.findById(corrida._id)
      .populate({
        path: 'participantes.usuario',
        select: '_id profile email gravatar',
        populate: {
          path: 'profile',
          select: 'name picture'
        }
      })
      .populate('criador', '_id profile.name');

    // Emite evento via Socket.IO para atualizar em tempo real
    io.emit('race-update', {
      type: 'participant-joined',
      data: {
        raceId: corrida._id,
        corrida: corridaAtualizada,
        novoParticipante: {
          id: req.user._id,
          name: req.user.profile.name,
          picture: req.user.profile.picture || req.user.gravatar(),
          pontosDisponiveis: req.user.carteira.pontos
        }
      }
    });

    req.flash('success', { msg: 'Você entrou na corrida com sucesso!' });
    return res.redirect('/');
  } catch (err) {
    console.error('Erro ao participar da corrida:', err);
    req.flash('error', { msg: 'Erro ao participar da corrida' });
    return res.redirect('/');
  }
};

exports.interagirCorrida = async (req, res) => {
  try {
    console.log('Interagindo na corrida');
    console.log(req.body);
    
    const { pontos } = req.body;
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', '_id profile email gravatar')
      .populate('criador', '_id profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    await corrida.interagir(req.user.id, parseInt(pontos, 10));

    // Emitir atualização para todos os clientes
    io.emit('race-update', {
      type: 'race-interaction',
      data: {
        raceId: corrida._id,
        userId: req.user._id,
        userName: req.user.profile.name,
        pontos: pontos,
        pontuacaoAtual: corrida.pontuacaoAtual,
        status: corrida.status,
        participantes: corrida.participantes,
        tempoDecorrido: corrida.tempoDecorrido,
        podium: corrida.podium
      }
    });

    if (corrida.status === 'finalizada') {
      req.flash('success', { msg: 'Corrida finalizada! Confira o pódium!' });
    } else {
      req.flash('success', { msg: `Você enviou ${pontos} pontos para a corrida!` });
    }

    res.redirect('/');

  } catch (err) {
    console.error(err);
    req.flash('error', { msg: err.message });
    res.redirect('/');
  }
};

exports.getSalaCorreda = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('criador', '_id profile.name')
      .populate('participantes.usuario', '_id profile email gravatar')
      .populate('podium.usuario', '_id profile email gravatar')
      .populate({
        path: 'mensagens.usuario',
        select: '_id profile email gravatar'
      });

    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    res.render('sala-corrida', {
      title: corrida.titulo,
      corrida
    });
  } catch (err) {
    console.error('Erro ao carregar sala da corrida:', err);
    req.flash('error', { msg: 'Erro ao carregar sala da corrida' });
    res.redirect('/');
  }
};

exports.cancelarInscricao = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', 'profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se a corrida já começou
    if (corrida.status === 'start' || corrida.status === 'em_andamento' || corrida.status === 'finalizada') {
      req.flash('error', { msg: 'Não é possível cancelar inscrição de uma corrida em andamento ou finalizada' });
      
    }

    // Remove o participante
    corrida.participantes = corrida.participantes.filter(p => 
      !p.usuario.equals(req.user._id)
    );

    await corrida.save();

    // Emite evento via Socket.IO para atualizar em tempo real para TODOS os usuários
    io.emit('race-update', {
      type: 'participant-left',
      data: {
        raceId: corrida._id,
        userId: req.user._id,
        userName: req.user.profile.name,
        participantCount: corrida.participantes.length
      }
    });

    req.flash('success', { msg: 'Inscrição cancelada com sucesso' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao cancelar inscrição' });
    res.redirect('/');
  }
};

exports.cancelarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id);
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador da corrida
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode cancelar a corrida' });
      
    }

    // Verifica se a corrida já começou
    if (corrida.status === 'start' || corrida.status === 'em_andamento' || corrida.status === 'finalizada') {
      req.flash('error', { msg: 'Não é possível cancelar uma corrida em andamento ou finalizada' });
      
    }

    // Remove a corrida
    await Race.findByIdAndDelete(corrida._id);

    // Emite evento via Socket.IO para atualizar em tempo real para TODOS os usuários
    io.emit('race-update', {
      type: 'race-cancelled',
      data: {
        raceId: corrida._id
      }
    });

    req.flash('success', { msg: 'Corrida cancelada com sucesso' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao cancelar corrida' });
    res.redirect('/');
  }
};

exports.apagarTodasCorridas = async (req, res) => {
  try {
    // Verifica se o usuário é admin
    if (!req.user.isAdmin) {
      req.flash('error', { msg: 'Apenas administradores podem apagar todas as corridas' });
      
    }

    // Busca todas as corridas para emitir eventos de cancelamento
    const corridas = await Race.find({});
    
    // Apaga todas as corridas
    await Race.deleteMany({});

    // Emite eventos para cada corrida apagada
    corridas.forEach(corrida => {
      io.emit('race-update', {
        type: 'race-cancelled',
        data: {
          raceId: corrida._id
        }
      });
    });

    req.flash('success', { msg: `${corridas.length} corridas foram apagadas com sucesso` });
    res.redirect('/');
  } catch (err) {
    console.error('Erro ao apagar todas as corridas:', err);
    req.flash('error', { msg: 'Erro ao apagar todas as corridas' });
    res.redirect('/');
  }
};

exports.iniciarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', 'profile.name carteira.pontos')
      .populate('criador', 'profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador._id.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode iniciar a corrida' });
      
    }

    // Verifica se a corrida está em espera
    if (corrida.status !== 'espera') {
      req.flash('error', { msg: 'A corrida já foi iniciada' });
      
    }

    // Verifica número mínimo de participantes
    if (corrida.participantes.length < 2) {
      req.flash('error', { msg: 'Mínimo de 2 participantes necessários' });
      
    }

    // Calcula o total de pontos disponíveis dos participantes
    const totalPontosDisponiveis = corrida.participantes.reduce((acc, p) => 
      acc + (p.pontosDisponiveis || 0), 0
    );

    // Verifica se há pontos suficientes
    if (totalPontosDisponiveis < corrida.pontuacaoMaxima) {
      req.flash('error', { msg: 'Pontos insuficientes para iniciar a corrida' });
      
    }

    // Inicia a contagem regressiva
    corrida.status = 'contagem';
    corrida.startTime = new Date();
    await corrida.save();
    
    // Emite evento de início de contagem para todos os usuários
    io.emit('race-update', {
      type: 'race-countdown-start',
      data: {
        raceId: corrida._id,
        status: 'contagem',
        startTime: corrida.startTime,
        participantes: corrida.participantes.map(p => ({
          id: p.usuario._id.toString(),
          name: p.usuario.profile.name,
          pontos: p.pontosDisponiveis
        }))
      }
    });

    // Agenda a mudança para status 'start' após 10 segundos
    setTimeout(async () => {
      try {
        const corridaAtualizada = await Race.findById(corrida._id)
          .populate('participantes.usuario', 'profile.name')
          .populate('criador', 'profile.name');

        if (corridaAtualizada && corridaAtualizada.status === 'contagem') {
          corridaAtualizada.status = 'start';
          await corridaAtualizada.save();

          // Emite evento de início da corrida para todos os usuários
          io.emit('race-update', {
            type: 'race-started',
            data: {
              raceId: corridaAtualizada._id.toString(),
              status: 'start',
              startTime: corridaAtualizada.startTime,
              participantes: corridaAtualizada.participantes.map(p => ({
                id: p.usuario._id.toString(),
                name: p.usuario.profile.name,
                pontos: p.pontosDisponiveis
              })),
              criador: {
                id: corridaAtualizada.criador._id.toString(),
                name: corridaAtualizada.criador.profile.name
              }
            }
          });
        }
      } catch (err) {
        console.error('Erro ao iniciar corrida após contagem:', err);
      }
    }, 10000); // 10 segundos

    req.flash('success', { msg: 'Contagem regressiva iniciada!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao iniciar corrida' });
    res.redirect('/');
  }
};

exports.cancelarContagem = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id);
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode cancelar a contagem' });
      
    }

    // Verifica se a corrida está em contagem
    if (corrida.status !== 'contagem') {
      req.flash('error', { msg: 'A corrida precisa estar em contagem para ser cancelada' });
      
    }

    corrida.status = 'espera';
    corrida.startTime = null;
    await corrida.save();

    // Emite evento de contagem cancelada
    io.emit('race-update', {
      type: 'countdown-cancelled',
      data: {
        raceId: corrida._id.toString(),
        status: 'espera'
      }
    });

    req.flash('success', { msg: 'Contagem regressiva cancelada!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao cancelar contagem' });
    res.redirect('/');
  }
};

exports.startCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', 'profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode iniciar a corrida' });
      
    }

    // Verifica se a corrida está em contagem
    if (corrida.status !== 'contagem') {
      req.flash('error', { msg: 'A corrida precisa estar em contagem para ser iniciada' });
      
    }

    // Inicia a corrida
    corrida.status = 'start';
    corrida.startTime = new Date();
    await corrida.save();

    // Emite evento de início da corrida
    io.emit('race-update', {
      type: 'race-started',
      data: {
        raceId: corrida._id,
        status: 'start',
        startTime: corrida.startTime
      }
    });

    // Inicia o contador de tempo da corrida
    const raceInterval = setInterval(async () => {
      const corridaEmAndamento = await Race.findById(corrida._id);
      if (!corridaEmAndamento || corridaEmAndamento.status === 'finalizada') {
        clearInterval(raceInterval);
        return;
      }

      // Calcula o tempo decorrido como diferença entre agora e startTime
      const agora = new Date();
      const tempoDecorrido = Math.floor((agora - corridaEmAndamento.startTime) / 1000);
      
      io.emit('race-update', {
        type: 'race-in-progress',
        data: {
          raceId: corridaEmAndamento._id,
          tempoDecorrido: tempoDecorrido,
          status: corridaEmAndamento.status
        }
      });
    }, 1000);

    req.flash('success', { msg: 'Corrida iniciada!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao iniciar corrida' });
    res.redirect('/');
  }
};

exports.pausarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id);
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode pausar a corrida' });
      
    }

    // Verifica se a corrida está em andamento
    if (corrida.status !== 'start') {
      req.flash('error', { msg: 'A corrida precisa estar em andamento para ser pausada' });
      
    }

    corrida.status = 'pausada';
    await corrida.save();

    // Emite evento para todos os usuários
    io.emit('race-update', {
      type: 'race-paused',
      raceId: corrida._id.toString(),
      data: {
        status: 'pausada',
        corridaId: corrida._id
      }
    });

    req.flash('success', { msg: 'Corrida pausada com sucesso!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao pausar corrida' });
    res.redirect('/');
  }
};

exports.finalizarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', '_id profile email gravatar')
      .populate('criador', '_id profile.name')
      .populate('podium.usuario', '_id profile email gravatar');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode finalizar a corrida' });
      
    }

    // Verifica se a corrida está em andamento ou pausada
    if (corrida.status !== 'start' && corrida.status !== 'em_andamento') {
      req.flash('error', { msg: 'A corrida precisa estar em andamento ou pausada para ser finalizada' });
      
    }

    // Calcula o tempo final
    const tempoFinal = Math.floor((new Date() - corrida.startTime) / 1000);

    // Finaliza a corrida
    corrida.status = 'finalizada';
    corrida.tempoFinal = tempoFinal;

    // Cria o pódium
    corrida.podium = corrida.participantes
      .filter(p => p.ultimaInteracao) // Filtra apenas participantes que interagiram
      .sort((a, b) => b.ultimaInteracao.timestamp - a.ultimaInteracao.timestamp)
      .slice(0, 3)
      .map((p, index) => ({
        usuario: p.usuario,
        posicao: index + 1,
        pontuacaoTotal: p.pontuacao
      }));

    await corrida.save();

    // Distribui os prêmios para os vencedores
    await corrida.distribuirPremios();

    // Emite evento de finalização
    io.emit('race-update', {
      type: 'race-finished',
      data: {
        raceId: corrida._id,
        status: 'finalizada',
        tempoFinal: tempoFinal,
        podium: corrida.podium,
        pontuacaoFinal: corrida.pontuacaoAtual,
        premiosDistribuidos: true
      }
    });

    req.flash('success', { msg: 'Corrida finalizada! Prêmios distribuídos aos vencedores!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao finalizar corrida' });
    res.redirect('/');
  }
};

exports.retomarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id);
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode retomar a corrida' });
      
    }

    // Verifica se a corrida está pausada
    if (corrida.status !== 'pausada') {
      req.flash('error', { msg: 'A corrida precisa estar pausada para ser retomada' });
      
    }

    corrida.status = 'start';
    await corrida.save();

    // Emite evento de corrida retomada
    io.emit('race-update', {
      type: 'race-resumed',
      data: {
        raceId: corrida._id.toString(),
        status: 'start'
      }
    });

    req.flash('success', { msg: 'Corrida retomada com sucesso!' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao retomar corrida' });
    res.redirect('/');
  }
};

exports.reiniciarCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', 'profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      
    }

    // Verifica se o usuário é o criador
    if (!corrida.criador.equals(req.user._id)) {
      req.flash('error', { msg: 'Apenas o criador pode reiniciar a corrida' });
      
    }

    // Verifica se a corrida está pausada
    if (corrida.status !== 'em_andamento') {
      req.flash('error', { msg: 'A corrida precisa estar pausada para ser reiniciada' });
      
    }

    // Reinicia a corrida
    corrida.status = 'espera';
    corrida.tempoDecorrido = -60;
    corrida.pontuacaoAtual = 0;
    corrida.startTime = null;
    corrida.tempoFinal = null;
    corrida.podium = [];

    // Reseta os pontos dos participantes
    corrida.participantes.forEach(p => {
      p.pontuacao = 0;
      p.pontosDisponiveis = 100;
      p.ultimaInteracao = null;
    });

    await corrida.save();

    // Emite evento de reinício
    io.emit('race-update', {
      type: 'race-restarted',
      data: {
        raceId: corrida._id,
        status: 'espera',
        tempoDecorrido: -60,
        pontuacaoAtual: 0, 
        participantes: corrida.participantes
      }
    });

    req.flash('success', { msg: 'Corrida reiniciada! Todos os participantes receberam 100 pontos novamente.' });
    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', { msg: 'Erro ao reiniciar corrida' });
    res.redirect('/');
  }
};

exports.excluirCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id);
    
    if (!corrida) {
      req.flash('errors', { msg: 'Corrida não encontrada.' });
      
    }

    // Verifica se o usuário é o criador ou admin
    if (corrida.criador.toString() !== req.user.id && !req.user.isAdmin) {
      req.flash('errors', { msg: 'Você não tem permissão para excluir esta corrida.' });
      
    }

    await Race.findByIdAndDelete(req.params.id);

    // Emite evento de corrida excluída para todos os clientes
    io.emit('race-event', {
      type: 'race-deleted',
      data: {
        corridaId: req.params.id
      }
    });

    req.flash('success', { msg: 'Corrida excluída com sucesso!' });
    res.redirect('/');
  } catch (err) {
    console.error('Erro ao excluir corrida:', err);
    req.flash('errors', { msg: 'Erro ao excluir corrida.' });
    res.redirect('/');
  }
};

exports.sairCorrida = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id)
      .populate('participantes.usuario', '_id profile email gravatar')
      .populate('criador', '_id profile.name');
    
    if (!corrida) {
      req.flash('error', { msg: 'Corrida não encontrada' });
      return res.redirect('/');
    }

    // Verifica se a corrida já começou
    if (corrida.status !== 'espera') {
      req.flash('error', { msg: 'Não é possível sair de uma corrida que já começou' });
      return res.redirect('/');
    }

    // Remove o usuário dos participantes
    corrida.participantes = corrida.participantes.filter(p => 
      !p.usuario._id.equals(req.user._id)
    );

    await corrida.save();

    // Busca a corrida atualizada e populada
    const corridaAtualizada = await Race.findById(corrida._id)
      .populate({
        path: 'participantes.usuario',
        select: '_id profile email gravatar',
        populate: {
          path: 'profile',
          select: 'name picture'
        }
      })
      .populate('criador', '_id profile.name');

    // Emite evento via Socket.IO para atualizar em tempo real
    io.emit('race-update', {
      type: 'participant-left',
      data: {
        raceId: corrida._id,
        corrida: corridaAtualizada,
        participanteSaiu: {
          id: req.user._id,
          name: req.user.profile.name
        }
      }
    });

    req.flash('success', { msg: 'Você saiu da corrida com sucesso!' });
    return res.redirect('/');
  } catch (err) {
    console.error('Erro ao sair da corrida:', err);
    req.flash('error', { msg: 'Erro ao sair da corrida' });
    return res.redirect('/');
  }
};

// Adicionar rota para mensagens
exports.postMensagem = async (req, res) => {
  try {
    const corrida = await Race.findById(req.params.id);
    if (!corrida) {
      return res.status(404).json({ error: 'Corrida não encontrada' });
    }

    corrida.mensagens.push({
      usuario: req.user._id,
      texto: req.body.mensagem
    });

    await corrida.save();

    // Emite evento via Socket.IO
    if (io) {
      io.to(`race-${corrida._id}`).emit('race-message', {
        raceId: corrida._id,
        userId: req.user._id,
        userName: req.user.profile.name || req.user.email,
        userAvatar: req.user.profile.picture || req.user.gravatar(),
        message: req.body.mensagem
      });
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Erro ao enviar mensagem:', err);
    res.status(500).json({ error: 'Erro ao enviar mensagem' });
  }
};
