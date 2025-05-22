const mongoose = require('mongoose');

const raceSchema = new mongoose.Schema({
  titulo: String,
  descricao: String,
  status: {
    type: String,
    enum: ['espera', 'contagem', 'start', 'pausada', 'finalizada'],
    default: 'espera'
  },
  criador: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  participantes: [{
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    pontuacao: { type: Number, default: 0 },
    pontosDisponiveis: { type: Number, default: 0 },
    ultimaInteracao: {
      timestamp: Date,
      pontos: Number
    }
  }],
  premioTotal: { type: Number, default: 0 },
  pontuacaoMaxima: { type: Number, default: 0 },
  pontuacaoAtual: { type: Number, default: 0 },
  podium: [{
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    posicao: Number,
    pontuacao: Number
  }],
  mensagens: [{
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    texto: String,
    criadoEm: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  premiosDistribuidos: { type: Boolean, default: false }
});

// Adicionar método de interação
raceSchema.methods.interagir = async function(userId, pontos) {
  // Encontra o participante
  const participante = this.participantes.find(p => 
    p.usuario._id.toString() === userId.toString()
  );

  if (!participante) {
    throw new Error('Usuário não é participante desta corrida');
  }

  if (pontos > participante.pontosDisponiveis) {
    throw new Error('Pontos insuficientes');
  }

  if (this.status !== 'start') {
    throw new Error('Corrida não está em andamento');
  }

  // Atualiza pontuação do participante
  participante.pontuacao += pontos;
  participante.pontosDisponiveis -= pontos;
  participante.ultimaInteracao = {
    timestamp: new Date(),
    pontos: pontos
  };

  // Atualiza pontuação total da corrida
  this.pontuacaoAtual += pontos;

  // Verifica se atingiu a pontuação máxima
  if (this.pontuacaoAtual >= this.pontuacaoMaxima) {
    this.status = 'finalizada';
    
    // Define o pódium
    const participantesOrdenados = this.participantes
      .sort((a, b) => b.ultimaInteracao.timestamp - a.ultimaInteracao.timestamp)
      .slice(0, 3);

    this.podium = participantesOrdenados.map((p, index) => ({
      usuario: p.usuario,
      posicao: index + 1,
      pontuacao: p.pontuacao
    }));

    // Distribui os prêmios automaticamente ao finalizar
    if (this.premioTotal > 0) {
      await this.distribuirPremios();
    }
  }

  await this.save();
  return this;
};

// Adicionar método de distribuição de prêmios
raceSchema.methods.distribuirPremios = async function() {
  if (this.status !== 'finalizada' || !this.podium || this.podium.length === 0) {
    throw new Error('Corrida não está finalizada ou não tem pódium definido');
  }

  const User = mongoose.model('User');

  // Calcula os prêmios baseado nas porcentagens
  const premios = {
    1: this.premioTotal * 0.7, // 70% para o primeiro lugar
    2: this.premioTotal * 0.2, // 20% para o segundo lugar
    3: this.premioTotal * 0.1  // 10% para o terceiro lugar
  };

  // Distribui os prêmios para cada posição do pódium
  for (const position of this.podium) {
    const user = await User.findById(position.usuario);
    if (user) {
      // Adiciona o prêmio ao saldo do usuário
      user.carteira.premios += premios[position.posicao];
      
      // Registra a transação no histórico
      user.carteira.historico.push({
        tipo: 'premio',
        quantidade: premios[position.posicao],
        data: new Date(),
        isPremio: true,
        corrida: this._id,
        posicao: position.posicao,
        adminNote: `Prêmio por ${position.posicao}º lugar na corrida "${this.titulo}"`
      });

      await user.save();
    }
  }

  // Marca que os prêmios foram distribuídos
  this.premiosDistribuidos = true;
  await this.save();

  return this;
};

module.exports = mongoose.model('Race', raceSchema); 