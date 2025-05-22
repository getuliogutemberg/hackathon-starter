const User = require('../models/User');

exports.getBankReport = async (req, res) => {
  try {
    // Verifica se é admin
    if (!req.user?.isAdmin) {
      req.flash('error', { msg: 'Acesso restrito a administradores' });
      return res.redirect('/');
    }

    // Busca todos os usuários
    const users = await User.find({})
      .populate('carteira.historico.corrida', 'titulo');

    // Calcula total de saldos (o que o banco deve)
    const totalSaldos = users.reduce((acc, user) => 
      acc + (user.carteira.premios || 0), 0
    );

    // Calcula total de depósitos (o que entrou no banco) considerando saques como subtração
    const totalDepositos = users.reduce((acc, user) => {
      const transacoesDinheiro = user.carteira.historico
        .filter(t => (t.tipo === 'deposito' || t.tipo === 'saque') && t.isPremio)
        .reduce((sum, t) => {
          // Se for saque, subtrai o valor
          if (t.tipo === 'saque') {
            return sum - Math.abs(t.quantidade || 0);
          }
          // Se for depósito, soma o valor
          return sum + (t.quantidade || 0);
        }, 0);
      return acc + transacoesDinheiro;
    }, 0);

    // Calcula lucro atual
    const lucroAtual = totalDepositos - totalSaldos;

    // Busca histórico de todas as transações em dinheiro (apenas depósitos, saques e prêmios)
    const todasTransacoes = users.reduce((acc, user) => {
      const transacoes = user.carteira.historico
        .filter(t => 
          t.isPremio && t.data && // Deve ser transação em dinheiro com data válida
          (t.tipo === 'deposito' || t.tipo === 'saque' || t.tipo === 'premio') // Apenas tipos relevantes
        )
        .map(t => ({
          ...t.toObject(),
          usuario: {
            id: user._id,
            nome: user.profile.name || user.email
          },
          data: new Date(t.data), // Converte para data válida
          quantidade: Number(t.quantidade) || 0 // Garante que quantidade é número
        }));
      return [...acc, ...transacoes];
    }, []);

    // Ordena transações por data (mais recentes primeiro)
    todasTransacoes.sort((a, b) => b.data - a.data);

    res.render('bank/report', {
      title: 'Relatório Bancário',
      totalSaldos,
      totalDepositos,
      lucroAtual,
      transacoes: todasTransacoes
    });

  } catch (err) {
    console.error('Erro ao gerar relatório bancário:', err);
    req.flash('error', { msg: 'Erro ao gerar relatório bancário' });
    res.redirect('/');
  }
}; 