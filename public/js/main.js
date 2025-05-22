/* eslint-env jquery, browser */
$(document).ready(() => {
  // Gerenciamento do tema
  const themeSwitch = document.getElementById('themeSwitch');
  if (themeSwitch) {
    // Carrega tema inicial dos cookies ou usa 'dark' como padrão
    const currentTheme = document.cookie
      .split('; ')
      .find(row => row.startsWith('theme='))
      ?.split('=')[1] || 'dark';

    // Aplica o tema inicial
    applyTheme(currentTheme);

    // Adiciona evento de clique
    themeSwitch.addEventListener('click', async () => {
      try {
        const response = await fetch('/theme/toggle', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        });
        
        if (!response.ok) {
          throw new Error('Erro ao trocar tema');
        }

        const { theme } = await response.json();
        
        // Aplica o novo tema
        applyTheme(theme);
        
      } catch (err) {
        console.error('Erro ao trocar tema:', err);
      }
    });
  }

  const socket = io();

  socket.on('race-update', function(event) {
    console.log('Evento recebido:', event);
    
    const corridaCard = document.querySelector(`.corrida-card[data-corrida-id="${event.data.raceId}"]`);
    if (!corridaCard) return;

    switch(event.type) {
      case 'participant-joined':
        // Atualiza o card da corrida com os novos dados
        corridaCard.outerHTML = createRaceCard(event.data.corrida);
        
        // Mostra notificação
        toastr.info(`${event.data.novoParticipante.name} entrou na corrida!`);
        break;

      case 'participant-left':
        // Atualiza o card da corrida com os dados atualizados
        corridaCard.outerHTML = createRaceCard(event.data.corrida);
        
        // Mostra notificação
        toastr.warning(`${event.data.participanteSaiu.name} saiu da corrida!`);
        break;

      case 'race-interaction':
        // Atualiza o progresso e posições dos ciclistas
        updateRaceProgress(corridaCard, event.data);
        break;
    }
  });
});

// Função para aplicar o tema
function applyTheme(theme) {
  // Atualiza o DOM
  document.documentElement.setAttribute('data-theme', theme);
  document.body.setAttribute('data-theme', theme);
  
  // Atualiza o ícone - começa com sol já que o tema padrão é dark
  const themeIcon = document.getElementById('themeIcon');
  if (themeIcon) {
    if (theme === 'dark') {
      themeIcon.classList.remove('fa-moon');
      themeIcon.classList.add('fa-sun');
    } else {
      themeIcon.classList.remove('fa-sun');
      themeIcon.classList.add('fa-moon');
    }
  }

  // Força recálculo do CSS
  document.body.style.display = 'none';
  document.body.offsetHeight; // Força um reflow
  document.body.style.display = '';
}

// Função para atualizar o progresso da corrida
function updateRaceProgress(card, data) {
  // Atualiza barra de progresso
  const progressBar = card.querySelector('.progress-bar');
  if (progressBar) {
    const progress = (data.pontuacaoAtual / data.pontuacaoMaxima) * 100;
    progressBar.style.width = `${progress}%`;
    progressBar.textContent = `${data.pontuacaoAtual} / ${data.pontuacaoMaxima} pts`;
  }

  // Atualiza posições dos ciclistas
  const cyclistsContainer = card.querySelector('.cyclists-container');
  if (cyclistsContainer && data.participantes) {
    const participantesOrdenados = data.participantes
      .sort((a, b) => b.pontuacao - a.pontuacao);

    participantesOrdenados.forEach((participante, index) => {
      const cyclist = cyclistsContainer.querySelector(`[data-user-id="${participante.usuario._id}"]`);
      if (cyclist) {
        cyclist.className = `cyclist position-${index + 1}`;
        cyclist.title = `${participante.usuario.profile.name} - ${participante.pontuacao} pts`;
      }
    });
  }
}

// Função auxiliar para criar o HTML do card da corrida (mantenha a função existente)
function createRaceCard(corrida) {
  // Mantenha sua implementação atual do createRaceCard
  // Esta função já deve existir no seu código
}


