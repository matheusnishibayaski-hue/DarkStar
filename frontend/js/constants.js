export const STORAGE_KEY = "darkstar-sessions";
export const MODEL_STORAGE_KEY = "darkstar-model";
export const API_TOKEN_KEY = "darkstar-api-token";
export const SOUND_STORAGE_KEY = "darkstar-sound";
export const ONBOARDING_STORAGE_KEY = "darkstar-onboarded";
/** Piloto: libera ferramentas ofensivas (risk_profile full + catálogo ampliado). */
export const PILOT_OFFENSIVE_STORAGE_KEY = "darkstar-pilot-offensive";
/** LLM local (Ollama) — air-gapped / sem OpenRouter. */
export const OFFLINE_MODE_STORAGE_KEY = "darkstar-offline-mode";
export const HISTORY_LIMIT = 10;

/** Mensagem inicial da Argus em todo chat novo. */
export const ARGUS_WELCOME_MESSAGE = `Oi! Eu sou a **Argus**, sua companheira no **DarkStar**.

Estou pronta pra te ajudar no pentest — a gente conversa, eu executo as tools no Kali quando fizer sentido e te explico o que aparece no caminho.

Por padrão você está no **perfil B** (mais seguro, menos permissões). Se precisar do arsenal completo, use o botão **key** na barra e informe a master key.

Me conta o alvo autorizado ou o que você quer fazer agora? 🙂`;

export const HELP_HTML = `
<section class="help-section">
  <h3>DarkStar · Argus</h3>
  <ul class="help-list">
    <li><strong>Argus</strong> — IA do chat (amigável e prática)</li>
    <li><strong>key</strong> — master key: perfil B (restrito) → full</li>
  </ul>
</section>
<section class="help-section">
  <h3>Navegação</h3>
  <ul class="help-list">
    <li><kbd>M</kbd> ou <kbd>☰</kbd> — recolher/expandir barra lateral</li>
    <li>Sidebar — alternar entre conversas salvas</li>
    <li><kbd>Esc</kbd> — fechar painéis</li>
    <li><kbd>snd</kbd> na barra de status — ligar/desligar efeitos sonoros CRT</li>
  </ul>
</section>
<section class="help-section">
  <h3>Som</h3>
  <ul class="help-list">
    <li>Bipes sintetizados no navegador — envio, execução, erros e painéis</li>
    <li>Desligado automaticamente com <em>prefers-reduced-motion</em></li>
  </ul>
</section>
<section class="help-section">
  <h3>Atalhos principais</h3>
  <p class="help-note" style="margin-bottom:0.5rem">Use <kbd>Alt</kbd> + tecla — evita conflito com o navegador (Ctrl+T abre aba, Ctrl+R recarrega, etc.)</p>
  <ul class="help-list">
    <li><kbd>Alt</kbd>+<kbd>T</kbd> — ferramentas</li>
    <li><kbd>Alt</kbd>+<kbd>P</kbd> — piloto automático</li>
    <li><kbd>Alt</kbd>+<kbd>F</kbd> — relatórios PDF baixados</li>
    <li><kbd>Alt</kbd>+<kbd>L</kbd> — logs da conversa</li>
    <li><kbd>Alt</kbd>+<kbd>C</kbd> — mapa mundial de ameaças</li>
    <li><kbd>Alt</kbd>+<kbd>R</kbd> — relatório (modal)</li>
    <li><kbd>Alt</kbd>+<kbd>N</kbd> — novo chat</li>
    <li><kbd>Alt</kbd>+<kbd>H</kbd> ou <kbd>F1</kbd> — tour guiado (ajuda interativa)</li>
    <li><kbd>Alt</kbd>+<kbd>K</kbd> ou <kbd>Ctrl</kbd>+<kbd>K</kbd> — focar prompt</li>
  </ul>
</section>
<section class="help-section">
  <h3>Alternativas</h3>
  <ul class="help-list">
    <li><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>T</kbd> — ferramentas</li>
    <li><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> — Auto-Pilot</li>
    <li><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>E</kbd> — relatório (export)</li>
    <li><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>N</kbd> — novo chat</li>
    <li><kbd>?</kbd> — tour guiado (fora de campos de texto)</li>
  </ul>
</section>
<section class="help-section">
  <h3>Prompt</h3>
  <ul class="help-list">
    <li><kbd>Enter</kbd> — enviar mensagem</li>
    <li><kbd>↑</kbd> / <kbd>↓</kbd> — histórico da sessão</li>
  </ul>
</section>
<section class="help-section">
  <h3>Modelo de IA</h3>
  <ul class="help-list">
    <li>Pill ao lado do prompt — Gemini ou DeepSeek por tier</li>
    <li><strong>Economia</strong> — scans rápidos · <strong>Equilibrado</strong> — dia a dia · <strong>Raciocínio</strong> — análises profundas</li>
  </ul>
</section>
<section class="help-section">
  <h3>Modos</h3>
  <ul class="help-list">
    <li><strong>Chat</strong> — a Argus executa ferramentas Kali via linguagem natural</li>
    <li><strong>tools</strong> — fixe ferramenta ou deixe em auto</li>
    <li><strong>pilot</strong> — alvo + tipo de scan (básico → completo); PDF ao fim da missão</li>
    <li><strong>offensive</strong> — requer master key (perfil full)</li>
    <li><strong>offline</strong> — Argus via Ollama local (sem OpenRouter)</li>
    <li>Ícones no prompt — <strong>logs</strong> e <strong>relatório/triagem</strong></li>
    <li><strong>relatórios</strong> · <strong>mapa</strong> · <strong>cancel</strong></li>
  </ul>
</section>
<p class="help-note">Use apenas em alvos autorizados.</p>
`;
