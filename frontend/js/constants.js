export const STORAGE_KEY = "chat-ia-kali-sessions";
export const MODEL_STORAGE_KEY = "chat-ia-kali-model";
export const API_TOKEN_KEY = "chat-ia-kali-api-token";
export const SOUND_STORAGE_KEY = "chat-ia-kali-sound";
export const ONBOARDING_STORAGE_KEY = "chat-ia-kali-onboarded";
export const HISTORY_LIMIT = 10;

export const QUICK_PROMPTS = [
  { label: "Scan Nmap", text: "Faça um scan de portas e serviços em scanme.nmap.org" },
  { label: "Subdomínios", text: "Liste subdomínios de example.com com subfinder" },
  { label: "Whois", text: "Consulte whois e DNS de google.com" },
  { label: "Wi-Fi local", text: "Liste redes Wi-Fi visíveis ao redor" },
];

export const QUICK_OBJECTIVES = [
  "Encontre subdomínios expostos e verifique se há takeover",
  "Mapeie portas abertas e identifique serviços desatualizados",
  "Faça reconhecimento web: tecnologias, diretórios e vulnerabilidades",
];

export const HELP_HTML = `
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
    <li><kbd>Alt</kbd>+<kbd>F</kbd> — artefatos (/tools/output)</li>
    <li><kbd>Alt</kbd>+<kbd>I</kbd> — intel (recon + ameaças)</li>
    <li><kbd>Alt</kbd>+<kbd>C</kbd> — mapa mundial de ameaças</li>
    <li><kbd>Alt</kbd>+<kbd>R</kbd> — relatório</li>
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
    <li><strong>Chat</strong> — a IA executa ferramentas Kali via linguagem natural</li>
    <li><strong>tools</strong> — fixe ferramenta ou deixe em auto</li>
    <li><strong>pilot</strong> — missão autônoma com alvo + objetivo</li>
    <li><strong>intel</strong> — alvos, achados e relatórios · <strong>mapa</strong> é modal separado (<em>Alt+C</em>)</li>
    <li><strong>files</strong> — baixar artefatos salvos em <code>/tools/output</code></li>
    <li><strong>report</strong> — relatório Markdown da sessão</li>
    <li><strong>cancel</strong> — interrompe execução em andamento</li>
  </ul>
</section>
<p class="help-note">Use apenas em alvos autorizados.</p>
`;
