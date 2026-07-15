export const STORAGE_KEY = "chat-ia-kali-sessions";
export const MODEL_STORAGE_KEY = "chat-ia-kali-model";
export const API_TOKEN_KEY = "chat-ia-kali-api-token";
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
    <li><kbd>M</kbd> ou <kbd>☰</kbd> — abrir/fechar menu lateral</li>
    <li>Sidebar — alternar entre conversas salvas</li>
    <li><kbd>Esc</kbd> — fechar painéis</li>
  </ul>
</section>
<section class="help-section">
  <h3>Ações</h3>
  <ul class="help-list">
    <li><kbd>Ctrl+N</kbd> — novo chat</li>
    <li><kbd>Ctrl+T</kbd> — selecionar ferramenta</li>
    <li><kbd>Ctrl+P</kbd> — modo Auto-Pilot</li>
    <li><kbd>Ctrl+R</kbd> — gerar relatório</li>
    <li><kbd>Ctrl+/</kbd> — esta ajuda</li>
    <li><kbd>Ctrl+K</kbd> — focar no prompt</li>
  </ul>
</section>
<section class="help-section">
  <h3>Prompt</h3>
  <ul class="help-list">
    <li><kbd>Enter</kbd> — enviar mensagem</li>
    <li><kbd>↑</kbd> / <kbd>↓</kbd> — histórico de comandos da sessão</li>
  </ul>
</section>
<section class="help-section">
  <h3>Modelo de IA</h3>
  <ul class="help-list">
    <li>Seletor no prompt (pill) — escolha Gemini ou DeepSeek</li>
    <li><strong>Economia</strong> — menos tokens, respostas rápidas</li>
    <li><strong>Equilibrado</strong> — uso geral do dia a dia</li>
    <li><strong>Raciocínio</strong> — análises complexas (mais tokens)</li>
  </ul>
</section>
<section class="help-section">
  <h3>Modos de uso</h3>
  <ul class="help-list">
    <li><strong>Chat</strong> — descreva o que precisa; a IA executa ferramentas Kali</li>
    <li><strong>tool:X</strong> — force uma ferramenta específica (ex: nmap, nuclei)</li>
    <li><strong>pilot</strong> — informe alvo + objetivo; o agente roda sozinho</li>
    <li><strong>report</strong> — baixa relatório Markdown da sessão atual</li>
  </ul>
</section>
<p class="help-note">Use apenas em alvos autorizados.</p>
`;
