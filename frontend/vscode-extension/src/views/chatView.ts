import * as vscode from "vscode";
import type { Finding, ScanResult } from "../types";

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function findingContextHtml(finding: Finding | undefined): string {
  if (!finding) return "";

  const cweHtml = finding.cwe
    ? `<a class="cwe-badge" href="https://cwe.mitre.org/data/definitions/${finding.cwe.replace(/^CWE-/i, "")}.html" target="_blank">${escapeHtml(finding.cwe)}</a>`
    : "";

  return `
    <div class="finding-context" id="findingContext">
      <div class="finding-context-header">
        <span class="severity-badge severity-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity.toUpperCase())}</span>
        ${cweHtml}
        <span class="finding-context-title">${escapeHtml(finding.title)}</span>
      </div>
      <div class="finding-context-location">
        <code>${escapeHtml(finding.file)}:${finding.line}</code>
      </div>
      <div class="finding-context-rationale">${escapeHtml(finding.rationale)}</div>
    </div>`;
}

function scanContextHtml(scan: ScanResult | undefined): string {
  if (!scan) return "";
  const summary = scan.summary
    ? `<div class="finding-context-rationale">${escapeHtml(scan.summary)}</div>`
    : "";
  const high = scan.findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  return `
    <div class="finding-context" id="scanContext">
      <div class="finding-context-header">
        <span class="severity-badge severity-${high > 0 ? "high" : "low"}">${high} critical/high</span>
        <span class="finding-context-title">${escapeHtml(scan.pr_title || `PR #${scan.pr_number}`)}</span>
      </div>
      <div class="finding-context-location">
        <code>${escapeHtml(scan.repo)} · PR #${scan.pr_number} · ${scan.findings.length} findings</code>
      </div>
      ${summary}
    </div>`;
}

export function getChatWebviewContent(
  webview: vscode.Webview,
  _extensionUri: vscode.Uri,
  finding?: Finding,
  scan?: ScanResult
): string {
  const nonce = Math.random().toString(36).slice(2);
  // connect-src needs to include the backend URL — we allow any http(s) origin
  const csp = `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src data: https:; connect-src http: https:;`;

  const initialFindingJson = finding ? JSON.stringify(finding) : "null";
  const initialScanJson = scan ? JSON.stringify(scan) : "null";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aegis Security Chat</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --color-bg: var(--vscode-editor-background);
      --color-fg: var(--vscode-editor-foreground);
      --color-border: var(--vscode-panel-border, #3c3c3c);
      --color-input-bg: var(--vscode-input-background);
      --color-input-fg: var(--vscode-input-foreground);
      --color-input-border: var(--vscode-input-border);
      --color-button-bg: var(--vscode-button-background);
      --color-button-fg: var(--vscode-button-foreground);
      --color-button-hover: var(--vscode-button-hoverBackground);
      --color-user-bubble: var(--vscode-badge-background, #0078d4);
      --color-user-bubble-fg: var(--vscode-badge-foreground, #fff);
      --color-assistant-bubble: var(--vscode-editorWidget-background, #252526);
      --color-assistant-bubble-fg: var(--vscode-editor-foreground);
      --color-code-bg: var(--vscode-textCodeBlock-background, #1e1e1e);
      --color-diff-add: rgba(0, 180, 80, 0.18);
      --color-diff-add-fg: #4ec994;
      --color-diff-del: rgba(220, 50, 50, 0.18);
      --color-diff-del-fg: #f14c4c;
      --radius: 8px;
    }

    body {
      font-family: var(--vscode-font-family, system-ui, sans-serif);
      font-size: var(--vscode-font-size, 13px);
      background: var(--color-bg);
      color: var(--color-fg);
      height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    /* Finding context card */
    .finding-context {
      padding: 10px 14px;
      border-bottom: 1px solid var(--color-border);
      background: var(--vscode-sideBar-background, var(--color-bg));
      flex-shrink: 0;
    }
    .finding-context-header {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 4px;
    }
    .finding-context-title {
      font-weight: 600;
      flex: 1;
    }
    .finding-context-location code {
      font-size: 11px;
      opacity: 0.75;
    }
    .finding-context-rationale {
      font-size: 12px;
      opacity: 0.8;
      margin-top: 4px;
      max-height: 60px;
      overflow: hidden;
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
    }

    .severity-badge {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .severity-critical { background: #dc2626; color: #fff; }
    .severity-high     { background: #ea580c; color: #fff; }
    .severity-medium   { background: #ca8a04; color: #fff; }
    .severity-low      { background: #2563eb; color: #fff; }
    .severity-info     { background: #6b7280; color: #fff; }

    .cwe-badge {
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 4px;
      background: var(--vscode-badge-background, #4a4a4a);
      color: var(--vscode-badge-foreground, #fff);
      text-decoration: none;
    }
    .cwe-badge:hover { opacity: 0.8; }

    /* Messages area */
    #messages {
      flex: 1;
      overflow-y: auto;
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .msg {
      display: flex;
      flex-direction: column;
      max-width: 88%;
    }
    .msg.user { align-self: flex-end; }
    .msg.assistant { align-self: flex-start; }

    .msg-label {
      font-size: 11px;
      opacity: 0.55;
      margin-bottom: 3px;
    }
    .msg.user .msg-label { text-align: right; }

    .msg-bubble {
      padding: 9px 13px;
      border-radius: var(--radius);
      line-height: 1.5;
      word-break: break-word;
    }
    .msg.user .msg-bubble {
      background: var(--color-user-bubble);
      color: var(--color-user-bubble-fg);
      border-bottom-right-radius: 2px;
    }
    .msg.assistant .msg-bubble {
      background: var(--color-assistant-bubble);
      color: var(--color-assistant-bubble-fg);
      border-bottom-left-radius: 2px;
    }

    /* Code blocks */
    .msg-bubble pre {
      background: var(--color-code-bg);
      border-radius: 4px;
      padding: 8px 10px;
      overflow-x: auto;
      margin: 6px 0;
      font-size: 12px;
    }
    .msg-bubble code {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 12px;
    }
    .msg-bubble p { margin: 4px 0; }
    .msg-bubble ul, .msg-bubble ol { padding-left: 18px; }

    /* Diff viewer */
    .diff-viewer {
      margin-top: 8px;
      border: 1px solid var(--color-border);
      border-radius: var(--radius);
      overflow: hidden;
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 12px;
    }
    .diff-viewer-header {
      padding: 6px 10px;
      background: var(--vscode-titleBar-activeBackground, #3c3c3c);
      font-size: 11px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .diff-viewer-body {
      max-height: 280px;
      overflow-y: auto;
    }
    .diff-line {
      padding: 1px 10px;
      white-space: pre;
      display: block;
    }
    .diff-add { background: var(--color-diff-add); color: var(--color-diff-add-fg); }
    .diff-del { background: var(--color-diff-del); color: var(--color-diff-del-fg); }
    .diff-meta { opacity: 0.5; }
    .diff-actions { display: flex; gap: 6px; }
    .diff-actions button {
      font-size: 11px;
      padding: 2px 8px;
      border: 1px solid var(--color-border);
      border-radius: 4px;
      background: var(--color-button-bg);
      color: var(--color-button-fg);
      cursor: pointer;
    }
    .diff-actions button:hover { background: var(--color-button-hover); }

    /* Typing indicator */
    .typing-indicator {
      display: none;
      align-self: flex-start;
      padding: 9px 13px;
      background: var(--color-assistant-bubble);
      border-radius: var(--radius);
      border-bottom-left-radius: 2px;
    }
    .typing-indicator.visible { display: flex; gap: 4px; align-items: center; }
    .dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: var(--color-fg);
      opacity: 0.4;
      animation: bounce 1.2s ease-in-out infinite;
    }
    .dot:nth-child(2) { animation-delay: 0.2s; }
    .dot:nth-child(3) { animation-delay: 0.4s; }
    @keyframes bounce {
      0%, 80%, 100% { transform: translateY(0); opacity: 0.4; }
      40% { transform: translateY(-5px); opacity: 1; }
    }

    /* Input area */
    #inputArea {
      border-top: 1px solid var(--color-border);
      padding: 10px 14px;
      display: flex;
      gap: 8px;
      align-items: flex-end;
      flex-shrink: 0;
    }
    #msgInput {
      flex: 1;
      background: var(--color-input-bg);
      color: var(--color-input-fg);
      border: 1px solid var(--color-input-border, transparent);
      border-radius: var(--radius);
      padding: 8px 10px;
      font-family: inherit;
      font-size: inherit;
      resize: none;
      min-height: 38px;
      max-height: 140px;
      line-height: 1.5;
      outline: none;
    }
    #msgInput:focus { border-color: var(--vscode-focusBorder, #007acc); }

    #sendBtn {
      background: var(--color-button-bg);
      color: var(--color-button-fg);
      border: none;
      border-radius: var(--radius);
      padding: 8px 14px;
      cursor: pointer;
      font-size: 13px;
      flex-shrink: 0;
      align-self: flex-end;
      height: 38px;
    }
    #sendBtn:hover { background: var(--color-button-hover); }
    #sendBtn:disabled { opacity: 0.5; cursor: not-allowed; }

    #clearBtn {
      background: transparent;
      color: var(--color-fg);
      border: 1px solid var(--color-border);
      border-radius: var(--radius);
      padding: 8px 10px;
      cursor: pointer;
      font-size: 11px;
      flex-shrink: 0;
      align-self: flex-end;
      height: 38px;
      opacity: 0.7;
    }
    #clearBtn:hover { opacity: 1; }

    .hint {
      font-size: 11px;
      opacity: 0.45;
      text-align: center;
      padding: 4px 0;
      flex-shrink: 0;
    }

    #emptyState {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      opacity: 0.4;
      gap: 8px;
      font-size: 13px;
    }
    #emptyState svg { opacity: 0.5; }
  </style>
</head>
<body>
  ${scanContextHtml(scan)}
  ${findingContextHtml(finding)}

  <div id="messages">
    <div id="emptyState">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2L4 5.5V11c0 4.418 3.372 8.556 8 9.93C16.628 19.556 20 15.418 20 11V5.5L12 2z" opacity="0.6"/>
        <path d="M9 12l2 2 4-4" stroke="white" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>${finding ? "Ask Aegis about this finding" : scan ? "Ask Aegis about this pull request" : "Ask Aegis a security question"}</span>
    </div>
    <div class="typing-indicator" id="typingIndicator">
      <div class="dot"></div>
      <div class="dot"></div>
      <div class="dot"></div>
    </div>
  </div>

  <div id="inputArea">
    <textarea
      id="msgInput"
      placeholder="${finding ? "Ask about this finding… (Ctrl+Enter to send)" : scan ? "Ask about this pull request… (Ctrl+Enter to send)" : "Ask a security question… (Ctrl+Enter to send)"}"
      rows="1"
    ></textarea>
    <button id="clearBtn" title="Clear history">Clear</button>
    <button id="sendBtn">Send</button>
  </div>
  <p class="hint">Ctrl+Enter to send</p>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();

    let currentFinding = ${initialFindingJson};
    let currentScan = ${initialScanJson};
    let history = [];
    let waiting = false;

    const messagesEl = document.getElementById('messages');
    const typingEl   = document.getElementById('typingIndicator');
    const inputEl    = document.getElementById('msgInput');
    const sendBtn    = document.getElementById('sendBtn');
    const clearBtn   = document.getElementById('clearBtn');
    const emptyState = document.getElementById('emptyState');
    const findingCtx = document.getElementById('findingContext');

    function escHtml(s) {
      return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    }

    function renderInlineMarkdown(text) {
      let html = escHtml(text);
      html = html.replace(/\`([^\`]+)\`/g, '<code>$1</code>');
      html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
      return html.replace(/\\n/g, '<br>');
    }

    function renderMarkdown(text) {
      const parts = [];
      const re = /\`\`\`(\\w*)\\n([\\s\\S]*?)\`\`\`/g;
      let last = 0;
      let match;
      while ((match = re.exec(text)) !== null) {
        if (match.index > last) {
          parts.push(renderInlineMarkdown(text.slice(last, match.index)));
        }
        const lang = String(match[1] || '').toLowerCase();
        const code = String(match[2] || '').replace(/\\n$/, '');
        if (lang === 'diff' || lang === 'patch') {
          parts.push(renderDiffBlock(code));
        } else {
          parts.push('<pre><code>' + escHtml(code) + '</code></pre>');
        }
        last = re.lastIndex;
      }
      if (last < text.length) {
        parts.push(renderInlineMarkdown(text.slice(last)));
      }
      return parts.join('');
    }

    function renderDiffBlock(diffText) {
      const lines = diffText.split('\\n');
      const lineHtml = lines.map(line => {
        let cls = '';
        if (line.startsWith('+') && !line.startsWith('+++')) cls = 'diff-add';
        else if (line.startsWith('-') && !line.startsWith('---')) cls = 'diff-del';
        else if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) cls = 'diff-meta';
        return '<span class="diff-line ' + cls + '">' + escHtml(line) + '</span>';
      }).join('');

      const encodedPatch = encodeURIComponent(diffText);

      return \`<div class="diff-viewer">
        <div class="diff-viewer-header">
          <span>Proposed patch</span>
          <div class="diff-actions">
            <button class="apply-patch-btn" data-patch="\${encodedPatch}">Apply Patch</button>
            <button class="dismiss-patch-btn">Dismiss</button>
          </div>
        </div>
        <div class="diff-viewer-body">\${lineHtml}</div>
      </div>\`;
    }

    function applyPatch(patch) {
      vscode.postMessage({ type: 'applyPatch', patch: patch });
    }

    document.addEventListener('click', (e) => {
      const applyBtn = e.target.closest('.apply-patch-btn');
      if (applyBtn) {
        applyPatch(decodeURIComponent(applyBtn.dataset.patch || ''));
        return;
      }
      const dismissBtn = e.target.closest('.dismiss-patch-btn');
      if (dismissBtn) {
        const viewer = dismissBtn.closest('.diff-viewer');
        if (viewer) viewer.remove();
      }
    });

    function addMessage(role, content, proposedPatch) {
      if (emptyState) emptyState.style.display = 'none';
      const div = document.createElement('div');
      div.className = 'msg ' + role;
      const labelText = role === 'user' ? 'You' : 'Aegis';
      let bubbleContent = renderMarkdown(content);
      if (proposedPatch) {
        bubbleContent += renderDiffBlock(proposedPatch);
      }
      div.innerHTML = \`
        <div class="msg-label">\${labelText}</div>
        <div class="msg-bubble">\${bubbleContent}</div>
      \`;
      messagesEl.insertBefore(div, typingEl);
      scrollToBottom();
    }

    function scrollToBottom() {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function setWaiting(val) {
      waiting = val;
      sendBtn.disabled = val;
      inputEl.disabled = val;
      typingEl.classList.toggle('visible', val);
      if (val) scrollToBottom();
    }

    function sendMessage() {
      const text = inputEl.value.trim();
      if (!text || waiting) return;
      inputEl.value = '';
      inputEl.style.height = 'auto';

      addMessage('user', text);
      history.push({ role: 'user', content: text });
      setWaiting(true);

      vscode.postMessage({
        type: 'sendMessage',
        text: text,
        finding: currentFinding,
        scan: currentScan,
        history: history.slice(0, -1)
      });
    }

    sendBtn.addEventListener('click', sendMessage);
    clearBtn.addEventListener('click', () => {
      history = [];
      const msgs = messagesEl.querySelectorAll('.msg');
      msgs.forEach(m => m.remove());
      if (emptyState) emptyState.style.display = '';
      vscode.postMessage({ type: 'clearHistory' });
    });

    inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        sendMessage();
      }
    });

    // Auto-resize textarea
    inputEl.addEventListener('input', () => {
      inputEl.style.height = 'auto';
      inputEl.style.height = Math.min(inputEl.scrollHeight, 140) + 'px';
    });

    // Streaming state
    let streamingBubble = null;
    let streamingContent = '';

    function startStreamingMessage() {
      if (emptyState) emptyState.style.display = 'none';
      typingEl.classList.remove('visible');
      const div = document.createElement('div');
      div.className = 'msg assistant';
      div.id = '__streaming_msg__';
      div.innerHTML = '<div class="msg-label">Aegis</div><div class="msg-bubble" id="__streaming_bubble__"></div>';
      messagesEl.insertBefore(div, typingEl);
      streamingBubble = document.getElementById('__streaming_bubble__');
      streamingContent = '';
      scrollToBottom();
    }

    function appendStreamToken(token) {
      streamingContent += token;
      if (streamingBubble) {
        streamingBubble.innerHTML = renderMarkdown(streamingContent);
        scrollToBottom();
      }
    }

    function finalizeStreamingMessage(proposedPatch) {
      const msgDiv = document.getElementById('__streaming_msg__');
      if (msgDiv) {
        msgDiv.removeAttribute('id');
        const bubble = msgDiv.querySelector('.msg-bubble');
        if (bubble) {
          bubble.removeAttribute('id');
          if (proposedPatch) {
            bubble.innerHTML += renderDiffBlock(proposedPatch);
          }
        }
      }
      if (streamingContent) {
        history.push({ role: 'assistant', content: streamingContent });
      }
      streamingBubble = null;
      streamingContent = '';
    }

    // Messages from extension host
    window.addEventListener('message', (event) => {
      const msg = event.data;
      switch (msg.type) {
        case 'streamStart':
          setWaiting(true);
          startStreamingMessage();
          break;

        case 'streamChunk':
          appendStreamToken(msg.token);
          break;

        case 'streamEnd':
          setWaiting(false);
          finalizeStreamingMessage(msg.proposed_patch || null);
          break;

        case 'addMessage':
          setWaiting(false);
          addMessage(msg.message.role, msg.message.content, msg.message.proposed_patch);
          history.push({ role: msg.message.role, content: msg.message.content });
          break;

        case 'clearHistory':
          history = [];
          const msgs = messagesEl.querySelectorAll('.msg');
          msgs.forEach(m => m.remove());
          if (emptyState) emptyState.style.display = '';
          break;

        case 'setFinding':
          currentFinding = msg.finding;
          if (findingCtx && msg.finding) {
            findingCtx.style.display = '';
            const titleEl = findingCtx.querySelector('.finding-context-title');
            if (titleEl) titleEl.textContent = msg.finding.title;
          }
          break;

        case 'setScan':
          currentScan = msg.scan;
          break;

        case 'sendInitial':
          if (msg.text && !waiting) {
            inputEl.value = String(msg.text);
            sendMessage();
          }
          break;

        case 'error':
          setWaiting(false);
          if (streamingBubble) {
            streamingBubble.innerHTML = '<span style="color:#f14c4c">Error: ' + escHtml(msg.message) + '</span>';
            finalizeStreamingMessage(null);
          } else {
            addMessage('assistant', 'Error: ' + escHtml(msg.message));
          }
          break;
      }
    });
  </script>
</body>
</html>`;
}
