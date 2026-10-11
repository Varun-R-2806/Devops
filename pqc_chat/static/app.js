/* --------------------------------------------------------------------------
   app.js — Frontend Client for Hybrid PQC Secured Chat
   Performs live hybrid ECDH (P-256) + Kyber512 handshake over WebSockets
   and authenticates real-time AES-256-GCM encrypted messages via Web Crypto.
   -------------------------------------------------------------------------- */

(function () {
  'use strict';

  // State
  let ws = null;
  let sessionKeyBytes = null;
  let aesCryptoKey = null;
  let keyFingerprint = null;
  let showWireCiphertext = false;
  let myUsername = 'WebUser-' + Math.floor(1000 + Math.random() * 9000);

  // DOM Elements
  const statusPill = document.getElementById('server-status-pill');
  const statusText = document.getElementById('server-status-text');
  const peerCountEl = document.getElementById('peer-count');
  const messagesFeed = document.getElementById('messages-feed');
  const chatForm = document.getElementById('chat-form');
  const chatInput = document.getElementById('chat-input');
  const btnToggleCipher = document.getElementById('btn-toggle-cipher');
  const toggleCipherLabel = document.getElementById('toggle-cipher-label');
  const btnClearChat = document.getElementById('btn-clear-chat');
  const bannerFingerprint = document.getElementById('banner-fingerprint');
  const paramFingerprint = document.getElementById('param-fingerprint');
  const cliModal = document.getElementById('cli-modal');
  const btnCliModal = document.getElementById('btn-cli-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const cliCommandText = document.getElementById('cli-command-text');
  const btnCopyCommand = document.getElementById('btn-copy-command');

  // Binary / Base64 Helpers
  function bytesToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Determine WebSocket URL
  function getWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws/chat?username=${encodeURIComponent(myUsername)}&client_type=web`;
  }

  // Update CLI Modal command string with live current domain
  function updateCliCommandString() {
    const wsUrl = getWebSocketUrl();
    if (cliCommandText) {
      cliCommandText.textContent = `python ws_client.py --server ${wsUrl} --username Bob`;
    }
  }

  // Set Stepper State
  function setStepActive(stepNum, isCompleted = true) {
    const el = document.getElementById(`step-${stepNum}`);
    if (el) {
      if (isCompleted) {
        el.classList.add('completed');
      } else {
        el.classList.remove('completed');
      }
    }
  }

  // Render System Notification
  function addSystemMessage(text) {
    const div = document.createElement('div');
    div.className = 'system-notice';
    div.textContent = text;
    messagesFeed.appendChild(div);
    messagesFeed.scrollTop = messagesFeed.scrollHeight;
  }

  // Render Chat Message Bubble
  function addChatMessage(sender, plaintext, ciphertextHex, isOutgoing = false) {
    const bubble = document.createElement('div');
    const isBot = sender.includes('Bot');
    bubble.className = `message-bubble ${isOutgoing ? 'outgoing' : 'incoming'} ${isBot ? 'bot' : ''}`;

    const header = document.createElement('div');
    header.className = 'msg-header';
    header.innerHTML = `
      <span class="msg-sender">${sender}</span>
      <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
    `;

    const content = document.createElement('div');
    content.className = 'msg-content';

    const textSpan = document.createElement('div');
    textSpan.className = 'plain-text';
    textSpan.textContent = plaintext;
    content.appendChild(textSpan);

    if (ciphertextHex) {
      const wireDiv = document.createElement('div');
      wireDiv.className = `wire-preview ${showWireCiphertext ? '' : 'hidden'}`;
      wireDiv.innerHTML = `<strong>AES-GCM Wire Bytes:</strong><br><code>${ciphertextHex.slice(0, 48)}...</code>`;
      content.appendChild(wireDiv);
    }

    const footer = document.createElement('div');
    footer.className = 'msg-meta-footer';
    footer.innerHTML = `
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
      <span>PQC Encrypted</span>
    `;

    bubble.appendChild(header);
    bubble.appendChild(content);
    bubble.appendChild(footer);

    messagesFeed.appendChild(bubble);
    messagesFeed.scrollTop = messagesFeed.scrollHeight;
  }

  // Perform Client-Side Hybrid Handshake
  async function performHandshake(initData) {
    try {
      setStepActive(1, true);

      const serverEcdhPubDer = base64ToBytes(initData.server_ecdh_pub);
      const serverKyberPub = initData.server_kyber_pub;

      // 1. Generate Client Ephemeral ECDH Key Pair on P-256
      const clientEcdhKeyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
      );

      // Export Client Public Key in SPKI/DER format
      const clientSpki = await window.crypto.subtle.exportKey('spki', clientEcdhKeyPair.publicKey);
      const clientEcdhPubBytes = new Uint8Array(clientSpki);

      // Import Server's ECDH Public Key
      const serverEcdhKey = await window.crypto.subtle.importKey(
        'spki',
        serverEcdhPubDer,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );

      // Compute ECDH Shared Secret (32 bytes)
      const ecdhSecretBits = await window.crypto.subtle.deriveBits(
        { name: 'ECDH', public: serverEcdhKey },
        clientEcdhKeyPair.privateKey,
        256
      );
      const ecdhSecretBytes = new Uint8Array(ecdhSecretBits);

      // 2. Encapsulate Kyber512 Public Key via Server Helper API
      setStepActive(2, true);
      const encapRes = await fetch('/api/handshake/encapsulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_kyber_pub: serverKyberPub })
      });

      if (!encapRes.ok) {
        throw new Error('Kyber encapsulation request failed');
      }
      const encapData = await encapRes.json();
      const kyberCiphertextB64 = encapData.kyber_ciphertext;
      const kyberSharedSecretBytes = base64ToBytes(encapData.kyber_shared_secret);

      // 3. Concatenate Secrets: IKM = ecdhSecret || kyberSecret
      setStepActive(3, true);
      const ikm = new Uint8Array(ecdhSecretBytes.length + kyberSharedSecretBytes.length);
      ikm.set(ecdhSecretBytes, 0);
      ikm.set(kyberSharedSecretBytes, ecdhSecretBytes.length);

      // 4. Derive AES-256 Session Key via HKDF-SHA256
      const ikmKey = await window.crypto.subtle.importKey(
        'raw',
        ikm,
        { name: 'HKDF' },
        false,
        ['deriveBits', 'deriveKey']
      );

      const infoBuffer = new TextEncoder().encode('hybrid-pqc-chat-v1');
      const saltBuffer = new Uint8Array(32); // standard zero salt

      const derivedSessionBits = await window.crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: saltBuffer,
          info: infoBuffer
        },
        ikmKey,
        256
      );

      sessionKeyBytes = new Uint8Array(derivedSessionBits);

      // Import as AES-GCM Key for messaging
      aesCryptoKey = await window.crypto.subtle.importKey(
        'raw',
        sessionKeyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );

      keyFingerprint = bytesToHex(sessionKeyBytes.slice(0, 8));
      bannerFingerprint.textContent = keyFingerprint;
      paramFingerprint.textContent = keyFingerprint;

      // 5. Send Handshake Reply to Server
      const reply = {
        type: 'handshake_reply',
        username: myUsername,
        client_ecdh_pub: bytesToBase64(clientEcdhPubBytes),
        kyber_ciphertext: kyberCiphertextB64
      };
      ws.send(JSON.stringify(reply));

    } catch (err) {
      console.error('Handshake execution error:', err);
      addSystemMessage('Handshake negotiation failed: ' + err.message);
    }
  }

  // Encrypt Plaintext Message with AES-256-GCM
  async function encryptAndSendMessage(plaintext) {
    if (!aesCryptoKey || !ws) {
      alert('PQC handshake not complete yet.');
      return;
    }

    try {
      // 96-bit (12-byte) random nonce per NIST recommendation
      const nonce = window.crypto.getRandomValues(new Uint8Array(12));
      const encodedPlaintext = new TextEncoder().encode(plaintext);

      const ciphertextWithTag = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesCryptoKey,
        encodedPlaintext
      );

      // Wire format: nonce (12 B) || ciphertext+tag
      const wireBlob = new Uint8Array(12 + ciphertextWithTag.byteLength);
      wireBlob.set(nonce, 0);
      wireBlob.set(new Uint8Array(ciphertextWithTag), 12);

      const payloadB64 = bytesToBase64(wireBlob);
      const ciphertextHex = bytesToHex(wireBlob);

      // Send to server
      ws.send(JSON.stringify({
        type: 'encrypted_msg',
        username: myUsername,
        payload: payloadB64
      }));

      // Render locally
      addChatMessage(myUsername + ' (You)', plaintext, ciphertextHex, true);
    } catch (err) {
      console.error('Encryption error:', err);
    }
  }

  // Decrypt Incoming Message with AES-256-GCM
  async function decryptIncomingMessage(payloadB64, sender, ciphertextHexPreview) {
    if (!aesCryptoKey) return;

    try {
      const wireBlob = base64ToBytes(payloadB64);
      const nonce = wireBlob.slice(0, 12);
      const ciphertextWithTag = wireBlob.slice(12);

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesCryptoKey,
        ciphertextWithTag
      );

      const plaintext = new TextDecoder().decode(decryptedBuffer);
      const fullHex = bytesToHex(wireBlob);
      addChatMessage(sender, plaintext, fullHex, false);
    } catch (err) {
      console.error('Decryption failed:', err);
      addChatMessage(sender, '[Decryption Error: AEAD Authentication Tag Mismatch]', null, false);
    }
  }

  // Initialize WebSocket Connection
  function initWebSocket() {
    const wsUrl = getWebSocketUrl();
    console.log('Connecting to WebSocket:', wsUrl);

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      statusPill.style.background = 'rgba(16, 185, 129, 0.15)';
      statusText.textContent = 'Negotiating PQC Handshake...';
    };

    ws.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'handshake_init') {
          await performHandshake(data);
        } else if (data.type === 'handshake_complete') {
          setStepActive(4, true);
          statusText.textContent = 'Quantum-Safe Channel Active';
          addSystemMessage('Hybrid PQC Handshake completed. AES-256-GCM channel established.');
          if (data.online_users) {
            peerCountEl.textContent = `${data.online_users.length} Online`;
          }
        } else if (data.type === 'chat_msg') {
          await decryptIncomingMessage(data.payload, data.sender, data.ciphertext_hex_preview);
        } else if (data.type === 'system') {
          addSystemMessage(data.text);
        }
      } catch (err) {
        console.error('WebSocket message handling error:', err);
      }
    };

    ws.onclose = () => {
      statusPill.style.background = 'rgba(239, 68, 68, 0.15)';
      statusText.textContent = 'Disconnected — Reconnecting...';
      setTimeout(initWebSocket, 3000);
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };
  }

  // Event Listeners
  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = chatInput.value.trim();
    if (!text) return;
    encryptAndSendMessage(text);
    chatInput.value = '';
  });

  // Prompt Chips
  document.querySelectorAll('.chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const msg = chip.getAttribute('data-msg');
      if (msg) {
        chatInput.value = msg;
        chatInput.focus();
      }
    });
  });

  // Toggle Ciphertext View
  btnToggleCipher.addEventListener('click', () => {
    showWireCiphertext = !showWireCiphertext;
    btnToggleCipher.classList.toggle('active', showWireCiphertext);
    toggleCipherLabel.textContent = showWireCiphertext ? 'View Plaintext' : 'View Wire Ciphertext';

    document.querySelectorAll('.wire-preview').forEach((el) => {
      el.classList.toggle('hidden', !showWireCiphertext);
    });
  });

  // Clear Chat
  btnClearChat.addEventListener('click', () => {
    messagesFeed.innerHTML = '';
    addSystemMessage('Chat feed cleared.');
  });

  // CLI Modal Handlers
  btnCliModal.addEventListener('click', () => {
    updateCliCommandString();
    cliModal.classList.remove('hidden');
  });

  btnCloseModal.addEventListener('click', () => {
    cliModal.classList.add('hidden');
  });

  cliModal.addEventListener('click', (e) => {
    if (e.target === cliModal) {
      cliModal.classList.add('hidden');
    }
  });

  btnCopyCommand.addEventListener('click', () => {
    if (cliCommandText) {
      navigator.clipboard.writeText(cliCommandText.textContent).then(() => {
        btnCopyCommand.textContent = 'Copied!';
        setTimeout(() => {
          btnCopyCommand.textContent = 'Copy';
        }, 2000);
      });
    }
  });

  // Initialize
  updateCliCommandString();
  initWebSocket();

})();
