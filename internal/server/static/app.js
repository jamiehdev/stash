(function() {
  'use strict';

  const app = document.getElementById('app');
  const path = window.location.pathname;
  const hash = window.location.hash;

  if (path.startsWith('/p/') && hash.startsWith('#v1:')) {
    viewMode();
  } else {
    createMode();
  }

  function createMode() {
    app.innerHTML = `
      <textarea id="content" placeholder="paste content here..."></textarea>
      <div class="controls">
        <select id="ttl">
          <option value="3600">1 hour</option>
          <option value="21600">6 hours</option>
          <option value="86400" selected>24 hours</option>
          <option value="604800">7 days</option>
        </select>
        <button id="submit">create paste</button>
      </div>
      <div id="result"></div>
    `;

    document.getElementById('submit').addEventListener('click', createPaste);
  }

  async function createPaste() {
    const content = document.getElementById('content').value;
    const ttl = parseInt(document.getElementById('ttl').value);
    const result = document.getElementById('result');
    const btn = document.getElementById('submit');

    if (!content) {
      result.innerHTML = '<p class="error">enter some content first</p>';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'encrypting...';

    try {
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      const deleteToken = arrayToBase64url(crypto.getRandomValues(new Uint8Array(16)));

      const tokenBytes = new TextEncoder().encode(deleteToken);
      const hashBuffer = await crypto.subtle.digest('SHA-256', tokenBytes);
      const deleteHash = arrayToHex(new Uint8Array(hashBuffer));

      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(content);
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        plaintext
      );

      const blob = new Uint8Array(1 + 12 + ciphertext.byteLength);
      blob[0] = 0x01;
      blob.set(nonce, 1);
      blob.set(new Uint8Array(ciphertext), 13);

      const keyBytes = await crypto.subtle.exportKey('raw', key);
      const keyB64 = arrayToBase64url(new Uint8Array(keyBytes));

      const resp = await fetch('/api/paste', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: arrayToBase64url(blob),
          ttl: ttl,
          delete_token_hash: deleteHash
        })
      });

      if (!resp.ok) throw new Error('failed to create paste');

      const data = await resp.json();
      const pasteUrl = window.location.origin + '/p/' + data.id + '#v1:' + keyB64;
      const deleteUrl = window.location.origin + '/api/paste/' + data.id + '?token=' + deleteToken;

      result.innerHTML = `
        <div class="result">
          <div class="result-section">
            <p class="result-label">paste url</p>
            <a class="result-url" href="${pasteUrl}">${pasteUrl}</a>
          </div>
          <div class="result-section">
            <p class="result-label">delete url</p>
            <a class="result-url" href="${deleteUrl}">${deleteUrl}</a>
          </div>
          <p class="result-meta">expires ${formatExpiry(data.expires_at)}</p>
        </div>
      `;
    } catch (err) {
      result.innerHTML = '<p class="error">error: ' + err.message + '</p>';
    }

    btn.disabled = false;
    btn.textContent = 'create paste';
  }

  async function viewMode() {
    app.innerHTML = '<p class="loading">decrypting</p>';

    try {
      const id = path.split('/p/')[1];
      const keyB64 = hash.substring(4);

      const resp = await fetch('/api/paste/' + id);
      if (!resp.ok) {
        if (resp.status === 404) {
          app.innerHTML = '<p class="error">paste not found or expired</p>';
          return;
        }
        throw new Error('failed to fetch paste');
      }

      const data = await resp.json();
      const blob = base64urlToArray(data.content);

      if (blob[0] !== 0x01) throw new Error('unsupported version');
      const nonce = blob.slice(1, 13);
      const ciphertext = blob.slice(13);

      const keyBytes = base64urlToArray(keyB64);
      const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext
      );

      const text = new TextDecoder().decode(plaintext);
      app.innerHTML = `
        <pre>${escapeHtml(text)}</pre>
        <p class="view-meta">expires ${formatExpiry(data.expires_at)}</p>
      `;
    } catch (err) {
      app.innerHTML = '<p class="error">decryption failed: ' + err.message + '</p>';
    }
  }

  function formatExpiry(isoDate) {
    const d = new Date(isoDate);
    const now = new Date();
    const diffMs = d - now;

    if (diffMs < 0) return 'expired';

    const diffHrs = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHrs / 24);

    if (diffDays > 0) return `in ${diffDays}d ${diffHrs % 24}h`;
    if (diffHrs > 0) return `in ${diffHrs}h`;

    const diffMins = Math.floor(diffMs / (1000 * 60));
    return `in ${diffMins}m`;
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function arrayToBase64url(arr) {
    let binary = '';
    for (let i = 0; i < arr.length; i++) {
      binary += String.fromCharCode(arr[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64urlToArray(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const arr = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      arr[i] = binary.charCodeAt(i);
    }
    return arr;
  }

  function arrayToHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }
})();
