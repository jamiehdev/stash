(function() {
  'use strict';

  const app = document.getElementById('app');
  const path = window.location.pathname;
  const hash = window.location.hash;

  // check if viewing paste
  if (path.startsWith('/p/') && hash.startsWith('#v1:')) {
    viewMode();
  } else {
    createMode();
  }

  function createMode() {
    app.innerHTML = `
      <textarea id="content" placeholder="Paste your content here..."></textarea>
      <div class="controls">
        <select id="ttl">
          <option value="3600">1 hour</option>
          <option value="21600">6 hours</option>
          <option value="86400">24 hours</option>
          <option value="604800">7 days</option>
        </select>
        <button id="submit">Create Paste</button>
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
      result.innerHTML = '<p class="error">Please enter some content</p>';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Encrypting...';

    try {
      // generate key
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      // generate delete token
      const deleteToken = arrayToBase64url(crypto.getRandomValues(new Uint8Array(16)));

      // hash delete token for server
      const tokenBytes = new TextEncoder().encode(deleteToken);
      const hashBuffer = await crypto.subtle.digest('SHA-256', tokenBytes);
      const deleteHash = arrayToHex(new Uint8Array(hashBuffer));

      // encrypt
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(content);
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        plaintext
      );

      // create blob: version(1) || nonce(12) || ciphertext+tag
      const blob = new Uint8Array(1 + 12 + ciphertext.byteLength);
      blob[0] = 0x01;
      blob.set(nonce, 1);
      blob.set(new Uint8Array(ciphertext), 13);

      // export key
      const keyBytes = await crypto.subtle.exportKey('raw', key);
      const keyB64 = arrayToBase64url(new Uint8Array(keyBytes));

      // send to server
      const resp = await fetch('/api/paste', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: arrayToBase64url(blob),
          ttl: ttl,
          delete_token_hash: deleteHash
        })
      });

      if (!resp.ok) throw new Error('Failed to create paste');

      const data = await resp.json();
      const pasteUrl = window.location.origin + '/p/' + data.id + '#v1:' + keyB64;
      const deleteUrl = window.location.origin + '/api/paste/' + data.id + '?token=' + deleteToken;

      result.innerHTML = `
        <p><strong>Paste URL:</strong></p>
        <p><a href="${pasteUrl}">${pasteUrl}</a></p>
        <p><strong>Delete URL:</strong></p>
        <p><a href="${deleteUrl}">${deleteUrl}</a></p>
        <p><em>Expires: ${new Date(data.expires_at).toLocaleString()}</em></p>
      `;
    } catch (err) {
      result.innerHTML = '<p class="error">Error: ' + err.message + '</p>';
    }

    btn.disabled = false;
    btn.textContent = 'Create Paste';
  }

  async function viewMode() {
    app.innerHTML = '<p class="loading">Decrypting...</p>';

    try {
      const id = path.split('/p/')[1];
      const keyB64 = hash.substring(4); // remove #v1:

      // fetch blob
      const resp = await fetch('/api/paste/' + id);
      if (!resp.ok) {
        if (resp.status === 404) {
          app.innerHTML = '<p class="error">Paste not found or expired</p>';
          return;
        }
        throw new Error('Failed to fetch paste');
      }

      const data = await resp.json();
      const blob = base64urlToArray(data.content);

      // parse blob
      if (blob[0] !== 0x01) throw new Error('Unsupported version');
      const nonce = blob.slice(1, 13);
      const ciphertext = blob.slice(13);

      // import key
      const keyBytes = base64urlToArray(keyB64);
      const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      // decrypt
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext
      );

      const text = new TextDecoder().decode(plaintext);
      const pre = document.createElement('pre');
      pre.textContent = text;
      app.innerHTML = '';
      app.appendChild(pre);

      const info = document.createElement('p');
      info.innerHTML = '<em>Expires: ' + new Date(data.expires_at).toLocaleString() + '</em>';
      app.appendChild(info);
    } catch (err) {
      app.innerHTML = '<p class="error">Decryption failed: ' + err.message + '</p>';
    }
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
