'use strict';

/*
 * Secure Notes
 * ------------
 * All notes are encrypted in the browser using the Web Crypto API.
 *
 *  - Key derivation : PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt
 *  - Encryption     : AES-256-GCM (authenticated), fresh random 12-byte IV on every save
 *  - Storage        : one encrypted blob in localStorage (titles and note count are hidden too)
 *  - Key handling   : the derived key is non-extractable and only lives in memory while unlocked
 */
(() => {
  // ---------- Settings ----------
  const STORE_KEY = 'securenotes.vault.v1';
  const GUARD_KEY = 'securenotes.guard.v1';
  const AAD = new TextEncoder().encode('securenotes:v1'); // authenticated, not secret
  const PBKDF2_ITERATIONS = 600000;
  const MIN_ITERATIONS = 100000;
  const MAX_ITERATIONS = 5000000;
  const MIN_PASSWORD_LENGTH = 10;
  const IDLE_MS = 2 * 60 * 1000;
  const SAVE_DELAY_MS = 600;
  const MAX_BACKUP_BYTES = 20 * 1024 * 1024;
  const COMMON_PASSWORDS = ['password', 'password123', '1234567890', 'qwertyuiop', 'iloveyou123', 'letmein123'];

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const $ = (id) => document.getElementById(id);

  // ---------- Element references ----------
  const lockScreen = $('lockScreen');
  const appScreen = $('appScreen');
  const lockForm = $('lockForm');
  const pwInput = $('pw');
  const pw2Input = $('pw2');
  const confirmWrap = $('confirmWrap');
  const meter = $('meter');
  const meterText = $('meterText');
  const lockMsg = $('lockMsg');
  const lockSubmit = $('lockSubmit');
  const lockTitle = $('lockTitle');
  const lockLead = $('lockLead');
  const togglePw = $('togglePw');
  const restoreBtn = $('restoreBtn');
  const eraseBtn = $('eraseBtn');
  const importFile = $('importFile');

  const searchInput = $('search');
  const newBtn = $('newBtn');
  const noteList = $('noteList');
  const emptyState = $('emptyState');
  const editorPane = $('editorPane');
  const titleInput = $('title');
  const bodyInput = $('body');
  const saveStatus = $('saveStatus');
  const deleteBtn = $('deleteBtn');

  const confirmDialog = $('confirmDialog');
  const pwDialog = $('pwDialog');
  const pwForm = $('pwForm');
  const pwError = $('pwError');

  // ---------- State ----------
  let mode = 'unlock';        // 'setup' | 'unlock'
  let session = null;         // { key, salt (base64), iter } while unlocked
  let notes = [];
  let activeId = null;
  let saveTimer = null;
  let idleTimer = null;
  let saveChain = Promise.resolve();
  let busy = false;
  let locking = false;

  // ---------- Encoding helpers ----------
  function toB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
  }

  function fromB64(str) {
    const binary = atob(str);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function uid() {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---------- Cryptography ----------
  async function deriveKey(password, salt, iterations) {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['encrypt', 'decrypt']
    );
  }

  async function seal(key, value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: AAD },
      key,
      encoder.encode(JSON.stringify(value))
    );
    return { iv: toB64(iv), data: toB64(ciphertext) };
  }

  async function openBox(key, box) {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(box.iv), additionalData: AAD },
      key,
      fromB64(box.data)
    );
    return JSON.parse(decoder.decode(plaintext));
  }

  // ---------- Vault storage ----------
  function isValidVault(v) {
    return !!v && v.v === 1 &&
      typeof v.salt === 'string' && typeof v.iv === 'string' && typeof v.data === 'string' &&
      Number.isInteger(v.iter) && v.iter >= MIN_ITERATIONS && v.iter <= MAX_ITERATIONS;
  }

  function readStored() {
    try {
      const vault = JSON.parse(localStorage.getItem(STORE_KEY));
      return isValidVault(vault) ? vault : null;
    } catch {
      return null;
    }
  }

  function persist() {
    saveChain = saveChain
      .then(async () => {
        if (!session) return;
        const box = await seal(session.key, { notes });
        localStorage.setItem(STORE_KEY, JSON.stringify({
          v: 1,
          kdf: 'PBKDF2-SHA256',
          iter: session.iter,
          salt: session.salt,
          iv: box.iv,
          data: box.data
        }));
      })
      .catch(() => setStatus('Could not save. Browser storage may be full or blocked.', true));
    return saveChain;
  }

  function sanitizeNotes(list) {
    return list
      .filter((n) => n && typeof n === 'object')
      .map((n) => ({
        id: typeof n.id === 'string' ? n.id : uid(),
        title: typeof n.title === 'string' ? n.title : '',
        body: typeof n.body === 'string' ? n.body : '',
        created: Number(n.created) || Date.now(),
        updated: Number(n.updated) || Date.now()
      }));
  }

  async function createVault(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
    session = { key, salt: toB64(salt), iter: PBKDF2_ITERATIONS };
    notes = [];
    await persist();
    if (!readStored()) {
      session = null;
      throw new Error('STORAGE');
    }
  }

  async function unlockVault(password) {
    const vault = readStored();
    if (!vault) throw new Error('DAMAGED');
    const key = await deriveKey(password, fromB64(vault.salt), vault.iter);
    let data;
    try {
      data = await openBox(key, vault);
    } catch {
      throw new Error('WRONG_PASSWORD');
    }
    if (!data || !Array.isArray(data.notes)) throw new Error('DAMAGED');
    session = { key, salt: vault.salt, iter: vault.iter };
    notes = sanitizeNotes(data.notes);
  }

  // ---------- Brute-force slow-down (convenience only; see README) ----------
  function getGuard() {
    try {
      const g = JSON.parse(localStorage.getItem(GUARD_KEY));
      return { fails: Number(g && g.fails) || 0, until: Number(g && g.until) || 0 };
    } catch {
      return { fails: 0, until: 0 };
    }
  }

  function setGuard(guard) {
    try { localStorage.setItem(GUARD_KEY, JSON.stringify(guard)); } catch { /* ignore */ }
  }

  // ---------- Password strength ----------
  function assessPassword(pw) {
    if (!pw) return { level: 0, label: '' };
    if (pw.length < MIN_PASSWORD_LENGTH) {
      return { level: 1, label: `Too short. Use at least ${MIN_PASSWORD_LENGTH} characters.` };
    }
    if (COMMON_PASSWORDS.includes(pw.toLowerCase()) || /^(.)\1+$/.test(pw)) {
      return { level: 1, label: 'Too common. Choose something harder to guess.' };
    }
    let score = 1;
    if (pw.length >= 14) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (score <= 1) return { level: 1, label: 'Weak. Add more words, numbers or symbols.' };
    if (score === 2) return { level: 2, label: 'Fair. A longer passphrase would be stronger.' };
    if (score === 3) return { level: 3, label: 'Good.' };
    return { level: 4, label: 'Strong.' };
  }

  // ---------- Dialog helpers ----------
  function confirmAction({ title, message, okLabel, danger }) {
    return new Promise((resolve) => {
      $('confirmTitle').textContent = title;
      $('confirmMsg').textContent = message;
      const ok = $('confirmOk');
      ok.textContent = okLabel;
      ok.classList.toggle('danger', !!danger);
      confirmDialog.returnValue = '';
      confirmDialog.addEventListener('close', () => resolve(confirmDialog.returnValue === 'ok'), { once: true });
      confirmDialog.showModal();
    });
  }

  // ---------- Lock screen ----------
  function setLockMessage(text, isError) {
    lockMsg.textContent = text || '';
    lockMsg.classList.toggle('error', !!isError);
  }

  function showLock(nextMode, message, isError) {
    mode = nextMode;
    lockScreen.classList.remove('unlocking');
    lockScreen.hidden = false;
    appScreen.hidden = true;
    document.title = 'Secure Notes';

    const setup = mode === 'setup';
    lockTitle.textContent = setup ? 'Create your vault' : 'Your notes are locked';
    lockLead.textContent = setup
      ? 'Choose a master password. It encrypts every note and is never stored. If you forget it, your notes cannot be recovered.'
      : 'Enter your master password to decrypt your notes.';
    lockSubmit.textContent = setup ? 'Create vault' : 'Unlock';
    pwInput.autocomplete = setup ? 'new-password' : 'current-password';
    confirmWrap.hidden = !setup;
    eraseBtn.hidden = setup;

    pwInput.value = '';
    pw2Input.value = '';
    pwInput.type = pw2Input.type = 'password';
    togglePw.textContent = 'Show';
    togglePw.setAttribute('aria-pressed', 'false');
    updateMeter();
    setLockMessage(message, isError);
    lockSubmit.disabled = false;
    busy = false;
    pwInput.focus();
  }

  function showFatal(text) {
    lockForm.hidden = true;
    restoreBtn.hidden = true;
    eraseBtn.hidden = true;
    lockTitle.textContent = 'Secure Notes cannot run here';
    lockLead.textContent = text;
  }

  function updateMeter() {
    if (mode !== 'setup') return;
    const result = assessPassword(pwInput.value);
    meter.dataset.level = String(result.level);
    meterText.textContent = result.label;
  }

  async function enterApp() {
    pwInput.value = '';
    pw2Input.value = '';
    lockScreen.classList.add('unlocking');
    if (!prefersReducedMotion()) await sleep(320);
    lockScreen.hidden = true;
    lockScreen.classList.remove('unlocking');
    appScreen.hidden = false;
    document.title = 'Secure Notes (unlocked)';
    searchInput.value = '';
    setStatus('');
    renderList();
    if (notes.length) {
      selectNote([...notes].sort((a, b) => b.updated - a.updated)[0].id);
    } else {
      showEditor(false);
    }
    resetIdle();
  }

  lockForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const password = pwInput.value;

    if (mode === 'setup') {
      if (password.length < MIN_PASSWORD_LENGTH) {
        setLockMessage(`Use at least ${MIN_PASSWORD_LENGTH} characters.`, true);
        return;
      }
      if (password !== pw2Input.value) {
        setLockMessage('The two passwords do not match.', true);
        return;
      }
    } else {
      if (!password) {
        setLockMessage('Enter your master password.', true);
        return;
      }
      const guard = getGuard();
      const wait = Math.ceil((guard.until - Date.now()) / 1000);
      if (wait > 0) {
        setLockMessage(`Too many wrong attempts. Try again in ${wait} seconds.`, true);
        return;
      }
    }

    busy = true;
    lockSubmit.disabled = true;
    lockSubmit.textContent = mode === 'setup' ? 'Creating vault…' : 'Unlocking…';
    setLockMessage('');

    try {
      if (mode === 'setup') {
        await createVault(password);
      } else {
        await unlockVault(password);
        setGuard({ fails: 0, until: 0 });
      }
      await enterApp();
    } catch (err) {
      const code = err && err.message;
      if (code === 'WRONG_PASSWORD') {
        const guard = getGuard();
        guard.fails += 1;
        if (guard.fails >= 3) {
          guard.until = Date.now() + Math.min(2 ** (guard.fails - 2), 60) * 1000;
        }
        setGuard(guard);
        setLockMessage('Incorrect password. Check it and try again.', true);
      } else if (code === 'DAMAGED') {
        setLockMessage('The stored data is damaged. Restore a backup or erase the vault.', true);
      } else if (code === 'STORAGE') {
        setLockMessage('Your browser is blocking storage, so the vault could not be created.', true);
      } else {
        setLockMessage('Something went wrong. Reload the page and try again.', true);
      }
      lockSubmit.disabled = false;
      lockSubmit.textContent = mode === 'setup' ? 'Create vault' : 'Unlock';
      busy = false;
      pwInput.select();
    }
  });

  pwInput.addEventListener('input', updateMeter);

  togglePw.addEventListener('click', () => {
    const show = pwInput.type === 'password';
    pwInput.type = pw2Input.type = show ? 'text' : 'password';
    togglePw.textContent = show ? 'Hide' : 'Show';
    togglePw.setAttribute('aria-pressed', String(show));
  });

  // ---------- Backup restore / erase (lock screen) ----------
  restoreBtn.addEventListener('click', () => importFile.click());

  importFile.addEventListener('change', async () => {
    const file = importFile.files[0];
    importFile.value = '';
    if (!file) return;
    if (file.size > MAX_BACKUP_BYTES) {
      setLockMessage('That file is too large to be a backup.', true);
      return;
    }
    let vault;
    try {
      vault = JSON.parse(await file.text());
    } catch {
      vault = null;
    }
    if (!isValidVault(vault)) {
      setLockMessage('That file is not a valid Secure Notes backup.', true);
      return;
    }
    if (localStorage.getItem(STORE_KEY) !== null) {
      const ok = await confirmAction({
        title: 'Replace the current vault?',
        message: 'The vault stored in this browser will be overwritten by the backup.',
        okLabel: 'Replace vault',
        danger: true
      });
      if (!ok) return;
    }
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({
        v: 1, kdf: 'PBKDF2-SHA256', iter: vault.iter, salt: vault.salt, iv: vault.iv, data: vault.data
      }));
      setGuard({ fails: 0, until: 0 });
    } catch {
      setLockMessage('Could not save the backup. Browser storage may be blocked.', true);
      return;
    }
    showLock('unlock', 'Backup restored. Enter the master password it was created with.');
  });

  eraseBtn.addEventListener('click', async () => {
    const ok = await confirmAction({
      title: 'Erase the vault?',
      message: 'All notes stored in this browser will be permanently deleted. This cannot be undone.',
      okLabel: 'Erase everything',
      danger: true
    });
    if (!ok) return;
    try {
      localStorage.removeItem(STORE_KEY);
      localStorage.removeItem(GUARD_KEY);
    } catch { /* ignore */ }
    showLock('setup', 'Vault erased. Create a new one to start again.');
  });

  // ---------- Notes list & editor ----------
  function formatDate(ts) {
    return new Date(ts).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function renderList() {
    const query = searchInput.value.trim().toLowerCase();
    const visible = notes
      .filter((n) => !query || n.title.toLowerCase().includes(query) || n.body.toLowerCase().includes(query))
      .sort((a, b) => b.updated - a.updated);

    noteList.replaceChildren();

    if (!visible.length) {
      const li = document.createElement('li');
      li.className = 'list-empty';
      li.textContent = query ? 'No notes match your search.' : 'No notes yet. Select "New note" to begin.';
      noteList.append(li);
      return;
    }

    for (const note of visible) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'note-item';
      btn.setAttribute('aria-current', String(note.id === activeId));
      btn.dataset.id = note.id;

      const title = document.createElement('span');
      title.className = 'n-title';
      title.textContent = note.title.trim() || 'Untitled note';

      const meta = document.createElement('span');
      meta.className = 'n-meta';
      const snippet = note.body.replace(/\s+/g, ' ').trim().slice(0, 60);
      meta.textContent = snippet || formatDate(note.updated);

      btn.append(title, meta);
      li.append(btn);
      noteList.append(li);
    }
  }

  noteList.addEventListener('click', (event) => {
    const btn = event.target.closest('.note-item');
    if (btn) selectNote(btn.dataset.id);
  });

  function showEditor(visible) {
    editorPane.hidden = !visible;
    emptyState.hidden = visible;
  }

  function selectNote(id) {
    const note = notes.find((n) => n.id === id);
    if (!note) return;
    activeId = id;
    titleInput.value = note.title;
    bodyInput.value = note.body;
    showEditor(true);
    setStatus('Encrypted on this device');
    renderList();
  }

  function activeNote() {
    return notes.find((n) => n.id === activeId) || null;
  }

  function setStatus(text, isError) {
    saveStatus.textContent = text || '';
    saveStatus.style.color = isError ? 'var(--danger)' : '';
  }

  function onEdit() {
    const note = activeNote();
    if (!note) return;
    note.title = titleInput.value;
    note.body = bodyInput.value;
    note.updated = Date.now();
    setStatus('Saving…');
    clearTimeout(saveTimer);
    saveTimer = setTimeout(flushSave, SAVE_DELAY_MS);
  }

  async function flushSave() {
    clearTimeout(saveTimer);
    saveTimer = null;
    if (!session) return;
    await persist();
    if (session) {
      setStatus('Saved and encrypted');
      renderList();
    }
  }

  titleInput.addEventListener('input', onEdit);
  bodyInput.addEventListener('input', onEdit);
  searchInput.addEventListener('input', renderList);

  newBtn.addEventListener('click', async () => {
    const now = Date.now();
    const note = { id: uid(), title: '', body: '', created: now, updated: now };
    notes.push(note);
    searchInput.value = '';
    selectNote(note.id);
    titleInput.focus();
    await flushSave();
  });

  deleteBtn.addEventListener('click', async () => {
    const note = activeNote();
    if (!note) return;
    const ok = await confirmAction({
      title: 'Delete this note?',
      message: `"${note.title.trim() || 'Untitled note'}" will be permanently deleted.`,
      okLabel: 'Delete note',
      danger: true
    });
    if (!ok || !session) return;
    notes = notes.filter((n) => n.id !== note.id);
    activeId = null;
    await flushSave();
    if (notes.length) {
      selectNote([...notes].sort((a, b) => b.updated - a.updated)[0].id);
    } else {
      showEditor(false);
      renderList();
    }
    setStatus('Note deleted');
  });

  // ---------- Locking & inactivity ----------
  async function lock(message) {
    if (!session || locking) return;
    locking = true;
    clearTimeout(idleTimer);
    clearTimeout(saveTimer);
    saveTimer = null;
    try {
      await persist();
    } finally {
      session = null;
      notes = [];
      activeId = null;
      titleInput.value = '';
      bodyInput.value = '';
      searchInput.value = '';
      noteList.replaceChildren();
      showEditor(false);
      if (confirmDialog.open) confirmDialog.close();
      if (pwDialog.open) pwDialog.close();
      locking = false;
      showLock('unlock', message);
    }
  }

  function resetIdle() {
    if (!session) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => lock('Locked after 2 minutes of inactivity.'), IDLE_MS);
  }

  ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach((name) =>
    document.addEventListener(name, resetIdle, { passive: true, capture: true })
  );

  document.addEventListener('visibilitychange', () => {
    if (document.hidden && saveTimer) flushSave();
  });

  $('lockBtn').addEventListener('click', () => lock('Locked.'));

  // ---------- Export backup ----------
  $('exportBtn').addEventListener('click', async () => {
    await flushSave();
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) {
      setStatus('Nothing to export yet.', true);
      return;
    }
    const url = URL.createObjectURL(new Blob([raw], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `secure-notes-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatus('Backup downloaded. It is encrypted with your master password.');
  });

  // ---------- Change master password ----------
  $('changePwBtn').addEventListener('click', () => {
    pwForm.reset();
    pwError.textContent = '';
    pwDialog.showModal();
    $('curPw').focus();
  });

  $('pwCancel').addEventListener('click', () => pwDialog.close());

  pwForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!session) return;
    const current = $('curPw').value;
    const next = $('newPw').value;
    const confirmNext = $('newPw2').value;
    pwError.textContent = '';

    if (!current) { pwError.textContent = 'Enter your current password.'; return; }
    if (next.length < MIN_PASSWORD_LENGTH) { pwError.textContent = `The new password needs at least ${MIN_PASSWORD_LENGTH} characters.`; return; }
    if (next !== confirmNext) { pwError.textContent = 'The new passwords do not match.'; return; }
    if (next === current) { pwError.textContent = 'Choose a password different from the current one.'; return; }

    const submit = $('pwSubmit');
    submit.disabled = true;
    submit.textContent = 'Changing…';
    try {
      const vault = readStored();
      if (!vault) { pwError.textContent = 'The stored data is damaged.'; return; }

      const oldKey = await deriveKey(current, fromB64(vault.salt), vault.iter);
      try {
        await openBox(oldKey, vault);
      } catch {
        pwError.textContent = 'The current password is incorrect.';
        return;
      }

      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(next, salt, PBKDF2_ITERATIONS);
      session = { key, salt: toB64(salt), iter: PBKDF2_ITERATIONS };
      await persist();
      pwDialog.close();
      setStatus('Master password changed. Notes were re-encrypted.');
    } catch {
      pwError.textContent = 'Something went wrong. Try again.';
    } finally {
      submit.disabled = false;
      submit.textContent = 'Change password';
    }
  });

  // ---------- Start ----------
  function init() {
    if (!window.crypto || !crypto.subtle || !window.isSecureContext) {
      showFatal('This app needs a secure connection (HTTPS or localhost) and a browser that supports the Web Crypto API.');
      return;
    }
    let hasVault;
    try {
      hasVault = localStorage.getItem(STORE_KEY) !== null;
    } catch {
      showFatal('Your browser is blocking local storage, so notes cannot be saved. Allow site data and reload.');
      return;
    }
    showLock(hasVault ? 'unlock' : 'setup');
  }

  init();
})();
