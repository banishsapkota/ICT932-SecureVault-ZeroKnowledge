'use strict';
let vaultKey = null, epoch = 0, lockTimer;
const $ = id => document.getElementById(id);
const message = text => { $('status').textContent = text; };
const marker = 'SecureVault key verification v1';
function toBase64(buffer) { return btoa(Array.from(new Uint8Array(buffer), b => String.fromCharCode(b)).join('')); }
function fromBase64(text) { return Uint8Array.from(atob(text), c => c.charCodeAt(0)); }
async function deriveVaultKey(password, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt:new TextEncoder().encode(salt), iterations:600000, hash:'SHA-256'}, base,
        {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encryptRecord(record, key) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce}, key, new TextEncoder().encode(JSON.stringify(record)));
    return {ciphertext:toBase64(ciphertext), nonce:toBase64(nonce)};
}
async function decryptRecord(envelope, key) {
    const data = await crypto.subtle.decrypt({name:'AES-GCM', iv:fromBase64(envelope.nonce)}, key, fromBase64(envelope.ciphertext));
    return JSON.parse(new TextDecoder().decode(data));
}
function generateStrongPassword(length = 20) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
    let result = '';
    const limit = 256 - (256 % chars.length);
    while (result.length < length) {
        for (const byte of crypto.getRandomValues(new Uint8Array(length)))
            if (byte < limit && result.length < length) result += chars[byte % chars.length];
    }
    return result;
}
async function api(path = '', method = 'GET', data) {
    const response = await fetch('/api/vault' + path, {method, credentials:'same-origin',
        headers:{'Content-Type':'application/json', 'X-CSRFToken':document.querySelector('meta[name="csrf-token"]').content},
        body:data === undefined ? undefined : JSON.stringify(data)});
    if (!response.ok) {
        if (response.status === 401) lockVault();
        throw new Error(response.status === 409 ? 'Vault state changed. Lock and unlock again.' : 'Request failed. Your session may have expired.');
    }
    return response.status === 204 ? null : response.json();
}
function resetLockTimer() { clearTimeout(lockTimer); lockTimer = setTimeout(lockVault, 5 * 60 * 1000); }
function lockVault() {
    epoch++; vaultKey = null; clearTimeout(lockTimer);
    for (const id of ['masterPassword','entryLabel','entryUsername','entryPassword']) $(id).value = '';
    $('entryList').replaceChildren(); $('vaultArea').classList.add('hidden'); message('Vault locked.');
}
async function loadEntries(key, generation) {
    const entries = await api(), fragment = document.createDocumentFragment();
    for (const entry of entries) {
        const row = document.createElement('div'); row.className = 'vault-entry';
        try {
            const record = await decryptRecord(entry, key);
            const title = document.createElement('strong'); title.textContent = record.label;
            const username = document.createElement('p'); username.textContent = 'User: ' + record.username;
            const password = document.createElement('input'); password.type = 'password'; password.readOnly = true; password.value = record.password;
            password.setAttribute('aria-label', 'Saved password');
            const reveal = document.createElement('button'); reveal.textContent = 'Show / hide';
            reveal.addEventListener('click', () => { password.type = password.type === 'password' ? 'text' : 'password'; });
            const remove = document.createElement('button'); remove.textContent = 'Delete';
            remove.addEventListener('click', () => run(async () => {
                if (!vaultKey || generation !== epoch) return;
                await api('/' + entry.id, 'DELETE'); await loadEntries(key, generation);
            }));
            row.append(title, username, password, reveal, remove);
        } catch { row.textContent = 'Cannot authenticate this record: it may have been modified.'; }
        fragment.append(row);
    }
    // A pending decrypt must never repopulate plaintext after locking.
    if (generation === epoch && vaultKey === key) $('entryList').replaceChildren(fragment);
}
async function unlockVault() {
    const password = $('masterPassword').value;
    lockVault(); const generation = epoch;
    if (password.length < 12) throw new Error('Use a master passphrase of at least 12 characters.');
    const check = await api('/key-check'), key = await deriveVaultKey(password, check.salt);
    if (generation !== epoch) return;
    if (check.ciphertext) {
        let value;
        try { value = await decryptRecord(check, key); } catch { throw new Error('Incorrect master passphrase or damaged vault verification record.'); }
        if (value !== marker) throw new Error('Vault verification failed.');
    } else {
        const encrypted = await encryptRecord(marker, key);
        if (generation !== epoch) return;
        await api('/key-check', 'POST', encrypted);
    }
    if (generation !== epoch) return;
    vaultKey = key; $('vaultArea').classList.remove('hidden'); resetLockTimer(); message('Vault unlocked.');
    await loadEntries(key, generation);
}
async function saveEntry() {
    const key = vaultKey, generation = epoch;
    if (!key) throw new Error('Unlock the vault first.');
    const record = {label:$('entryLabel').value.trim(), username:$('entryUsername').value, password:$('entryPassword').value};
    if (!record.label || !record.password) throw new Error('Label and password are required.');
    if (JSON.stringify(record).length > 16000) throw new Error('Record is too large.');
    const encrypted = await encryptRecord(record, key);
    if (generation !== epoch || vaultKey !== key) return;
    await api('', 'POST', encrypted);
    if (generation !== epoch) return;
    for (const id of ['entryLabel','entryUsername','entryPassword']) $(id).value = '';
    message('Encrypted record saved.'); await loadEntries(key, generation);
}
async function run(action) { try { await action(); } catch (error) { message(error.message); } }
if (typeof document !== 'undefined') {
    $('unlockButton').addEventListener('click', () => run(unlockVault));
    $('lockButton').addEventListener('click', lockVault);
    $('saveButton').addEventListener('click', () => run(saveEntry));
    $('generateButton').addEventListener('click', () => { $('entryPassword').value = generateStrongPassword(); });
    ['keydown','click'].forEach(name => document.addEventListener(name, () => { if (vaultKey) resetLockTimer(); }));
    window.addEventListener('pagehide', lockVault);
    window.addEventListener('pageshow', event => { if (event.persisted) lockVault(); });
    document.querySelector('form[action$="/logout"]').addEventListener('submit', lockVault);
}
if (typeof module !== 'undefined') module.exports = {deriveVaultKey, encryptRecord, decryptRecord, generateStrongPassword};
