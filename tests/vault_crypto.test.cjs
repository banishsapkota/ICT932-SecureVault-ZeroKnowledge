const {test} = require('node:test');
const assert = require('node:assert/strict');
const {deriveVaultKey, encryptRecord, decryptRecord, generateStrongPassword} = require('../src/static/js/vault.js');
test('AES-GCM round trip; wrong password and tampering fail', async () => {
    const key = await deriveVaultKey('separate long master passphrase', 'random-account-salt');
    assert.equal(key.extractable, false);
    const record = {label:'Bank', username:'alice', password:'private'};
    const encrypted = await encryptRecord(record, key);
    assert.deepEqual(await decryptRecord(encrypted, key), record);
    assert.notEqual((await encryptRecord(record, key)).nonce, encrypted.nonce);
    const wrong = await deriveVaultKey('wrong master passphrase', 'random-account-salt');
    await assert.rejects(decryptRecord(encrypted, wrong));
    const bytes = Buffer.from(encrypted.ciphertext, 'base64'); bytes[0] ^= 1;
    await assert.rejects(decryptRecord({...encrypted, ciphertext:bytes.toString('base64')}, key));
    assert.equal(generateStrongPassword().length, 20);
    assert.notEqual(generateStrongPassword(), generateStrongPassword());
});
