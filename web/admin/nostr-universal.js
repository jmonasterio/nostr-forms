/**
 * nostr-universal.js
 *
 * A standalone, zero-dependency Nostr authentication library.
 * Works on desktop, mobile, localhost - with NIP-07, NIP-46, and dev signers.
 *
 * @license MIT
 */

// ============================================================================
// CRYPTO PRIMITIVES (secp256k1 + schnorr)
// ============================================================================

const CURVE = {
  P: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  N: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

function mod(a, m = CURVE.P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modInverse(a, m = CURVE.P) {
  a = mod(a, m); // Normalize to positive first
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

function pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2 && y1 === y2) {
    const s = mod(3n * x1 * x1 * modInverse(2n * y1));
    const x3 = mod(s * s - 2n * x1);
    const y3 = mod(s * (x1 - x3) - y1);
    return [x3, y3];
  }
  if (x1 === x2) return null;
  const s = mod((y2 - y1) * modInverse(x2 - x1));
  const x3 = mod(s * s - x1 - x2);
  const y3 = mod(s * (x1 - x3) - y1);
  return [x3, y3];
}

function pointMultiply(k, p = [CURVE.Gx, CURVE.Gy]) {
  let result = null;
  let addend = p;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

function bytesToBigInt(bytes) {
  return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
}

function bigIntToBytes(n, len = 32) {
  const hex = n.toString(16).padStart(len * 2, '0');
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function hexToBytes(hex) {
  if (hex.length % 2) hex = '0' + hex;
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

async function sha256(data) {
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

async function hmacSha256(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(sig);
}

function getRandomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function generatePrivateKey() {
  let sk;
  do {
    sk = bytesToBigInt(getRandomBytes(32));
  } while (sk === 0n || sk >= CURVE.N);
  return bigIntToBytes(sk);
}

const _pubkeyCache = new Map();

function getPublicKey(privateKey) {
  const keyHex = bytesToHex(privateKey);
  const cached = _pubkeyCache.get(keyHex);
  if (cached) return bigIntToBytes(cached[0]);
  const sk = bytesToBigInt(privateKey);
  const point = pointMultiply(sk);
  if (_pubkeyCache.size >= 20) {
    const first = _pubkeyCache.keys().next().value;
    _pubkeyCache.delete(first);
  }
  _pubkeyCache.set(keyHex, point);
  return bigIntToBytes(point[0]);
}

async function taggedHash(tag, ...data) {
  const tagHash = await sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, ...data));
}

async function schnorrSign(message, privateKey) {
  const keyHex = bytesToHex(privateKey);
  let P = _pubkeyCache.get(keyHex);
  if (!P) {
    const sk = bytesToBigInt(privateKey);
    P = pointMultiply(sk);
    if (_pubkeyCache.size >= 20) {
      const first = _pubkeyCache.keys().next().value;
      _pubkeyCache.delete(first);
    }
    _pubkeyCache.set(keyHex, P);
  }
  const d = bytesToBigInt(privateKey);
  const pk = bigIntToBytes(P[0]);

  // Negate d if P.y is odd
  const d_ = P[1] % 2n === 0n ? d : CURVE.N - d;

  // Generate k using RFC 6979-like deterministic nonce
  const aux = getRandomBytes(32);
  const t = await taggedHash('BIP0340/aux', aux);
  const tXor = new Uint8Array(32);
  for (let i = 0; i < 32; i++) tXor[i] = bigIntToBytes(d_)[i] ^ t[i];

  const rand = await taggedHash('BIP0340/nonce', tXor, pk, message);
  let k = mod(bytesToBigInt(rand), CURVE.N);
  if (k === 0n) throw new Error('Invalid nonce');

  const R = pointMultiply(k);
  if (R[1] % 2n !== 0n) k = CURVE.N - k;

  const r = bigIntToBytes(R[0]);
  const e = await taggedHash('BIP0340/challenge', r, pk, message);
  const eInt = mod(bytesToBigInt(e), CURVE.N);
  const s = mod(k + eInt * d_, CURVE.N);

  return concatBytes(r, bigIntToBytes(s));
}

async function schnorrVerify(signature, message, publicKey) {
  if (signature.length !== 64) return false;
  const r = bytesToBigInt(signature.slice(0, 32));
  const s = bytesToBigInt(signature.slice(32));
  const P = [bytesToBigInt(publicKey), null];

  // Compute y from x
  const x = P[0];
  const y2 = mod(x ** 3n + 7n);
  let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
  if (y % 2n !== 0n) y = CURVE.P - y;
  P[1] = y;

  if (r >= CURVE.P || s >= CURVE.N) return false;

  const e = await taggedHash('BIP0340/challenge', bigIntToBytes(r), publicKey, message);
  const eInt = mod(bytesToBigInt(e), CURVE.N);

  const sG = pointMultiply(s);
  const eP = pointMultiply(eInt, P);
  const negEP = eP ? [eP[0], CURVE.P - eP[1]] : null;
  const R = pointAdd(sG, negEP);

  if (!R || R[1] % 2n !== 0n) return false;
  return R[0] === r;
}

function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp % 2n === 1n) result = mod(result * base, m);
    exp = exp >> 1n;
    base = mod(base * base, m);
  }
  return result;
}

// ============================================================================
// BECH32 ENCODING (for npub/nsec)
// ============================================================================

const BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32CreateChecksum(hrp, data) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ 1;
  const ret = [];
  for (let i = 0; i < 6; i++) ret.push((polymod >> (5 * (5 - i))) & 31);
  return ret;
}

function bech32VerifyChecksum(hrp, data) {
  return bech32Polymod(bech32HrpExpand(hrp).concat(data)) === 1;
}

function bech32Encode(hrp, data) {
  const combined = data.concat(bech32CreateChecksum(hrp, data));
  let ret = hrp + '1';
  for (const d of combined) ret += BECH32_ALPHABET[d];
  return ret;
}

function bech32Decode(str) {
  const pos = str.lastIndexOf('1');
  if (pos < 1 || pos + 7 > str.length) throw new Error('Invalid bech32');
  const hrp = str.slice(0, pos).toLowerCase();
  const data = [];
  for (let i = pos + 1; i < str.length; i++) {
    const idx = BECH32_ALPHABET.indexOf(str[i].toLowerCase());
    if (idx === -1) throw new Error('Invalid character');
    data.push(idx);
  }
  if (!bech32VerifyChecksum(hrp, data)) throw new Error('Invalid checksum');
  return { hrp, data: data.slice(0, -6) };
}

function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0, bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const d of data) {
    acc = (acc << fromBits) | d;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

function encodeNpub(pubkeyHex) {
  const bytes = hexToBytes(pubkeyHex);
  const words = convertBits(Array.from(bytes), 8, 5);
  return bech32Encode('npub', words);
}

function encodeNsec(seckeyHex) {
  const bytes = hexToBytes(seckeyHex);
  const words = convertBits(Array.from(bytes), 8, 5);
  return bech32Encode('nsec', words);
}

function decodeNpub(npub) {
  const { hrp, data } = bech32Decode(npub);
  if (hrp !== 'npub') throw new Error('Invalid npub');
  const bytes = convertBits(data, 5, 8, false);
  return bytesToHex(new Uint8Array(bytes));
}

function decodeNsec(nsec) {
  const { hrp, data } = bech32Decode(nsec);
  if (hrp !== 'nsec') throw new Error('Invalid nsec');
  const bytes = convertBits(data, 5, 8, false);
  return bytesToHex(new Uint8Array(bytes));
}

// ============================================================================
// NIP-04: ENCRYPTED DIRECT MESSAGES
// ============================================================================

const _sharedSecretCache = new Map();
const _cryptoKeyCache = new Map();

async function deriveSharedSecret(privateKey, publicKey) {
  // Cache key: concat of both keys (same pair always yields same secret)
  const cacheKey = bytesToHex(privateKey) + bytesToHex(publicKey);
  const cached = _sharedSecretCache.get(cacheKey);
  if (cached) return cached;

  const sk = bytesToBigInt(privateKey);
  const pk = bytesToBigInt(publicKey);

  // Lift x to point
  const x = pk;
  const y2 = mod(x ** 3n + 7n);
  let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
  if (y % 2n !== 0n) y = CURVE.P - y; // even y

  const point = [x, y];
  const shared = pointMultiply(sk, point);
  const result = bigIntToBytes(shared[0]);

  // Keep cache bounded (max 20 entries)
  if (_sharedSecretCache.size >= 20) {
    const first = _sharedSecretCache.keys().next().value;
    _sharedSecretCache.delete(first);
  }
  _sharedSecretCache.set(cacheKey, result);
  return result;
}

async function getCryptoKey(sharedSecret, usage) {
  const cacheKey = bytesToHex(sharedSecret) + ':' + usage;
  const cached = _cryptoKeyCache.get(cacheKey);
  if (cached) return cached;
  const key = await crypto.subtle.importKey(
    'raw', sharedSecret, { name: 'AES-CBC' }, false, [usage]
  );
  if (_cryptoKeyCache.size >= 20) {
    const first = _cryptoKeyCache.keys().next().value;
    _cryptoKeyCache.delete(first);
  }
  _cryptoKeyCache.set(cacheKey, key);
  return key;
}

async function nip04Encrypt(content, privateKey, publicKey) {
  const sharedSecret = await deriveSharedSecret(privateKey, publicKey);
  const iv = getRandomBytes(16);

  const key = await getCryptoKey(sharedSecret, 'encrypt');

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv }, key, utf8ToBytes(content)
  );

  const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  const ivBase64 = btoa(String.fromCharCode(...iv));

  return `${encryptedBase64}?iv=${ivBase64}`;
}

// Decode base64, handling URL-safe variants and padding
function base64Decode(str) {
  // Convert URL-safe base64 to standard base64
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  while (b64.length % 4) b64 += '=';
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function base64Encode(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function nip04Decrypt(content, privateKey, publicKey) {
  const [encryptedBase64, ivPart] = content.split('?iv=');
  if (!ivPart) {
    throw new Error('Invalid NIP-04 content: missing IV');
  }
  const encrypted = base64Decode(encryptedBase64);
  const iv = base64Decode(ivPart);

  const sharedSecret = await deriveSharedSecret(privateKey, publicKey);

  const key = await getCryptoKey(sharedSecret, 'decrypt');

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv }, key, encrypted
  );

  return bytesToUtf8(new Uint8Array(decrypted));
}

// ============================================================================
// NIP-44 ENCRYPTION (ChaCha20-Poly1305)
// ============================================================================

// ChaCha20 quarter round
function quarterRound(state, a, b, c, d) {
  state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 16) | (state[d] >>> 16);
  state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 12) | (state[b] >>> 20);
  state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 8) | (state[d] >>> 24);
  state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 7) | (state[b] >>> 25);
}

function chacha20Block(key, counter, nonce) {
  const state = new Uint32Array(16);
  // "expand 32-byte k"
  state[0] = 0x61707865; state[1] = 0x3320646e;
  state[2] = 0x79622d32; state[3] = 0x6b206574;

  const keyView = new DataView(key.buffer, key.byteOffset, 32);
  for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);

  state[12] = counter;
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, 12);
  for (let i = 0; i < 3; i++) state[13 + i] = nonceView.getUint32(i * 4, true);

  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const output = new Uint8Array(64);
  const outView = new DataView(output.buffer);
  for (let i = 0; i < 16; i++) {
    outView.setUint32(i * 4, (working[i] + state[i]) >>> 0, true);
  }
  return output;
}

function hchacha20(key, nonce16) {
  const state = new Uint32Array(16);
  state[0] = 0x61707865; state[1] = 0x3320646e;
  state[2] = 0x79622d32; state[3] = 0x6b206574;

  const keyView = new DataView(key.buffer, key.byteOffset, 32);
  for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);

  const nonceView = new DataView(nonce16.buffer, nonce16.byteOffset, 16);
  for (let i = 0; i < 4; i++) state[12 + i] = nonceView.getUint32(i * 4, true);

  for (let i = 0; i < 10; i++) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);
    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, state[0], true);
  outView.setUint32(4, state[1], true);
  outView.setUint32(8, state[2], true);
  outView.setUint32(12, state[3], true);
  outView.setUint32(16, state[12], true);
  outView.setUint32(20, state[13], true);
  outView.setUint32(24, state[14], true);
  outView.setUint32(28, state[15], true);
  return out;
}

function xchacha20(key, nonce24, data) {
  const subkey = hchacha20(key, nonce24.subarray(0, 16));
  const subnonce = new Uint8Array(12);
  subnonce.set(nonce24.subarray(16, 24), 4);

  const output = new Uint8Array(data.length);
  let counter = 0;
  for (let i = 0; i < data.length; i += 64) {
    const block = chacha20Block(subkey, counter++, subnonce);
    const len = Math.min(64, data.length - i);
    for (let j = 0; j < len; j++) {
      output[i + j] = data[i + j] ^ block[j];
    }
  }
  return output;
}

// Poly1305 MAC
function poly1305(key, message) {
  const r = new Uint32Array(5);
  const h = new Uint32Array(5);
  const pad = new Uint32Array(4);

  // Clamp r
  const t0 = key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24);
  const t1 = key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24);
  const t2 = key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24);
  const t3 = key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24);

  r[0] = t0 & 0x3ffffff;
  r[1] = ((t0 >>> 26) | (t1 << 6)) & 0x3ffff03;
  r[2] = ((t1 >>> 20) | (t2 << 12)) & 0x3ffc0ff;
  r[3] = ((t2 >>> 14) | (t3 << 18)) & 0x3f03fff;
  r[4] = (t3 >>> 8) & 0x00fffff;

  pad[0] = key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);
  pad[1] = key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
  pad[2] = key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
  pad[3] = key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);

  const blocks = Math.ceil(message.length / 16);
  for (let i = 0; i < blocks; i++) {
    const start = i * 16;
    const isLast = start + 16 > message.length;
    const blockLen = isLast ? message.length - start : 16;

    let n0 = 0, n1 = 0, n2 = 0, n3 = 0, n4 = 0;
    for (let j = 0; j < blockLen && j < 4; j++) n0 |= message[start + j] << (j * 8);
    for (let j = 4; j < blockLen && j < 8; j++) n1 |= message[start + j] << ((j - 4) * 8);
    for (let j = 8; j < blockLen && j < 12; j++) n2 |= message[start + j] << ((j - 8) * 8);
    for (let j = 12; j < blockLen && j < 16; j++) n3 |= message[start + j] << ((j - 12) * 8);

    const hibit = isLast ? (1 << ((blockLen % 4) * 8)) : (1 << 24);
    if (blockLen < 4) n0 |= hibit;
    else if (blockLen < 8) n1 |= hibit;
    else if (blockLen < 12) n2 |= hibit;
    else if (blockLen < 16) n3 |= hibit;
    else n4 = 1;

    h[0] += n0 & 0x3ffffff;
    h[1] += ((n0 >>> 26) | (n1 << 6)) & 0x3ffffff;
    h[2] += ((n1 >>> 20) | (n2 << 12)) & 0x3ffffff;
    h[3] += ((n2 >>> 14) | (n3 << 18)) & 0x3ffffff;
    h[4] += (n3 >>> 8) | (n4 << 24);

    let d0 = h[0] * r[0] + h[1] * (5 * r[4]) + h[2] * (5 * r[3]) + h[3] * (5 * r[2]) + h[4] * (5 * r[1]);
    let d1 = h[0] * r[1] + h[1] * r[0] + h[2] * (5 * r[4]) + h[3] * (5 * r[3]) + h[4] * (5 * r[2]);
    let d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * (5 * r[4]) + h[4] * (5 * r[3]);
    let d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * (5 * r[4]);
    let d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];

    let c = d0 >>> 26; h[0] = d0 & 0x3ffffff; d1 += c;
    c = d1 >>> 26; h[1] = d1 & 0x3ffffff; d2 += c;
    c = d2 >>> 26; h[2] = d2 & 0x3ffffff; d3 += c;
    c = d3 >>> 26; h[3] = d3 & 0x3ffffff; d4 += c;
    c = d4 >>> 26; h[4] = d4 & 0x3ffffff; h[0] += c * 5;
    c = h[0] >>> 26; h[0] &= 0x3ffffff; h[1] += c;
  }

  // Final reduction
  let c = h[1] >>> 26; h[1] &= 0x3ffffff; h[2] += c;
  c = h[2] >>> 26; h[2] &= 0x3ffffff; h[3] += c;
  c = h[3] >>> 26; h[3] &= 0x3ffffff; h[4] += c;
  c = h[4] >>> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
  c = h[0] >>> 26; h[0] &= 0x3ffffff; h[1] += c;

  const g0 = h[0] + 5; c = g0 >>> 26; const g1c = h[1] + c; c = g1c >>> 26;
  const g2c = h[2] + c; c = g2c >>> 26; const g3c = h[3] + c; c = g3c >>> 26;
  const g4c = h[4] + c - (1 << 26);
  const mask = (g4c >>> 31) - 1;
  h[0] = (h[0] & ~mask) | (g0 & 0x3ffffff & mask);
  h[1] = (h[1] & ~mask) | (g1c & 0x3ffffff & mask);
  h[2] = (h[2] & ~mask) | (g2c & 0x3ffffff & mask);
  h[3] = (h[3] & ~mask) | (g3c & 0x3ffffff & mask);
  h[4] = (h[4] & ~mask) | (g4c & mask);

  const f0 = (h[0] | (h[1] << 26)) + pad[0]; const f0c = f0 >>> 32;
  const f1 = (h[1] >>> 6) | (h[2] << 20) + pad[1] + f0c; const f1c = f1 >>> 32;
  const f2 = (h[2] >>> 12) | (h[3] << 14) + pad[2] + f1c; const f2c = f2 >>> 32;
  const f3 = (h[3] >>> 18) | (h[4] << 8) + pad[3] + f2c;

  const mac = new Uint8Array(16);
  const view = new DataView(mac.buffer);
  view.setUint32(0, f0 >>> 0, true);
  view.setUint32(4, f1 >>> 0, true);
  view.setUint32(8, f2 >>> 0, true);
  view.setUint32(12, f3 >>> 0, true);
  return mac;
}

// HKDF-SHA256 Extract: PRK = HMAC(salt, IKM)
async function hkdfExtract(salt, ikm) {
  const key = await crypto.subtle.importKey('raw', salt.length ? salt : new Uint8Array(32),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, ikm));
}

// HKDF-SHA256 Expand: OKM = HMAC(PRK, info || counter)
async function hkdfExpand(prk, info, length) {
  const prkKey = await crypto.subtle.importKey('raw', prk,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

  const output = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let offset = 0;
  for (let i = 1; offset < length; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev);
    input.set(info, prev.length);
    input[input.length - 1] = i;
    prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkKey, input));
    output.set(prev.subarray(0, Math.min(32, length - offset)), offset);
    offset += 32;
  }
  return output;
}

// HKDF-SHA256 (extract + expand)
async function hkdfSha256(ikm, salt, info, length) {
  const prk = await hkdfExtract(salt, ikm);
  return await hkdfExpand(prk, info, length);
}

// NIP-44 decrypt
async function nip44Decrypt(content, privateKey, publicKey) {
  const payload = base64Decode(content);

  if (payload[0] !== 2) {
    throw new Error('Unsupported NIP-44 version: ' + payload[0]);
  }

  // NIP-44 structure: version(1) + nonce(32) + ciphertext(variable) + mac(32)
  const nonce = payload.subarray(1, 33);
  const ciphertext = payload.subarray(33, payload.length - 32);
  const mac = payload.subarray(payload.length - 32);

  // Step 1: Get shared x-coordinate from ECDH
  const sharedX = await deriveSharedSecret(privateKey, publicKey);

  // Step 2: conversation_key = HKDF-extract(salt="nip44-v2", ikm=shared_x)
  const salt = utf8ToBytes('nip44-v2');
  const conversationKey = await hkdfExtract(salt, sharedX);

  // Step 3: Derive message keys using HKDF-expand
  // message_keys = HKDF-expand(prk=conversation_key, info=nonce, L=76)
  const messageKeys = await hkdfExpand(conversationKey, nonce, 76);
  const chachaKey = messageKeys.subarray(0, 32);
  const chachaNonce = messageKeys.subarray(32, 44);
  const hmacKey = messageKeys.subarray(44, 76);

  // Step 4: Verify MAC over nonce || ciphertext
  const hmacKeyObj = await crypto.subtle.importKey('raw', hmacKey,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const aad = new Uint8Array(nonce.length + ciphertext.length);
  aad.set(nonce);
  aad.set(ciphertext, nonce.length);
  const expectedMac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKeyObj, aad));

  // Constant-time compare
  let diff = 0;
  for (let i = 0; i < 32; i++) {
    diff |= mac[i] ^ expectedMac[i];
  }
  if (diff !== 0) {
    throw new Error('NIP-44 MAC verification failed');
  }

  // Step 5: Decrypt with ChaCha20
  const padded = chacha20Decrypt(chachaKey, chachaNonce, ciphertext);

  // Step 6: Remove padding (first 2 bytes are big-endian length)
  const msgLen = (padded[0] << 8) | padded[1];
  if (msgLen > padded.length - 2) {
    throw new Error('Invalid NIP-44 padding');
  }
  const plaintext = padded.subarray(2, 2 + msgLen);

  return bytesToUtf8(plaintext);
}

/**
 * NIP-44 padded-length per spec (calc_padded_len). Returns the length of the
 * plaintext+suffix region, EXCLUDING the 2-byte length prefix.
 */
function _nip44CalcPaddedLen(len) {
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

/**
 * NIP-44 v2 encryption
 */
async function nip44Encrypt(content, privateKey, publicKey) {
  const plaintext = utf8ToBytes(content);

  // Step 1: NIP-44 padded length = 2-byte length prefix + calc_padded_len(plaintext)
  const len = plaintext.length;
  if (len < 1 || len > 65535) throw new Error('Message too long for NIP-44');
  const paddedLen = 2 + _nip44CalcPaddedLen(len);

  // Step 2: Create padded message: 2-byte BE length + message + zeros
  const padded = new Uint8Array(paddedLen);
  padded[0] = (len >> 8) & 0xff;
  padded[1] = len & 0xff;
  padded.set(plaintext, 2);

  // Step 3: Generate random nonce (32 bytes)
  const nonce = crypto.getRandomValues(new Uint8Array(32));

  // Step 4: Derive conversation key and message keys
  const sharedX = await deriveSharedSecret(privateKey, publicKey);
  const salt = utf8ToBytes('nip44-v2');
  const conversationKey = await hkdfExtract(salt, sharedX);
  const messageKeys = await hkdfExpand(conversationKey, nonce, 76);
  const chachaKey = messageKeys.subarray(0, 32);
  const chachaNonce = messageKeys.subarray(32, 44);
  const hmacKey = messageKeys.subarray(44, 76);

  // Step 5: Encrypt with ChaCha20 (same function works for encrypt/decrypt)
  const ciphertext = chacha20Decrypt(chachaKey, chachaNonce, padded);

  // Step 6: Calculate MAC over nonce || ciphertext
  const hmacKeyObj = await crypto.subtle.importKey('raw', hmacKey,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const aad = new Uint8Array(nonce.length + ciphertext.length);
  aad.set(nonce);
  aad.set(ciphertext, nonce.length);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKeyObj, aad));

  // Step 7: Assemble payload: version(1) + nonce(32) + ciphertext + mac(32)
  const payload = new Uint8Array(1 + 32 + ciphertext.length + 32);
  payload[0] = 2; // version
  payload.set(nonce, 1);
  payload.set(ciphertext, 33);
  payload.set(mac, 33 + ciphertext.length);

  return base64Encode(payload);
}

function chacha20Decrypt(key, nonce12, data) {
  const output = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 64) {
    const counter = Math.floor(i / 64);
    const block = chacha20Block(key, counter, nonce12);
    const len = Math.min(64, data.length - i);
    for (let j = 0; j < len; j++) {
      output[i + j] = data[i + j] ^ block[j];
    }
  }
  return output;
}

// Auto-detect and decrypt (NIP-04 or NIP-44)
async function nip04or44Decrypt(content, privateKey, publicKey) {
  // NIP-04 has ?iv= separator
  if (content.includes('?iv=')) {
    return await nip04Decrypt(content, privateKey, publicKey);
  }
  // Otherwise try NIP-44
  return await nip44Decrypt(content, privateKey, publicKey);
}

// ============================================================================
// NOSTR EVENT HANDLING
// ============================================================================

async function getEventHash(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  const hash = await sha256(utf8ToBytes(serialized));
  return bytesToHex(hash);
}

async function signEvent(event, privateKey) {
  // Derive pubkey from the signing key so id/pubkey/sig are always consistent,
  // even when the caller omits event.pubkey (was: produced a null-pubkey event).
  const pubkey = bytesToHex(getPublicKey(privateKey));
  const withPubkey = { ...event, pubkey };
  const id = await getEventHash(withPubkey);
  const sig = await schnorrSign(hexToBytes(id), privateKey);
  return {
    ...withPubkey,
    id,
    sig: bytesToHex(sig)
  };
}

async function verifyEvent(event) {
  const hash = await getEventHash(event);
  if (hash !== event.id) return false;
  return schnorrVerify(
    hexToBytes(event.sig),
    hexToBytes(event.id),
    hexToBytes(event.pubkey)
  );
}

function createEvent(kind, content, tags = []) {
  return {
    kind,
    content,
    tags,
    created_at: Math.floor(Date.now() / 1000)
  };
}

// ============================================================================
// NIP-98 HTTP AUTH
// ============================================================================

/**
 * Create an unsigned NIP-98 HTTP Auth event (kind 27235).
 *
 * Returns a bare event with `u` and `method` tags. Does NOT include a
 * `payload` tag — use signNip98() for the complete flow that handles
 * body hashing automatically.
 *
 * @param {string} url     - Absolute URL the request targets
 * @param {string} method  - HTTP method (GET, POST, etc.)
 * @returns {object} Unsigned Nostr event (kind 27235)
 */
function createNip98Event(url, method) {
  return {
    kind: 27235,
    content: '',
    tags: [
      ['u', url],
      ['method', method.toUpperCase()]
    ],
    created_at: Math.floor(Date.now() / 1000)
  };
}

/**
 * Sign a NIP-98 event and return the base64-encoded Authorization header value.
 *
 * Usage:
 *   const { header } = await signNip98(auth, 'https://example.com/api', 'POST', '{"x":1}');
 *   fetch(url, { headers: { Authorization: header } });
 *
 * @param {NostrAuth|BaseSigner} signer - NostrAuth instance or any signer with sign()
 * @param {string} url       - Absolute URL the request targets
 * @param {string} method    - HTTP method
 * @param {string} [body]    - Request body string (for payload tag)
 * @param {object} [options]
 * @param {number} [options.timeout=10000] - Sign timeout in ms; protects against NIP-07 hangs on HTTP
 * @returns {Promise<{header: string, event: object}>} The Authorization header and signed event
 */
async function signNip98(signer, url, method, body, options = {}) {
  const { timeout = 60000 } = options;
  const tags = [
    ['u', url],
    ['method', method.toUpperCase()]
  ];

  // Add payload hash for mutating methods when body is present
  if (body != null && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
    const bodyBytes = utf8ToBytes(body);
    const hash = await sha256(bodyBytes);
    tags.push(['payload', bytesToHex(hash)]);
  }

  const event = {
    kind: 27235,
    content: '',
    tags,
    created_at: Math.floor(Date.now() / 1000)
  };

  // Race the sign against a timeout — NIP-07 extensions (Alby) silently hang on HTTP
  const signed = await Promise.race([
    signer.sign(event),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(
        'Signing timed out after ' + (timeout / 1000) + 's. ' +
        (url.startsWith('http:') ? 'NIP-07 extensions (Alby) often require HTTPS to sign.' : 'The signer did not respond.')
      )), timeout)
    )
  ]);
  const json = JSON.stringify(signed);
  const header = 'Nostr ' + btoa(json);
  return { header, event: signed };
}

// ============================================================================
// RELAY POOL
// ============================================================================

/**
 * Close a relay socket without console noise. Closing a socket that is still
 * CONNECTING makes the browser log a red "WebSocket is closed before the
 * connection is established" error. Instead, detach handlers and close cleanly
 * once it opens (a genuine dial failure still surfaces on its own).
 * @private
 */
function _safeCloseWs(ws) {
  if (!ws) return;
  try {
    if (ws.readyState === WebSocket.CONNECTING) {
      ws.onerror = null;
      ws.onmessage = null;
      ws.onclose = null;
      ws.onopen = () => { try { ws.close(); } catch (e) {} };
    } else {
      ws.close();
    }
  } catch (e) {}
}

/**
 * RelayPool — manages WebSocket connections to Nostr relays.
 *
 * Connection model (NIP-01): a client SHOULD hold a SINGLE WebSocket per relay
 * and reuse it for all subscriptions/publishes. `connect(url)` returns the
 * existing live socket when one is present rather than dialing again.
 *
 * Failure handling (negative cache / backoff): NIP-46 signing under MNA1 signs
 * one event PER request, and every publish/subscribe calls `tryConnect`. If a
 * relay is unreachable, re-dialing it on each request produces a storm of
 * `WebSocket … failed` errors — each a fresh socket that waits up to
 * `connectionTimeout`. To honor the "one persistent connection" intent, a relay
 * whose *dial* fails is recorded in `failedRelays` with a timestamp; subsequent
 * `connect` calls fast-fail (throw an error tagged `{ cooldown: true }`, so
 * `tryConnect` returns null) for `retryBackoff` ms instead of opening a new
 * socket. A successful open clears the entry. A clean close of a
 * previously-open socket does NOT record a failure — transient drops are free
 * to reconnect immediately.
 *
 * @param {object} [options]
 * @param {number} [options.connectionTimeout=20000] ms before a pending dial is abandoned
 * @param {number} [options.pingInterval=30000]      ms between keepalive REQ pings
 * @param {number} [options.retryBackoff=30000]      ms to skip re-dialing a relay after a failed dial
 */
class RelayPool {
  constructor(options = {}) {
    this.relays = new Map(); // url -> { ws, status, queue, pingInterval }
    this.subscriptions = new Map(); // subId -> { filters, relays, callbacks }
    this.connectionTimeout = options.connectionTimeout || 20000; // 20 seconds
    this.pingInterval = options.pingInterval || 30000; // 30 seconds keepalive
    // ms to skip re-dialing a relay after a failed dial (negative cache).
    this.retryBackoff = options.retryBackoff || 30000;
    this.failedRelays = new Map(); // url -> failedAt(ms) of last failed dial
  }

  async connect(url) {
    // Negative cache (NIP-01: one socket per relay, reuse it). Skip a relay
    // whose dial failed within the last `retryBackoff` ms instead of opening a
    // brand-new socket on every request — see class doc.
    const failedAt = this.failedRelays.get(url);
    if (failedAt !== undefined) {
      if (Date.now() - failedAt < this.retryBackoff) {
        const err = new Error(`Relay cooling down: ${url}`);
        err.cooldown = true;
        throw err;
      }
      this.failedRelays.delete(url);
    }
    if (this.relays.has(url)) {
      const relay = this.relays.get(url);
      if (relay.status === 'connected') return relay;
      if (relay.status === 'connecting') {
        return new Promise((resolve, reject) => {
          relay.queue.push({ resolve, reject });
        });
      }
      // If failed, try again
      if (relay.status === 'failed') {
        this.relays.delete(url);
      }
    }

    const relay = {
      url,
      ws: null,
      status: 'connecting',
      queue: [],
      messageHandlers: new Set(),
      pingTimer: null
    };
    this.relays.set(url, relay);

    return new Promise((resolve, reject) => {
      let opened = false;
      try {
        relay.ws = new WebSocket(url);
      } catch (err) {
        relay.status = 'failed';
        this.relays.delete(url);
        this.failedRelays.set(url, Date.now());
        reject(err);
        return;
      }

      const timeout = setTimeout(() => {
        relay.status = 'failed';
        _safeCloseWs(relay.ws);
        this.relays.delete(url);
        this.failedRelays.set(url, Date.now());
        reject(new Error(`Connection timeout: ${url}`));
      }, this.connectionTimeout);

      relay.ws.onopen = () => {
        clearTimeout(timeout);
        relay.status = 'connected';
        opened = true;
        this.failedRelays.delete(url);

        // Replay active subscriptions targeting this relay (NIP-01 REQs die
        // with the socket; without this a dropped relay silently loses every
        // standing subscription — e.g. a NIP-46 signer's response listener —
        // until the caller re-subscribes). Dials stay demand-driven: this only
        // re-attaches subs when something else re-opened the socket.
        this.subscriptions.forEach(sub => {
          if (sub.urls.includes(url)) this._attachSubscription(relay, sub);
        });

        // Start keepalive ping
        relay.pingTimer = setInterval(() => {
          if (relay.ws && relay.ws.readyState === WebSocket.OPEN) {
            try {
              // Keepalive: a limit:0 REQ answers with EOSE only, so the
              // round-trip traffic itself is the ping. CLOSE it immediately —
              // otherwise server-side subscriptions accumulate one per
              // interval and relays with subscription caps drop the socket.
              const pingId = 'ping_' + Date.now();
              relay.ws.send(JSON.stringify(['REQ', pingId, { limit: 0 }]));
              relay.ws.send(JSON.stringify(['CLOSE', pingId]));
            } catch (e) {}
          }
        }, this.pingInterval);

        resolve(relay);
        relay.queue.forEach(q => q.resolve(relay));
        relay.queue = [];
      };

      relay.ws.onerror = (err) => {
        clearTimeout(timeout);
        if (relay.pingTimer) clearInterval(relay.pingTimer);
        relay.status = 'failed';
        this.relays.delete(url);
        if (!opened) this.failedRelays.set(url, Date.now());
        reject(new Error(`Connection failed: ${url}`));
        relay.queue.forEach(q => q.reject(err));
        relay.queue = [];
      };

      relay.ws.onclose = () => {
        if (relay.pingTimer) clearInterval(relay.pingTimer);
        relay.status = 'disconnected';
        this.relays.delete(url);
      };

      relay.ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          relay.messageHandlers.forEach(handler => handler(data));
        } catch (e) {
          console.error('Failed to parse relay message:', e);
        }
      };
    });
  }

  /**
   * Try to connect to a relay, return null on failure instead of throwing
   */
  async tryConnect(url) {
    try {
      return await this.connect(url);
    } catch (e) {
      if (!e.cooldown) console.debug(`Relay ${url} unavailable:`, e.message);
      return null;
    }
  }

  async publish(urls, event) {
    const results = await Promise.allSettled(
      urls.map(async url => {
        const relay = await this.tryConnect(url);
        if (!relay) {
          throw new Error(`Failed to connect to ${url}`);
        }

        return new Promise((resolve, reject) => {
          const handler = (data) => {
            if (data[0] === 'OK' && data[1] === event.id) {
              relay.messageHandlers.delete(handler);
              if (data[2]) resolve({ url, ok: true });
              else reject(new Error(data[3] || 'Rejected'));
            }
          };
          relay.messageHandlers.add(handler);

          try {
            relay.ws.send(JSON.stringify(['EVENT', event]));
          } catch (e) {
            relay.messageHandlers.delete(handler);
            reject(new Error(`Send failed: ${url}`));
            return;
          }

          setTimeout(() => {
            relay.messageHandlers.delete(handler);
            // Resolve anyway - we sent it, just didn't get confirmation
            resolve({ url, ok: true, unconfirmed: true });
          }, 2000);
        });
      })
    );
    return results;
  }

  /**
   * Attach a subscription's message handler to a relay and (re)send its REQ.
   * Idempotent per socket: a stale handler left over from a previous socket
   * (or an earlier call for the same socket) is replaced first, so the replay
   * on reconnect never double-delivers events. Used by `subscribe()` for the
   * initial attach and by `connect()`'s onopen to replay standing
   * subscriptions after a socket drop + re-dial.
   * @private
   */
  _attachSubscription(relay, sub) {
    const url = relay.url;
    const prev = sub.handlers.get(url);
    if (prev) relay.messageHandlers.delete(prev);
    const handler = (data) => {
      if (data[0] === 'EVENT' && data[1] === sub.id) {
        sub.callbacks.onEvent?.(data[2], url);
      } else if (data[0] === 'EOSE' && data[1] === sub.id) {
        sub.callbacks.onEose?.(url);
      }
    };
    relay.messageHandlers.add(handler);
    sub.handlers.set(url, handler);
    try {
      relay.ws.send(JSON.stringify(['REQ', sub.id, ...sub.filters]));
    } catch (e) {
      console.warn(`Failed to send to ${url}:`, e);
    }
  }

  subscribe(urls, filters, callbacks) {
    const subId = 'sub_' + Math.random().toString(36).slice(2);

    const sub = {
      id: subId,
      filters,
      urls,
      callbacks,
      handlers: new Map(),
      connectedCount: 0,
      failedCount: 0,
      close: () => {
        sub.handlers.forEach((handler, url) => {
          const relay = this.relays.get(url);
          if (relay) {
            relay.messageHandlers.delete(handler);
            if (relay.ws && relay.ws.readyState === WebSocket.OPEN) {
              try {
                relay.ws.send(JSON.stringify(['CLOSE', subId]));
              } catch (e) {}
            }
          }
        });
        this.subscriptions.delete(subId);
      }
    };

    this.subscriptions.set(subId, sub);

    // Connect to relays in parallel, don't fail if some don't connect
    urls.forEach(async url => {
      const relay = await this.tryConnect(url);

      if (!relay) {
        sub.failedCount++;
        // Only call onError if ALL relays failed
        if (sub.failedCount === urls.length && sub.connectedCount === 0) {
          callbacks.onError?.(new Error('All relays failed to connect'), url);
        }
        return;
      }

      sub.connectedCount++;
      this._attachSubscription(relay, sub);
    });

    return sub;
  }

  close() {
    this.subscriptions.forEach(sub => sub.close());
    this.relays.forEach(relay => {
      if (relay.pingTimer) clearInterval(relay.pingTimer);
      _safeCloseWs(relay.ws);
    });
    this.relays.clear();
    this.subscriptions.clear();
    this.failedRelays.clear();
  }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/**
 * Base error for all Nostr-related errors
 */
class NostrError extends Error {
  constructor(message, code = 'NOSTR_ERROR') {
    super(message);
    this.name = 'NostrError';
    this.code = code;
  }
}

/**
 * Timeout waiting for response
 */
class TimeoutError extends NostrError {
  constructor(message = 'Operation timed out') {
    super(message, 'TIMEOUT');
    this.name = 'TimeoutError';
  }
}

/**
 * Remote signer rejected the request
 */
class SignerRejectedError extends NostrError {
  constructor(message = 'Signer rejected the request') {
    super(message, 'SIGNER_REJECTED');
    this.name = 'SignerRejectedError';
  }
}

/**
 * Connection to relay(s) failed
 */
class RelayError extends NostrError {
  constructor(message = 'Relay connection failed', relay = null) {
    super(message, 'RELAY_ERROR');
    this.name = 'RelayError';
    this.relay = relay;
  }
}

/**
 * Auth challenge required - signer wants user to authenticate via URL
 */
class AuthChallengeError extends NostrError {
  constructor(authUrl, requestId) {
    super('Authentication required', 'AUTH_CHALLENGE');
    this.name = 'AuthChallengeError';
    this.authUrl = authUrl;
    this.requestId = requestId;
  }
}

/**
 * Invalid secret in connection response (potential spoofing)
 */
class InvalidSecretError extends NostrError {
  constructor(message = 'Invalid connection secret') {
    super(message, 'INVALID_SECRET');
    this.name = 'InvalidSecretError';
  }
}

// ============================================================================
// SIGNERS
// ============================================================================

/**
 * Base signer interface
 */
class BaseSigner {
  async getPublicKey() { throw new Error('Not implemented'); }
  async sign(event) { throw new Error('Not implemented'); }
  async nip04Encrypt(content, pubkey) { throw new Error('Not implemented'); }
  async nip04Decrypt(content, pubkey) { throw new Error('Not implemented'); }
  getType() { return 'base'; }
}

/**
 * NIP-07 Browser Extension Signer (Alby, nos2x, etc.)
 */
class Nip07Signer extends BaseSigner {
  constructor() {
    super();
    if (!window.nostr) {
      throw new Error('No browser extension detected. Install a Nostr signer extension (nos2x, Alby, or Flamingo) and reload.');
    }
  }

  getType() { return 'nip07'; }

  async getPublicKey() {
    return await window.nostr.getPublicKey();
  }

  async sign(event) {
    return await window.nostr.signEvent(event);
  }

  async nip04Encrypt(content, pubkey) {
    if (!window.nostr.nip04) throw new Error('Your browser extension doesn\'t support encryption. Try updating it.');
    return await window.nostr.nip04.encrypt(pubkey, content);
  }

  async nip04Decrypt(content, pubkey) {
    if (!window.nostr.nip04) throw new Error('Your browser extension doesn\'t support encryption. Try updating it.');
    return await window.nostr.nip04.decrypt(pubkey, content);
  }
}

/**
 * Local Secret Key Signer (for development/testing)
 */
class LocalSigner extends BaseSigner {
  constructor(privateKeyHex) {
    super();
    this.privateKey = hexToBytes(privateKeyHex);
    this.publicKey = getPublicKey(this.privateKey);
  }

  static generate() {
    const sk = generatePrivateKey();
    return new LocalSigner(bytesToHex(sk));
  }

  static fromNsec(nsec) {
    const hex = decodeNsec(nsec);
    return new LocalSigner(hex);
  }

  getType() { return 'local'; }

  async getPublicKey() {
    return bytesToHex(this.publicKey);
  }

  async sign(event) {
    const pubkey = bytesToHex(this.publicKey);
    const eventWithPubkey = { ...event, pubkey };
    return await signEvent(eventWithPubkey, this.privateKey);
  }

  async nip04Encrypt(content, pubkey) {
    return await nip04Encrypt(content, this.privateKey, hexToBytes(pubkey));
  }

  async nip04Decrypt(content, pubkey) {
    return await nip04Decrypt(content, this.privateKey, hexToBytes(pubkey));
  }

  getNsec() {
    return encodeNsec(bytesToHex(this.privateKey));
  }

  getNpub() {
    return encodeNpub(bytesToHex(this.publicKey));
  }
}

/**
 * NIP-46 Remote Signer (Nostr Connect)
 * Supports both flows:
 * - nostrconnect:// (client-initiated, client displays QR)
 * - bunker:// (signer-initiated, user pastes URL)
 */
// Default permissions requested during NIP-46 connect handshake.
// Covers all operations a general-purpose signing client might need.
const NIP46_DEFAULT_PERMS =
  'sign_event,sign_event:27235,get_public_key,nip04_encrypt,nip04_decrypt,nip44_encrypt,nip44_decrypt';

class Nip46Signer extends BaseSigner {
  constructor({ relays, timeout = 60000, localPrivateKey = null, remotePubkey = null }) {
    super();
    this.relays = relays;
    this.timeout = timeout;
    this.pool = new RelayPool();

    // Local ephemeral keypair for communication (or restore from saved)
    if (localPrivateKey) {
      this.localPrivateKey = localPrivateKey;
      this.localPublicKey = getPublicKey(localPrivateKey);
    } else {
      this.localPrivateKey = generatePrivateKey();
      this.localPublicKey = getPublicKey(this.localPrivateKey);
    }

    this.remotePubkey = remotePubkey;
    this.bunkerSecret = null; // For bunker:// flow
    this.connectSecret = null; // For nostrconnect:// flow verification
    this.connected = false;
    this.pendingRequests = new Map();
    this.subscription = null;
    this.onAuthUrl = null; // Callback: (url) => {} — called when signer requires user approval
  }

  /**
   * Create a signer from saved session data
   */
  static restore(savedData, options = {}) {
    const signer = new Nip46Signer({
      relays: savedData.relays,
      timeout: options.timeout || 60000,
      localPrivateKey: hexToBytes(savedData.localPrivateKey),
      remotePubkey: savedData.remotePubkey
    });
    return signer;
  }

  /**
   * Reconnect a restored session
   */
  async reconnect(timeoutMs) {
    if (!this.remotePubkey) {
      throw new Error('Saved session is incomplete. Please connect again.');
    }

    // Don't block startup on the relay handshake — the pubkey is already known
    // from the saved session. _startListening() subscribes and connects to the
    // relays lazily in the background; the signer proves itself on first sign.
    this._startListening();

    // Mark as connected optimistically. Web-based signers (nsec.app) run
    // in service workers that may take seconds to wake up via push notification.
    // Verifying with ping/get_public_key here causes false failures.
    // The signer proves it's alive when the user actually signs something.
    this.connected = true;
    return this.remotePubkey;
  }

  getType() { return 'nip46'; }

  /**
   * Parse a nostrconnect:// or bunker:// URI
   * @returns {{ type: 'nostrconnect'|'bunker', pubkey: string, relays: string[], secret?: string, metadata?: object }}
   */
  static parseURI(uri) {
    const url = new URL(uri);
    const scheme = url.protocol.replace(':', '');

    if (scheme !== 'nostrconnect' && scheme !== 'bunker') {
      throw new Error('Invalid URI scheme. Expected nostrconnect:// or bunker://');
    }

    // The pubkey is the host part (after ://)
    const pubkey = url.hostname || url.pathname.replace('//', '');

    // Validate pubkey (should be 64 hex chars)
    if (!/^[a-f0-9]{64}$/i.test(pubkey)) {
      throw new Error('Invalid pubkey in URI');
    }

    // Parse params
    const params = url.searchParams;
    const relays = [];

    // Handle both 'relay' and 'relay[]' params
    params.forEach((value, key) => {
      if (key === 'relay' || key === 'relay[]') {
        relays.push(value);
      }
    });

    // Also check for relays in the hash (some implementations use this)
    if (url.hash) {
      const hashParams = new URLSearchParams(url.hash.slice(1));
      hashParams.forEach((value, key) => {
        if (key === 'relay') relays.push(value);
      });
    }

    const result = {
      type: scheme,
      pubkey: pubkey.toLowerCase(),
      relays,
      secret: params.get('secret') || undefined,
      metadata: {
        name: params.get('name') || undefined,
        url: params.get('url') || undefined,
        description: params.get('description') || undefined
      }
    };

    return result;
  }

  /**
   * Create a signer from a bunker:// URI
   */
  static fromBunkerURI(uri, options = {}) {
    const parsed = Nip46Signer.parseURI(uri);

    if (parsed.type !== 'bunker') {
      throw new Error('Expected bunker:// URI');
    }

    if (parsed.relays.length === 0) {
      throw new Error('No relay specified in bunker URI');
    }

    const signer = new Nip46Signer({
      relays: parsed.relays,
      timeout: options.timeout || 60000,
      localPrivateKey: options.localPrivateKey || null
    });

    signer.remotePubkey = parsed.pubkey;
    signer.bunkerSecret = parsed.secret;
    if (options.perms !== undefined) signer.requestedPerms = options.perms;

    return signer;
  }

  /**
   * Generate nostrconnect:// URI for QR code display
   * (Client-initiated flow: signer scans this)
   */
  getConnectURI(metadata = {}) {
    const localPubkeyHex = bytesToHex(this.localPublicKey);
    const params = new URLSearchParams();

    // Add all relays to give signer options
    for (const relay of this.relays) {
      params.append('relay', relay);
    }

    // Generate random secret for connection verification (NIP-46 required)
    this.connectSecret = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    params.set('secret', this.connectSecret);

    if (metadata.name) params.set('name', metadata.name);
    if (metadata.url) params.set('url', metadata.url);
    if (metadata.description) params.set('description', metadata.description);
    // Always request the standard perms so the signer grants sign_event (incl.
    // kind 27235 = NIP-98 / MNA1 auth) up front. Without this the nostrconnect://
    // URI carries no perms and the signer establishes a no-signing session, so
    // every later sign returns "no permission". Callers may override via metadata.perms.
    params.set('perms', metadata.perms || NIP46_DEFAULT_PERMS);

    return `nostrconnect://${localPubkeyHex}?${params.toString()}`;
  }

  /**
   * Connect to a bunker (signer-initiated flow)
   * Call this after creating signer from bunker:// URI
   */
  async connectToBunker(timeoutMs) {
    if (!this.remotePubkey) {
      throw new Error('No remote pubkey set. Use fromBunkerURI() first.');
    }

    const timeout = timeoutMs || this.timeout;
    const localPubkeyHex = bytesToHex(this.localPublicKey);

    this._startListening();

    // NIP-46 connect: [remote-signer-pubkey, secret?, perms?]
    const connectParams = [this.remotePubkey];
    if (this.bunkerSecret) connectParams.push(this.bunkerSecret);
    connectParams.push(this.requestedPerms ?? NIP46_DEFAULT_PERMS);


    try {
      const result = await this._rpc('connect', connectParams, timeout);

      // NIP-46: connect result is "ack" OR the secret we sent — accept (and thereby
      // validate) an echoed secret, not just "ack".
      if (result === 'ack' || result === true || result === 'true' ||
          (this.bunkerSecret && result === this.bunkerSecret)) {
        this.connected = true;
        return this.remotePubkey;
      }
      throw new SignerRejectedError('Bunker rejected connection');

    } catch (e) {
      // Some signers (e.g. Amber) return 'already connected' when the same
      // ephemeral key reconnects — treat as success.
      if (e.message && e.message.toLowerCase().includes('already connected')) {
        this.connected = true;
        return this.remotePubkey;
      }
      this.disconnect();
      throw e;
    }
  }

  async waitForConnection(timeoutMs) {
    const timeout = timeoutMs || this.timeout;
    const localPubkeyHex = bytesToHex(this.localPublicKey);

    return new Promise((resolve, reject) => {
      let resolved = false;

      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        if (this.subscription) this.subscription.close();
        reject(new TimeoutError('No response from signer. Try again, or use a different connection method.'));
      }, timeout);

      this.subscription = this.pool.subscribe(
        this.relays,
        [{ kinds: [24133], '#p': [localPubkeyHex] }],
        {
          onEvent: async (event) => {
            if (resolved) return;

            try {
              const decrypted = await nip04or44Decrypt(
                event.content,
                this.localPrivateKey,
                hexToBytes(event.pubkey)
              );
              const msg = JSON.parse(decrypted);

              // Handle connect request from signer (nostrconnect:// flow)
              // The signer sends back a response with the secret we provided
              if (msg.method === 'connect' && msg.id) {
                if (resolved) return;

                // Validate secret (NIP-46): when we issued a secret the signer MUST
                // echo it. Reject connect requests that omit or mismatch it —
                // accepting them lets any relay that sees our local pubkey spoof
                // the signer and MITM signing.
                if (this.connectSecret) {
                  const returnedSecret = msg.params && msg.params[1]; // [pubkey, secret?, perms?]
                  if (returnedSecret !== this.connectSecret) {
                    return;
                  }
                }

                this.remotePubkey = event.pubkey;
                await this._sendResponse(msg.id, 'ack');

                resolved = true;
                this.connected = true;
                clearTimeout(timer);
                this._startListening(); // Resubscribe with RPC handler
                resolve(this.remotePubkey);
                return;
              }

              // Handle ack/secret result (for connect responses)
              if (msg.result) {
                if (resolved) return;

                // Validate secret (NIP-46): the result MUST equal the secret we
                // sent. Do NOT accept 'ack' when a secret was issued — that escape
                // hatch lets any relay forge acceptance and hijack the session.
                if (this.connectSecret && msg.result !== this.connectSecret) {
                  return;
                }

                resolved = true;
                this.remotePubkey = event.pubkey;
                this.connected = true;
                clearTimeout(timer);
                this._startListening();
                resolve(this.remotePubkey);
                return;
              }

              // Handle pending RPC responses
              if (msg.id && this.pendingRequests.has(msg.id)) {
                const { resolve: res, reject: rej } = this.pendingRequests.get(msg.id);
                this.pendingRequests.delete(msg.id);
                if (msg.error) rej(new Error(msg.error));
                else res(msg.result);
              }
            } catch (e) {
              // Ignore decryption/parse errors
            }
          },
          onEose: () => {},
          onError: (err, relay) => {
            if (resolved) return;
            resolved = true;
            clearTimeout(timer);
            if (this.subscription) this.subscription.close();
            reject(new RelayError('Failed to connect to relay', relay));
          }
        }
      );
    });
  }

  /**
   * Request relay switch from remote signer (NIP-46 spec compliance)
   * Call after connection established to let signer specify preferred relays
   */
  async switchRelays(timeoutMs) {
    if (!this.connected) return null;

    try {
      const result = await this._rpc('switch_relays', [], timeoutMs || 10000);
      if (result && Array.isArray(result) && result.length > 0) {
        // Update our relay list
        this.relays = result;
        // Reconnect subscription to new relays
        this._startListening();
        return result;
      }
      return null; // No change requested
    } catch (e) {
      // switch_relays is optional, don't fail if signer doesn't support it
      return null;
    }
  }

  /**
   * Check if connection is still alive by sending a ping
   */
  async ping(timeoutMs) {
    if (!this.connected) return false;

    try {
      const result = await this._rpc('ping', [], timeoutMs || 5000);
      return result === 'pong';
    } catch (e) {
      return false;
    }
  }

  /**
   * Send a response to a NIP-46 request
   */
  async _sendResponse(id, result) {
    if (!this.remotePubkey) {
      throw new Error('No remote pubkey to respond to');
    }

    const response = { id, result };
    const encrypted = await nip04Encrypt(
      JSON.stringify(response),
      this.localPrivateKey,
      hexToBytes(this.remotePubkey)
    );

    const event = await signEvent(
      {
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', this.remotePubkey]],
        content: encrypted,
        pubkey: bytesToHex(this.localPublicKey)
      },
      this.localPrivateKey
    );

    this.pool.publish(this.relays, event).catch(() => {});
  }

  _startListening() {
    if (this.subscription) this.subscription.close();

    const localPubkeyHex = bytesToHex(this.localPublicKey);

    this.subscription = this.pool.subscribe(
      this.relays,
      [{ kinds: [24133], '#p': [localPubkeyHex] }],
      {
        onEvent: async (event) => {
          if (event.pubkey !== this.remotePubkey) return;

          try {
            const decrypted = await nip04or44Decrypt(
              event.content,
              this.localPrivateKey,
              hexToBytes(event.pubkey)
            );
            const msg = JSON.parse(decrypted);

            if (msg.id && this.pendingRequests.has(msg.id)) {
              const { resolve, reject } = this.pendingRequests.get(msg.id);

              // Handle auth challenge (NIP-46 spec)
              // When result is "auth_url", error contains URL for user authentication
              if (msg.result === 'auth_url' && msg.error) {
                // Keep the pending request alive and restart its timeout — the user
                // must approve out-of-app, which routinely exceeds the base timeout;
                // otherwise the genuine post-approval response arrives after we gave
                // up and is silently dropped.
                const pending = this.pendingRequests.get(msg.id);
                if (pending && pending.bumpTimeout) pending.bumpTimeout();
                if (this.onAuthUrl) {
                  this.onAuthUrl(msg.error);
                } else {
                  console.warn('NIP-46 auth_url received but no onAuthUrl handler:', msg.error);
                }
                return;
              }

              this.pendingRequests.delete(msg.id);

              if (msg.error) {
                // Check for rejection vs other errors
                if (msg.error.toLowerCase().includes('reject') ||
                    msg.error.toLowerCase().includes('denied') ||
                    msg.error.toLowerCase().includes('refused')) {
                  reject(new SignerRejectedError(msg.error));
                } else {
                  reject(new NostrError(msg.error, 'SIGNER_ERROR'));
                }
              } else {
                resolve(msg.result);
              }
            }
          } catch (e) {
            // Ignore decryption errors
          }
        },
        onError: (err) => {
          // Log but don't fail - we might still have other relays
          console.warn('NIP-46 relay error:', err.message);
        }
      }
    );
  }

  async _rpc(method, params = [], timeoutMs) {
    // Allow 'connect' method before fully connected (for bunker:// flow)
    if (method !== 'connect' && (!this.connected || !this.remotePubkey)) {
      throw new NostrError('Not connected to remote signer', 'NOT_CONNECTED');
    }
    if (!this.remotePubkey) {
      throw new NostrError('No remote pubkey set', 'NO_REMOTE_PUBKEY');
    }

    const timeout = timeoutMs || this.timeout;
    const id = crypto.randomUUID();

    // Create promise and register pending request BEFORE publishing
    // to avoid race condition where response arrives before we're ready
    const responsePromise = new Promise((resolve, reject) => {
      const pending = {};
      const arm = () => setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new TimeoutError(`Signer did not respond to ${method}. It may be offline or unavailable.`));
      }, timeout);
      pending.timer = arm();
      pending.bumpTimeout = () => { clearTimeout(pending.timer); pending.timer = arm(); };
      pending.resolve = (result) => { clearTimeout(pending.timer); resolve(result); };
      pending.reject = (err) => { clearTimeout(pending.timer); reject(err); };
      this.pendingRequests.set(id, pending);
    });

    // NIP-46 RPC uses NIP-04 encryption (ecosystem standard as of early 2026)
    const request = { id, method, params };
    const encrypted = await nip04Encrypt(
      JSON.stringify(request),
      this.localPrivateKey,
      hexToBytes(this.remotePubkey)
    );

    const event = await signEvent(
      {
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', this.remotePubkey]],
        content: encrypted,
        pubkey: bytesToHex(this.localPublicKey)
      },
      this.localPrivateKey
    );

    // Fire and forget — response comes via subscription, not publish confirmation
    this.pool.publish(this.relays, event).catch(() => {});

    return responsePromise;
  }

  async getPublicKey() {
    return await this._rpc('get_public_key');
  }

  async sign(event) {
    // NIP-46 spec: params are [JSON.stringify(event)], result is JSON string of signed event
    const result = await this._rpc('sign_event', [JSON.stringify(event)]);
    if (typeof result === 'string') {
      try {
        const parsed = JSON.parse(result);
        if (parsed && parsed.sig) return parsed;
      } catch (_) {
        // Not JSON — treat as raw signature
        return { ...event, sig: result };
      }
    }
    if (typeof result === 'object' && result.sig) {
      return result;
    }
    return { ...event, sig: result };
  }

  async nip04Encrypt(content, pubkey) {
    return await this._rpc('nip04_encrypt', [pubkey, content]);
  }

  async nip04Decrypt(content, pubkey) {
    return await this._rpc('nip04_decrypt', [pubkey, content]);
  }

  disconnect() {
    try {
      if (this.subscription) {
        this.subscription.close();
        this.subscription = null;
      }
      this.pool.close();
    } catch (_) {}
    this.connected = false;
    this.remotePubkey = null;
    this.pendingRequests.forEach((p) => {
      try { p.reject(new NostrError('Disconnected from remote signer', 'NOT_CONNECTED')); } catch (_) {}
    });
    this.pendingRequests.clear();
  }
}

// ============================================================================
// AUTH MANAGER
// ============================================================================

/**
 * Main authentication manager
 * Handles multiple accounts, signer detection, and session persistence
 */
class NostrAuth {
  constructor(options = {}) {
    this.relays = options.relays || ['wss://relay.nsec.app', 'wss://relay.damus.io', 'wss://nos.lol'];
    this.timeout = options.timeout || 60000;
    this.allowLocalDev = options.allowLocalDev || false;
    this.allowGuestMode = options.allowGuestMode || false;
    this.storageKey = options.storageKey || 'nostr_auth';
    this.onAccountChange = options.onAccountChange || null;

    this.accounts = new Map(); // pubkey -> { signer, type, metadata }
    this.activePubkey = null;

    this._loadSession();
  }

  // ---------- Detection ----------

  hasNip07() {
    return typeof window !== 'undefined' && !!window.nostr;
  }

  // ---------- Connection Methods ----------

  /**
   * Try to connect via NIP-07 extension
   */
  async connectExtension() {
    if (!this.hasNip07()) {
      throw new Error('No browser extension detected. Install a Nostr signer extension (nos2x, Alby, or Flamingo) and reload.');
    }

    const signer = new Nip07Signer();
    const pubkey = await signer.getPublicKey();

    this._addAccount(pubkey, signer, 'nip07');
    this._setActive(pubkey);

    return pubkey;
  }

  /**
   * Start NIP-46 connection flow
   * Returns URI for QR code, call finalizeNip46() after user scans
   */
  createNip46Session(metadata = {}) {
    const signer = new Nip46Signer({
      relays: this.relays,
      timeout: this.timeout
    });

    const uri = signer.getConnectURI(metadata);

    return { signer, uri };
  }

  /**
   * Wait for NIP-46 connection to complete (nostrconnect:// flow)
   * @param {Nip46Signer} signer - The signer instance
   * @param {number} timeoutMs - Connection timeout
   * @param {function} onProgress - Progress callback (stage, message)
   */
  async finalizeNip46(signer, timeoutMs, onProgress = () => {}) {
    onProgress('connecting', 'Waiting for signer to connect...');
    const remotePubkey = await signer.waitForConnection(timeoutMs);

    onProgress('connected', 'Signer connected! Getting your identity...');

    const pubkey = await signer.getPublicKey();

    onProgress('complete', 'Login successful!');
    this._addAccount(pubkey, signer, 'nip46', { remotePubkey });
    this._setActive(pubkey);

    return pubkey;
  }

  /**
   * Connect using a bunker:// URI (signer-initiated flow)
   * @param {string} bunkerUri - The bunker:// URI from the signer
   * @param {number} timeoutMs - Connection timeout
   */
  async connectBunker(bunkerUri, timeoutMs, { onAuthUrl, localPrivateKey, perms } = {}) {
    const parsed = Nip46Signer.parseURI(bunkerUri);

    if (parsed.type !== 'bunker') {
      throw new Error('Expected bunker:// URI. For nostrconnect://, use createNip46Session()');
    }

    let activeSigner = null;

    const attempt = async (lk) => {
      const signer = Nip46Signer.fromBunkerURI(bunkerUri, {
        timeout: timeoutMs || this.timeout,
        localPrivateKey: lk,
        perms: perms ?? null
      });
      activeSigner = signer;
      if (onAuthUrl) signer.onAuthUrl = onAuthUrl;
      await signer.connectToBunker(timeoutMs || this.timeout);
      const pubkey = await signer.getPublicKey();
      this._addAccount(pubkey, signer, 'nip46', {
        remotePubkey: parsed.pubkey,
        bunkerUri
      });
      this._setActive(pubkey);
      return pubkey;
    };

    try {
      return await attempt(localPrivateKey || null);
    } catch (e) {
      // Clean up the failed signer before retrying or throwing
      if (activeSigner) activeSigner.disconnect();

      // Stored ephemeral key session was established before permissions were declared.
      // 'no permission' on get_public_key means Amber reused the old zero-grant session.
      // Retry with a fresh key to force a new connect handshake with correct perms.
      if (localPrivateKey && e.message?.toLowerCase().includes('no permission')) {
        return await attempt(null);
      }
      throw e;
    }
  }

  /**
   * Parse any NIP-46 URI (nostrconnect:// or bunker://)
   * Useful for determining which flow to use
   */
  static parseNip46URI(uri) {
    return Nip46Signer.parseURI(uri);
  }

  /**
   * Add local dev signer (for testing)
   */
  addLocalSigner(nsecOrHex) {
    if (!this.allowLocalDev) {
      throw new Error('Local dev signers are disabled');
    }

    let signer;
    if (nsecOrHex.startsWith('nsec')) {
      signer = LocalSigner.fromNsec(nsecOrHex);
    } else {
      signer = new LocalSigner(nsecOrHex);
    }

    const pubkey = bytesToHex(signer.publicKey);
    this._addAccount(pubkey, signer, 'local');
    this._setActive(pubkey);

    return pubkey;
  }

  /**
   * Generate a new local keypair (for testing)
   */
  generateLocalSigner() {
    if (!this.allowLocalDev) {
      throw new Error('Local dev signers are disabled');
    }

    const signer = LocalSigner.generate();
    const pubkey = bytesToHex(signer.publicKey);
    this._addAccount(pubkey, signer, 'local');
    this._setActive(pubkey);

    return {
      pubkey,
      nsec: signer.getNsec(),
      npub: signer.getNpub()
    };
  }

  /**
   * Connect as guest with a temporary local keypair.
   * Creates a new key on first call, restores the same key on subsequent calls.
   * Key is stored in localStorage and persists until explicitly cleared.
   */
  connectGuest() {
    if (!this.allowGuestMode) {
      throw new Error('Guest mode is not enabled.');
    }

    const guestKey = `${this.storageKey}_guest`;
    let signer;

    // Restore existing guest key if present
    const savedHex = localStorage.getItem(guestKey);
    if (savedHex) {
      try {
        signer = new LocalSigner(savedHex);
      } catch (_) {
        // Corrupt key, regenerate
        localStorage.removeItem(guestKey);
      }
    }

    // Generate fresh key if none restored
    if (!signer) {
      signer = LocalSigner.generate();
      localStorage.setItem(guestKey, bytesToHex(signer.privateKey));
    }

    const pubkey = bytesToHex(signer.publicKey);
    this._addAccount(pubkey, signer, 'guest');
    this._setActive(pubkey);

    return pubkey;
  }

  /**
   * Clear the guest key from storage
   */
  clearGuest() {
    const guestKey = `${this.storageKey}_guest`;
    localStorage.removeItem(guestKey);
  }

  /**
   * Auto-connect: tries NIP-07 first, returns null if unavailable
   */
  async autoConnect() {
    if (this.hasNip07()) {
      try {
        return await this.connectExtension();
      } catch (e) {
        console.warn('NIP-07 auto-connect failed:', e);
      }
    }
    return null;
  }

  // ---------- Account Management ----------

  _addAccount(pubkey, signer, type, metadata = {}) {
    this.accounts.set(pubkey, { signer, type, metadata });
    this._saveSession();
  }

  _setActive(pubkey) {
    if (!this.accounts.has(pubkey)) {
      throw new Error('Account not found');
    }
    this.activePubkey = pubkey;
    this._saveSession();

    if (this.onAccountChange) {
      this.onAccountChange(pubkey);
    }
  }

  switchAccount(pubkey) {
    this._setActive(pubkey);
  }

  getActiveAccount() {
    if (!this.activePubkey) return null;
    return {
      pubkey: this.activePubkey,
      ...this.accounts.get(this.activePubkey)
    };
  }

  getActivePubkey() {
    return this.activePubkey;
  }

  getActiveSigner() {
    if (!this.activePubkey) return null;
    return this.accounts.get(this.activePubkey)?.signer;
  }

  listAccounts() {
    return Array.from(this.accounts.entries()).map(([pubkey, data]) => ({
      pubkey,
      type: data.type,
      npub: encodeNpub(pubkey),
      isActive: pubkey === this.activePubkey
    }));
  }

  logout(pubkey) {
    const account = this.accounts.get(pubkey);
    if (account) {
      // Clean up NIP-46 connections
      if (account.type === 'nip46' && account.signer?.disconnect) {
        account.signer.disconnect();
      }
      this.accounts.delete(pubkey);

      if (this.activePubkey === pubkey) {
        // Switch to another account or null
        const remaining = Array.from(this.accounts.keys());
        this.activePubkey = remaining.length > 0 ? remaining[0] : null;
      }

      this._saveSession();

      if (this.onAccountChange) {
        this.onAccountChange(this.activePubkey);
      }
    }
  }

  logoutAll() {
    this.accounts.forEach((account) => {
      if (account.type === 'nip46' && account.signer?.disconnect) {
        account.signer.disconnect();
      }
    });
    this.accounts.clear();
    this.activePubkey = null;
    this._saveSession();

    if (this.onAccountChange) {
      this.onAccountChange(null);
    }
  }

  // ---------- Signing ----------

  async sign(event) {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('Session expired. Please sign in again.');
    return await signer.sign(event);
  }

  async getPublicKey() {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('Session expired. Please sign in again.');
    return await signer.getPublicKey();
  }

  async nip04Encrypt(content, pubkey) {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('Session expired. Please sign in again.');
    return await signer.nip04Encrypt(content, pubkey);
  }

  async nip04Decrypt(content, pubkey) {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('Session expired. Please sign in again.');
    return await signer.nip04Decrypt(content, pubkey);
  }

  // ---------- Session Persistence ----------

  _saveSession() {
    try {
      const data = {
        active: this.activePubkey,
        accounts: Array.from(this.accounts.entries()).map(([pubkey, acc]) => {
          const saved = { pubkey, type: acc.type, metadata: acc.metadata || {} };

          // For NIP-46, persist the session credentials (ephemeral key is safe to
          // store). When restored-but-not-yet-reconnected the live signer is null,
          // so fall back to the retained savedNip46 or the account is lost on reload.
          if (acc.type === 'nip46') {
            if (acc.signer) {
              saved.nip46 = {
                localPrivateKey: bytesToHex(acc.signer.localPrivateKey),
                remotePubkey: acc.signer.remotePubkey,
                relays: acc.signer.relays
              };
            } else if (acc.savedNip46) {
              saved.nip46 = acc.savedNip46;
            }
          }

          return saved;
        })
      };
      localStorage.setItem(this.storageKey, JSON.stringify(data));
    } catch (e) {
      console.warn('Failed to save session:', e);
    }
  }

  _loadSession() {
    try {
      const saved = localStorage.getItem(this.storageKey);
      if (!saved) return;

      const data = JSON.parse(saved);

      // Restore accounts
      data.accounts?.forEach(acc => {
        if (acc.type === 'nip07') {
          // Mark as known, but signer needs to be re-created
          this.accounts.set(acc.pubkey, {
            type: 'nip07',
            signer: null, // Will be created on demand
            metadata: acc.metadata || {}
          });
        } else if (acc.type === 'nip46' && acc.nip46) {
          // Restore NIP-46 account with saved credentials
          // Signer will be recreated on reconnect
          this.accounts.set(acc.pubkey, {
            type: 'nip46',
            signer: null, // Will be reconnected on restoreSession()
            metadata: acc.metadata || {},
            savedNip46: acc.nip46 // Store for reconnection
          });
        } else if (acc.type === 'guest') {
          // Guest account — signer recreated from stored guest key on restore
          this.accounts.set(acc.pubkey, {
            type: 'guest',
            signer: null,
            metadata: acc.metadata || {}
          });
        }
      });

      // Restore active pubkey if account exists
      if (data.active && this.accounts.has(data.active)) {
        this.activePubkey = data.active;
      }
    } catch (e) {
      console.warn('Failed to load session:', e);
    }
  }

  /**
   * Restore active signer (call after page load)
   * @param {number} timeoutMs - Timeout for NIP-46 reconnection
   */
  async restoreSession(timeoutMs = 15000) {
    if (!this.activePubkey) return null;

    const account = this.accounts.get(this.activePubkey);
    if (!account) return null;

    if (account.type === 'nip07') {
      if (!this.hasNip07()) {
        // Extension no longer available
        this.logout(this.activePubkey);
        return null;
      }

      // Re-create signer
      try {
        const signer = new Nip07Signer();
        const pubkey = await signer.getPublicKey();

        if (pubkey === this.activePubkey) {
          account.signer = signer;
          return pubkey;
        } else {
          // Different pubkey - extension changed
          this.logout(this.activePubkey);
          return null;
        }
      } catch (e) {
        this.logout(this.activePubkey);
        return null;
      }
    }

    if (account.type === 'nip46' && account.savedNip46) {
      try {
        // Recreate signer from saved credentials
        const signer = Nip46Signer.restore(account.savedNip46);

        // Try to reconnect
        await signer.reconnect(timeoutMs);

        account.signer = signer;
        delete account.savedNip46; // Clean up saved data once reconnected
        return this.activePubkey;
      } catch (e) {
        console.warn('Failed to restore NIP-46 session:', e);
        // Don't logout - keep the saved data for retry
        return null;
      }
    }

    if (account.type === 'guest') {
      if (!this.allowGuestMode) {
        this.logout(this.activePubkey);
        return null;
      }
      const guestKey = `${this.storageKey}_guest`;
      const savedHex = localStorage.getItem(guestKey);
      if (savedHex) {
        try {
          const signer = new LocalSigner(savedHex);
          const pubkey = bytesToHex(signer.publicKey);
          if (pubkey === this.activePubkey) {
            account.signer = signer;
            return pubkey;
          }
        } catch (_) {}
      }
      this.logout(this.activePubkey);
      return null;
    }

    return null;
  }

  /**
   * Check if there's a saved session that can be restored
   */
  hasSavedSession() {
    return this.activePubkey !== null && this.accounts.has(this.activePubkey);
  }

  /**
   * Get saved session info without connecting
   */
  getSavedSessionInfo() {
    if (!this.activePubkey) return null;

    const account = this.accounts.get(this.activePubkey);
    if (!account) return null;

    return {
      pubkey: this.activePubkey,
      type: account.type,
      metadata: account.metadata || {},
      needsReconnect: account.signer === null
    };
  }
}

// ============================================================================
// QR CODE GENERATOR
// ============================================================================

/**
 * QR Code generator - generates valid QR codes for nostrconnect URIs
 * Implements QR Code Model 2, ISO/IEC 18004, ECC Level L
 */
const QR = (function() {
  // GF(256) with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
  const EXP = new Uint8Array(256);
  const LOG = new Uint8Array(256);
  for (let i = 0, x = 1; i < 256; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x = x * 2 ^ (x >= 128 ? 0x11D : 0);
  }

  function reedSolomonRemainder(data, numEcc) {
    const divisor = reedSolomonDivisor(numEcc);
    const result = new Uint8Array(numEcc);
    for (const b of data) {
      const factor = b ^ result[0];
      result.copyWithin(0, 1);
      result[numEcc - 1] = 0;
      for (let i = 0; i < numEcc; i++)
        result[i] ^= multiply(divisor[i], factor);
    }
    return result;
  }

  function reedSolomonDivisor(degree) {
    const result = new Uint8Array(degree);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < degree; j++) {
        result[j] = multiply(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = multiply(root, 2);
    }
    return result;
  }

  function multiply(x, y) {
    return x === 0 || y === 0 ? 0 : EXP[(LOG[x] + LOG[y]) % 255];
  }

  // Version parameters for ECC level L
  const VERSION_PARAMS = {
    1:  { totalCw: 26,  dataCw: 19,  eccPerBlock: 7,  numBlocks: 1 },
    2:  { totalCw: 44,  dataCw: 34,  eccPerBlock: 10, numBlocks: 1 },
    3:  { totalCw: 70,  dataCw: 55,  eccPerBlock: 15, numBlocks: 1 },
    4:  { totalCw: 100, dataCw: 80,  eccPerBlock: 20, numBlocks: 1 },
    5:  { totalCw: 134, dataCw: 108, eccPerBlock: 26, numBlocks: 1 },
    6:  { totalCw: 172, dataCw: 136, eccPerBlock: 18, numBlocks: 2 },
    7:  { totalCw: 196, dataCw: 156, eccPerBlock: 20, numBlocks: 2 },
    8:  { totalCw: 242, dataCw: 194, eccPerBlock: 24, numBlocks: 2 },
    9:  { totalCw: 292, dataCw: 232, eccPerBlock: 30, numBlocks: 2 },
    10: { totalCw: 346, dataCw: 274, eccPerBlock: 18, numBlocks: 4 },
  };

  const ALIGN_POSITIONS = {
    1: [], 2: [6,18], 3: [6,22], 4: [6,26], 5: [6,30],
    6: [6,34], 7: [6,22,38], 8: [6,24,42], 9: [6,26,46], 10: [6,28,50]
  };

  function getVersion(dataLen) {
    for (let v = 1; v <= 10; v++) {
      if (VERSION_PARAMS[v].dataCw >= dataLen + 3) return v;
    }
    throw new Error('Data too long');
  }

  function encode(text) {
    const bytes = new TextEncoder().encode(text);
    const version = getVersion(bytes.length);
    const params = VERSION_PARAMS[version];
    const size = 17 + version * 4;

    // Build data bits
    let bits = '0100'; // Byte mode
    bits += bytes.length.toString(2).padStart(version < 10 ? 8 : 16, '0');
    for (const b of bytes) bits += b.toString(2).padStart(8, '0');

    // Add terminator
    const capacityBits = params.dataCw * 8;
    bits += '0'.repeat(Math.min(4, capacityBits - bits.length));
    bits += '0'.repeat((8 - bits.length % 8) % 8);

    // Pad to capacity
    while (bits.length < capacityBits) {
      bits += bits.length % 16 === 0 ? '11101100' : '00010001';
    }

    // Convert to codewords
    const dataCodewords = new Uint8Array(params.dataCw);
    for (let i = 0; i < params.dataCw; i++) {
      dataCodewords[i] = parseInt(bits.substr(i * 8, 8), 2);
    }

    // Generate error correction
    const numBlocks = params.numBlocks;
    const eccPerBlock = params.eccPerBlock;
    const shortBlockLen = Math.floor(params.dataCw / numBlocks);
    const longBlocks = params.dataCw % numBlocks;

    const allCodewords = [];
    let dataIndex = 0;

    const dataBlocks = [];
    const eccBlocks = [];

    for (let i = 0; i < numBlocks; i++) {
      const blockLen = shortBlockLen + (i >= numBlocks - longBlocks ? 1 : 0);
      const block = dataCodewords.slice(dataIndex, dataIndex + blockLen);
      dataIndex += blockLen;
      dataBlocks.push(block);
      eccBlocks.push(reedSolomonRemainder(block, eccPerBlock));
    }

    // Interleave data blocks
    for (let i = 0; i < shortBlockLen + 1; i++) {
      for (let j = 0; j < numBlocks; j++) {
        if (i < dataBlocks[j].length) allCodewords.push(dataBlocks[j][i]);
      }
    }
    // Interleave ECC blocks
    for (let i = 0; i < eccPerBlock; i++) {
      for (let j = 0; j < numBlocks; j++) {
        allCodewords.push(eccBlocks[j][i]);
      }
    }

    // Create modules grid (-1 = not set, 0 = white, 1 = black)
    const modules = [];
    for (let i = 0; i < size; i++) modules.push(new Int8Array(size).fill(-1));

    // Place finder patterns
    function setFinderPattern(row, col) {
      for (let dy = -1; dy <= 7; dy++) {
        for (let dx = -1; dx <= 7; dx++) {
          const y = row + dy, x = col + dx;
          if (y < 0 || y >= size || x < 0 || x >= size) continue;
          const dist = Math.max(Math.abs(dy - 3), Math.abs(dx - 3));
          modules[y][x] = (dist !== 2 && dist !== 4) ? 1 : 0;
        }
      }
    }
    setFinderPattern(0, 0);
    setFinderPattern(0, size - 7);
    setFinderPattern(size - 7, 0);

    // Place alignment patterns
    const alignPos = ALIGN_POSITIONS[version];
    for (const y of alignPos) {
      for (const x of alignPos) {
        if (modules[y][x] !== -1) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            const dist = Math.max(Math.abs(dy), Math.abs(dx));
            modules[y + dy][x + dx] = dist !== 1 ? 1 : 0;
          }
        }
      }
    }

    // Place timing patterns
    for (let i = 8; i < size - 8; i++) {
      const val = i % 2 === 0 ? 1 : 0;
      if (modules[6][i] === -1) modules[6][i] = val;
      if (modules[i][6] === -1) modules[i][6] = val;
    }

    // Place dark module
    modules[size - 8][8] = 1;

    // Reserve format areas (will be filled later)
    for (let i = 0; i < 9; i++) {
      if (modules[8][i] === -1) modules[8][i] = 0;
      if (modules[i][8] === -1) modules[i][8] = 0;
    }
    for (let i = 0; i < 8; i++) {
      if (modules[8][size - 1 - i] === -1) modules[8][size - 1 - i] = 0;
      if (modules[size - 1 - i][8] === -1) modules[size - 1 - i][8] = 0;
    }

    // Place data
    let bitIndex = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (modules[y][x] !== -1) continue;
          const bit = bitIndex < allCodewords.length * 8
            ? (allCodewords[Math.floor(bitIndex / 8)] >> (7 - bitIndex % 8)) & 1
            : 0;
          modules[y][x] = bit;
          bitIndex++;
        }
      }
    }

    // Apply mask pattern 0 and format info
    const mask = (y, x) => (y + x) % 2 === 0;
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (modules[y][x] === -1) modules[y][x] = 0;
      }
    }

    // Mark which modules are function patterns (should not be masked)
    const isFunction = [];
    for (let i = 0; i < size; i++) isFunction.push(new Uint8Array(size));

    // Mark finders
    for (const [fy, fx] of [[0,0], [0,size-7], [size-7,0]]) {
      for (let dy = -1; dy <= 7; dy++) {
        for (let dx = -1; dx <= 7; dx++) {
          const y = fy + dy, x = fx + dx;
          if (y >= 0 && y < size && x >= 0 && x < size) isFunction[y][x] = 1;
        }
      }
    }
    // Mark alignments
    for (const ay of alignPos) {
      for (const ax of alignPos) {
        if (isFunction[ay][ax]) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            isFunction[ay + dy][ax + dx] = 1;
          }
        }
      }
    }
    // Mark timing
    for (let i = 0; i < size; i++) {
      isFunction[6][i] = isFunction[i][6] = 1;
    }
    // Mark dark module
    isFunction[size - 8][8] = 1;
    // Mark format areas
    for (let i = 0; i < 9; i++) {
      isFunction[8][i] = isFunction[i][8] = 1;
    }
    for (let i = 0; i < 8; i++) {
      isFunction[8][size - 1 - i] = isFunction[size - 1 - i][8] = 1;
    }

    // Apply mask
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (!isFunction[y][x] && mask(y, x)) {
          modules[y][x] ^= 1;
        }
      }
    }

    // Place format info (ECC L = 01, Mask 0 = 000, format = 01000)
    // Format string with BCH: 111011111000100
    const formatBits = [1,1,1,0,1,1,1,1,1,0,0,0,1,0,0];

    // Around top-left
    for (let i = 0; i <= 5; i++) modules[8][i] = formatBits[i];
    modules[8][7] = formatBits[6];
    modules[8][8] = formatBits[7];
    modules[7][8] = formatBits[8];
    for (let i = 9; i < 15; i++) modules[14 - i][8] = formatBits[i];

    // Around top-right and bottom-left
    for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = formatBits[i];
    for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = formatBits[i];

    return { modules, size, version };
  }

  function toCanvas(text, scale = 5, margin = 4) {
    const { modules, size } = encode(text);
    const imgSize = (size + margin * 2) * scale;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = imgSize;
    const ctx = canvas.getContext('2d');

    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, imgSize, imgSize);

    ctx.fillStyle = '#000000';
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (modules[y][x] === 1) {
          ctx.fillRect((x + margin) * scale, (y + margin) * scale, scale, scale);
        }
      }
    }
    return canvas;
  }

  function toDataURL(text, scale = 5, margin = 4) {
    return toCanvas(text, scale, margin).toDataURL();
  }

  function toSVG(text, scale = 5, margin = 4) {
    const { modules, size } = encode(text);
    const imgSize = size + margin * 2;

    let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${imgSize} ${imgSize}" width="${imgSize * scale}" height="${imgSize * scale}">`;
    svg += `<rect width="100%" height="100%" fill="white"/>`;
    svg += `<path d="`;

    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (modules[y][x] === 1) {
          svg += `M${x + margin},${y + margin}h1v1h-1z`;
        }
      }
    }

    svg += `" fill="black"/>`;
    svg += `</svg>`;

    return svg;
  }

  function toASCII(text) {
    const { modules, size } = encode(text);
    let result = '';
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        result += modules[y][x] === 1 ? '██' : '  ';
      }
      result += '\n';
    }
    return result;
  }

  return { encode, toCanvas, toDataURL, toSVG, toASCII };
})();

/**
 * Generate QR code as data URL (PNG)
 * @param {string} text - Text to encode
 * @param {number} scale - Pixel scale (default 5)
 * @param {number} margin - Quiet zone margin in modules (default 4)
 * @param {boolean} useExternal - Use external API (default false)
 * @returns {string} Data URL or URL to QR code image
 */
function generateQRCode(text, scale = 5, margin = 4, useExternal = false) {
  if (useExternal) {
    const size = 200 + (scale * 10);
    return `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}`;
  }
  return QR.toDataURL(text, scale, margin);
}

/**
 * Generate QR code as SVG string
 * @param {string} text - Text to encode
 * @param {number} scale - Pixel scale (default 4)
 * @param {number} margin - Quiet zone margin in modules (default 4)
 * @returns {string} SVG markup
 */
function generateQRCodeSVG(text, scale = 4, margin = 4) {
  return QR.toSVG(text, scale, margin);
}

// ============================================================================
// LOGIN UI HELPER
// ============================================================================

/**
 * Login flow states
 */
const LoginState = {
  IDLE: 'idle',
  CHECKING: 'checking',
  WAITING_EXTENSION: 'waiting_extension',
  SHOWING_QR: 'showing_qr',
  WAITING_NIP46: 'waiting_nip46',
  CONNECTED: 'connected',
  ERROR: 'error'
};

/**
 * Login UI Helper - manages the login flow state machine
 * You provide the UI, this manages the logic and callbacks
 */
class NostrLoginFlow {
  constructor(auth, options = {}) {
    this.auth = auth;
    this.state = LoginState.IDLE;
    this.error = null;
    this.qrUri = null;
    this.qrDataUrl = null;
    this.countdown = 0;
    this.countdownInterval = null;
    this.pendingSigner = null;
    this.abortController = null;

    // Callbacks
    this.onStateChange = options.onStateChange || (() => {});
    this.onCountdown = options.onCountdown || (() => {});
    this.onProgress = options.onProgress || (() => {});
    this.onConnected = options.onConnected || (() => {});
    this.onError = options.onError || (() => {});

    // Config
    this.nip46Timeout = options.nip46Timeout || 120000; // 2 minutes
    this.appName = options.appName || 'Nostr App';
    this.appUrl = options.appUrl || (typeof window !== 'undefined' ? window.location.origin : '');
  }

  _setState(state, extra = {}) {
    this.state = state;
    Object.assign(this, extra);
    this.onStateChange(state, this);
  }

  /**
   * Start the login flow - checks for extension first
   */
  async start() {
    this._setState(LoginState.CHECKING);

    // Check for existing session
    const restored = await this.auth.restoreSession();
    if (restored) {
      this._setState(LoginState.CONNECTED);
      this.onConnected(restored);
      return restored;
    }

    // Try NIP-07 extension
    if (this.auth.hasNip07()) {
      this._setState(LoginState.WAITING_EXTENSION);
      try {
        const pubkey = await this.auth.connectExtension();
        this._setState(LoginState.CONNECTED);
        this.onConnected(pubkey);
        return pubkey;
      } catch (e) {
        // Extension failed, fall through to show options
      }
    }

    // No extension or failed, go to idle state (show options)
    this._setState(LoginState.IDLE);
    return null;
  }

  /**
   * Attempt extension login
   */
  async connectExtension() {
    if (!this.auth.hasNip07()) {
      this._setState(LoginState.ERROR, { error: 'No browser extension found' });
      this.onError(new Error('No browser extension found'));
      return null;
    }

    this._setState(LoginState.WAITING_EXTENSION);

    try {
      const pubkey = await this.auth.connectExtension();
      this._setState(LoginState.CONNECTED);
      this.onConnected(pubkey);
      return pubkey;
    } catch (e) {
      this._setState(LoginState.ERROR, { error: e.message });
      this.onError(e);
      return null;
    }
  }

  /**
   * Start NIP-46 QR code flow
   */
  async startNip46() {
    this.abortController = new AbortController();

    const { signer, uri } = this.auth.createNip46Session({
      name: this.appName,
      url: this.appUrl
    });

    this.pendingSigner = signer;
    this.qrUri = uri;

    // Generate QR code - use external API for reliability until local is fixed
    console.log('NIP-46 URI length:', uri.length, 'chars');
    console.log('NIP-46 URI:', uri);
    this.qrDataUrl = generateQRCode(uri, 5, 4, true); // Use external API
    console.log('QR data URL generated');

    // Start countdown
    this.countdown = Math.floor(this.nip46Timeout / 1000);
    this._setState(LoginState.SHOWING_QR);

    this.countdownInterval = setInterval(() => {
      this.countdown--;
      this.onCountdown(this.countdown);
      if (this.countdown <= 0) {
        this.cancelNip46();
      }
    }, 1000);

    // Wait for connection
    this._setState(LoginState.WAITING_NIP46);

    try {
      const pubkey = await this.auth.finalizeNip46(signer, this.nip46Timeout, (stage, message) => {
        this.onProgress(stage, message);
      });
      this._clearCountdown();
      this._setState(LoginState.CONNECTED);
      this.onConnected(pubkey);
      return pubkey;
    } catch (e) {
      this._clearCountdown();
      if (this.state !== LoginState.IDLE) {
        this._setState(LoginState.ERROR, { error: e.message });
        this.onError(e);
      }
      return null;
    }
  }

  /**
   * Cancel NIP-46 flow
   */
  cancelNip46() {
    this._clearCountdown();
    if (this.pendingSigner) {
      this.pendingSigner.disconnect();
      this.pendingSigner = null;
    }
    this.qrUri = null;
    this.qrDataUrl = null;
    this._setState(LoginState.IDLE);
  }

  _clearCountdown() {
    if (this.countdownInterval) {
      clearInterval(this.countdownInterval);
      this.countdownInterval = null;
    }
  }

  /**
   * Add a local dev key (for testing)
   */
  addDevKey(nsec) {
    try {
      const pubkey = this.auth.addLocalSigner(nsec);
      this._setState(LoginState.CONNECTED);
      this.onConnected(pubkey);
      return pubkey;
    } catch (e) {
      this._setState(LoginState.ERROR, { error: e.message });
      this.onError(e);
      return null;
    }
  }

  /**
   * Generate a new local key (for testing)
   */
  generateDevKey() {
    try {
      const result = this.auth.generateLocalSigner();
      this._setState(LoginState.CONNECTED);
      this.onConnected(result.pubkey);
      return result;
    } catch (e) {
      this._setState(LoginState.ERROR, { error: e.message });
      this.onError(e);
      return null;
    }
  }

  /**
   * Connect using a bunker:// URI (signer-initiated flow)
   * User pastes this URI from their signer app
   */
  async connectBunker(bunkerUri, { onAuthUrl } = {}) {
    this._setState(LoginState.CHECKING);

    try {
      // Validate URI format
      const parsed = NostrAuth.parseNip46URI(bunkerUri);

      if (parsed.type === 'nostrconnect') {
        throw new Error('This is a nostrconnect:// URI. Use the QR code flow instead, or provide a bunker:// URI.');
      }

      const pubkey = await this.auth.connectBunker(bunkerUri, this.nip46Timeout, { onAuthUrl });
      this._setState(LoginState.CONNECTED);
      this.onConnected(pubkey);
      return pubkey;
    } catch (e) {
      this._setState(LoginState.ERROR, { error: e.message });
      this.onError(e);
      return null;
    }
  }

  /**
   * Reset to idle state
   */
  reset() {
    this.cancelNip46();
    this._setState(LoginState.IDLE, { error: null });
  }

  /**
   * Check if extension is available
   */
  hasExtension() {
    return this.auth.hasNip07();
  }

  /**
   * Check if dev mode is enabled
   */
  hasDevMode() {
    return this.auth.allowLocalDev;
  }
}

// ============================================================================
// PLATFORM DETECTION
// ============================================================================

/**
 * Detect the current platform for login method selection.
 * @returns {{ isMobile: boolean, isAndroid: boolean, isiOS: boolean }}
 */
function detectPlatform() {
  if (typeof navigator === 'undefined' || typeof window === 'undefined') {
    return { isMobile: false, isAndroid: false, isiOS: false };
  }
  const ua = navigator.userAgent;
  const isAndroid = /Android/i.test(ua);
  const isiOS = /iPhone|iPad|iPod/i.test(ua);
  // screen.width/height report physical screen size in CSS pixels,
  // unaffected by Chrome's "Request Desktop Site" viewport override.
  // maxTouchPoints is a hardware capability, not spoofed by desktop mode.
  const smallScreen = Math.min(screen.width, screen.height) <= 800;
  const hasTouch = navigator.maxTouchPoints > 0;
  const isMobile = isAndroid || isiOS || (hasTouch && smallScreen);
  return { isMobile, isAndroid, isiOS };
}

/**
 * Get login methods appropriate for the current platform.
 * On mobile: no extension (won't work), prefer deep link over QR.
 * On desktop: extension, QR, bunker paste.
 * @param {{ hasNip07?: boolean }} options
 * @returns {{ methods: string[], platform: { isMobile: boolean, isAndroid: boolean, isiOS: boolean } }}
 */
function getLoginMethods(options = {}) {
  const platform = detectPlatform();
  const hasExt = options.hasNip07 ?? false;
  const methods = [];

  if (platform.isMobile) {
    methods.push('deeplink');  // nostrconnect:// opens signer app
    methods.push('bunker');    // paste bunker:// URI
  } else {
    if (hasExt) methods.push('extension');
    methods.push('qr');        // QR code for cross-device
    methods.push('bunker');    // paste bunker:// URI
  }

  return { methods, platform };
}


// ============================================================================
// PROFILE UTILITIES
// ============================================================================

/**
 * Internal debug logger — always-on, uses console.debug.
 * Visible in DevTools under Verbose level (hidden at Default).
 * @private
 */
function _nuiLog(...args) {
  console.debug('[nui]', ...args);
}
/**
 * Fetch a Nostr profile (kind:0) from relays.
 * Creates and disposes its own RelayPool — caller does not manage relay state.
 * Resolves on EOSE or after timeoutMs, whichever comes first.
 * @param {string} pubkeyHex - Hex-encoded public key
 * @param {string[]} relays  - Relay WebSocket URLs
 * @param {number}  [timeoutMs=5000]
 * @returns {Promise<object|null>} Parsed kind:0 content, or null
 */
async function fetchProfile(pubkeyHex, relays, timeoutMs = 5000) {
  return new Promise(resolve => {
    let best = null;
    let done = false;
    const pool = new RelayPool();
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sub.close();
      setTimeout(() => pool.close(), 200);
      if (!best) {
        _nuiLog('fetchProfile → null (no event received)');
        resolve(null); return;
      }
      let parsed = null;
      try { parsed = JSON.parse(best.content); } catch { /* malformed */ }
      _nuiLog('fetchProfile →', parsed ? (parsed.display_name || parsed.name || '(no name field)') : 'JSON parse failed');
      resolve(parsed);
    };
    const timer = setTimeout(finish, timeoutMs);
    const sub = pool.subscribe(
      relays,
      [{ kinds: [0], authors: [pubkeyHex], limit: 1 }],
      {
        onEvent: async event => {
          // The relay's `authors` filter is advisory; a malicious relay can return
          // a forged/mismatched kind:0. Require the author to match and the
          // signature to verify before trusting it as this user's profile.
          if (event.pubkey !== pubkeyHex) return;
          if (!best || event.created_at > best.created_at) {
            if (!(await verifyEvent(event).catch(() => false))) return;
            if (!best || event.created_at > best.created_at) {
              best = event;
              _nuiLog('fetchProfile got event created_at:', event.created_at, 'from', event.pubkey.slice(0,8) + '…');
            }
          }
        },
        onEose:  () => { _nuiLog('fetchProfile EOSE'); finish(); },
        onError: (err) => { _nuiLog('fetchProfile relay error:', err?.message); if (!best) finish(); },
      }
    );
  });
}

/** @private */
const _NUI_PROFILE_PREFIX = 'nostr_profile_';
/** @private — app-supplied overrides; a separate slot the kind:0 fetch never touches. */
const _NUI_PROFILE_OVERRIDE_PREFIX = 'nostr_profile_override_';
/** @private */
const _NUI_PROFILE_TTL = 24 * 60 * 60 * 1000;

/** @private — read the kind:0 slot, honouring the 24 h TTL. */
function _nuiReadKind0(pubkeyHex) {
  try {
    const raw = localStorage.getItem(_NUI_PROFILE_PREFIX + pubkeyHex);
    if (!raw) return null;
    const { ts, profile } = JSON.parse(raw);
    if (Date.now() - ts > _NUI_PROFILE_TTL) return null;
    return profile || null;
  } catch { return null; }
}

/** @private — read the app-supplied override slot (no TTL; the app is authoritative). */
function _nuiReadOverride(pubkeyHex) {
  try {
    const raw = localStorage.getItem(_NUI_PROFILE_OVERRIDE_PREFIX + pubkeyHex);
    if (!raw) return null;
    const { profile } = JSON.parse(raw);
    return profile || null;
  } catch { return null; }
}

/**
 * Read a Nostr profile from the localStorage cache.
 * Merges the kind:0 slot (24 h TTL) with any app-supplied override, the override
 * winning field-by-field. Returns null only when neither slot has data.
 * @param {string} pubkeyHex
 * @returns {object|null}
 */
function getCachedProfile(pubkeyHex) {
  const kind0    = _nuiReadKind0(pubkeyHex);
  const override = _nuiReadOverride(pubkeyHex);
  if (!kind0 && !override) {
    _nuiLog('getCachedProfile MISS key:', pubkeyHex.slice(0, 8) + '…');
    return null;
  }
  const merged = { ...(kind0 || {}), ...(override || {}) };
  _nuiLog('getCachedProfile HIT:', merged.display_name || merged.name || '(no name)',
    override ? '(override)' : '', 'key:', pubkeyHex.slice(0, 8) + '…');
  return merged;
}

/**
 * Write a Nostr profile to the localStorage kind:0 cache slot.
 * Does not touch app overrides written via setProfileOverride.
 * @param {string} pubkeyHex
 * @param {object} profile
 */
function setCachedProfile(pubkeyHex, profile) {
  try {
    localStorage.setItem(
      _NUI_PROFILE_PREFIX + pubkeyHex,
      JSON.stringify({ ts: Date.now(), profile })
    );
    _nuiLog('setCachedProfile key:', pubkeyHex.slice(0, 8) + '…', '| name:', profile?.display_name || profile?.name || '(none)');
  } catch {}
}

/**
 * Write (or clear) an app-supplied profile override. The override slot is kept
 * separate from the kind:0 slot the background relay fetch writes, so an
 * app-chosen name/avatar survives re-login and wins at render time. Pass a
 * falsy `profile` to remove the override.
 * @param {string} pubkeyHex
 * @param {object|null} profile  Partial kind:0-shaped profile, or null to clear.
 */
function setProfileOverride(pubkeyHex, profile) {
  try {
    const key = _NUI_PROFILE_OVERRIDE_PREFIX + pubkeyHex;
    if (!profile) {
      localStorage.removeItem(key);
      _nuiLog('setProfileOverride CLEAR key:', pubkeyHex.slice(0, 8) + '…');
      return;
    }
    localStorage.setItem(key, JSON.stringify({ ts: Date.now(), profile }));
    _nuiLog('setProfileOverride key:', pubkeyHex.slice(0, 8) + '…', '| name:', profile?.display_name || profile?.name || '(none)');
  } catch {}
}

// ============================================================================
// LOGIN UI
// ============================================================================

/** @private — HTML-escape a string for safe insertion into innerHTML. */
function _nuiE(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Returns an avatar element HTML string.
 * Shows the profile picture if available; falls back to a letter avatar
 * with a hue derived from the public key.
 * @param {object|null} profile  Kind:0 profile content, or null
 * @param {string}      pubkeyHex  Hex public key (for colour)
 * @param {number}      [sizePx=32]
 * @returns {string} HTML
 */
function nuiAvatarHtml(profile, pubkeyHex, sizePx = 32) {
  const fs  = Math.round(sizePx * 0.42);
  const name = profile?.display_name || profile?.name || '';
  const letter = (name[0] || (pubkeyHex ? pubkeyHex[0] : '?')).toUpperCase();
  const hue  = pubkeyHex ? parseInt(pubkeyHex.slice(0, 6), 16) % 360 : 180;
  const bg   = `hsl(${hue},38%,32%)`;
  const base = `width:${sizePx}px;height:${sizePx}px;border-radius:50%;flex-shrink:0;overflow:hidden;position:relative;`;
  const inner = `<div style='position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:${fs}px;font-weight:600;color:#fff;background:${bg};'>${_nuiE(letter)}</div>`;
  if (!profile?.picture) {
    return `<div style='${base}'>${inner}</div>`;
  }
  return `<div style='${base}'>` +
    inner +
    `<img src='${_nuiE(profile.picture)}' style='position:absolute;inset:0;width:100%;height:100%;object-fit:cover;' onerror='this.remove()' loading='lazy'>` +
    `</div>`;
}

/**
 * Returns the best available display name for a profile.
 * Falls back to a shortened npub, then 'Nostr User'.
 * @param {object|null} profile
 * @param {string}      npub
 * @returns {string}
 */
function nuiDisplayName(profile, npub) {
  return profile?.display_name || profile?.name ||
    (npub ? npub.slice(0, 12) + '\u2026' : 'Nostr User');
}

/** @private — CSS for NostrLoginUI, injected once into <head>. */
function _nuiGetStyles() {
  return `
.nui-card{background:var(--nui-card,#1c1c24);border-radius:16px;padding:24px 32px;box-shadow:0 8px 32px rgba(0,0,0,.3);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:var(--nui-text,#e4e4e7);font-size:15px;}
.nui-hidden{display:none!important}
.nui-header{text-align:center;margin-bottom:16px}
.nui-title{font-size:20px;color:var(--nui-primary,#6366f1);margin-bottom:2px;font-weight:600;margin:0 0 2px}
.nui-subtitle{color:var(--nui-muted,#71717a);font-size:13px;margin:0}
.nui-status{padding:20px;border-radius:10px;margin-bottom:16px;text-align:center}
.nui-status.nui-loading{background:rgba(99,102,241,.08);display:flex;justify-content:center;align-items:center}
.nui-status.nui-error{background:rgba(239,68,68,.08);color:var(--nui-error,#ef4444)}
.nui-status.nui-approval{background:rgba(99,102,241,.08)}
.nui-status-step{font-size:16px;font-weight:600;color:var(--nui-text,#e4e4e7);margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:10px}
.nui-status-detail{font-size:13px;color:var(--nui-muted,#71717a);line-height:1.5}
.nui-status-detail a{color:var(--nui-primary,#6366f1);text-decoration:underline}
.nui-countdown-num{font-size:24px;font-weight:700;color:var(--nui-primary,#6366f1);font-variant-numeric:tabular-nums;margin:8px 0 4px}
.nui-spinner{width:20px;height:20px;border:2px solid var(--nui-primary,#6366f1);border-top-color:transparent;border-radius:50%;animation:nui-spin .7s linear infinite;flex-shrink:0}
@keyframes nui-spin{to{transform:rotate(360deg)}}
.nui-options{display:flex;flex-direction:column;gap:12px}
.nui-group-label{padding:12px 0 2px;font-size:11px;color:var(--nui-muted,#71717a);text-transform:uppercase;letter-spacing:.05em}
.nui-opt-btn{display:flex;align-items:center;gap:12px;padding:14px 18px;min-height:60px;background:var(--nui-card-hover,#26262f);border:1px solid var(--nui-border,#27272a);border-radius:10px;color:var(--nui-text,#e4e4e7);font-size:15px;cursor:pointer;transition:all .15s;text-align:left;width:100%;box-sizing:border-box;font-family:inherit}
.nui-opt-btn:hover:not(:disabled){background:var(--nui-primary,#6366f1);border-color:var(--nui-primary,#6366f1)}
.nui-opt-btn:hover:not(:disabled) .nui-opt-hint{color:rgba(255,255,255,.7)}
.nui-opt-btn:disabled{opacity:.4;cursor:not-allowed}
.nui-opt-icon{flex-shrink:0;color:var(--nui-muted,#71717a)}
.nui-opt-label{flex:1}
.nui-opt-hint{display:block;font-size:12px;color:var(--nui-muted,#71717a);margin-top:2px}
.nui-guest-section{text-align:center;padding-top:12px;border-top:1px solid var(--nui-border,#27272a);margin-top:12px}
.nui-guest-btn{background:none;border:none;color:var(--nui-muted,#71717a);font-size:12px;cursor:pointer;transition:color .15s;font-family:inherit}
.nui-guest-btn:hover{color:var(--nui-primary,#6366f1)}
.nui-guest-hint{margin:6px auto 0;font-size:11px;color:var(--nui-muted,#71717a);line-height:1.4;max-width:300px}
.nui-btn{padding:10px 18px;border-radius:8px;border:none;font-size:14px;cursor:pointer;transition:all .15s;font-family:inherit}
.nui-btn-primary{background:var(--nui-primary,#6366f1);color:#fff}
.nui-btn-primary:hover{background:var(--nui-primary-hover,#4f46e5)}
.nui-btn-ghost{background:transparent;color:var(--nui-muted,#71717a);border:1px solid var(--nui-border,#27272a)}
.nui-btn-ghost:hover{color:var(--nui-text,#e4e4e7);border-color:var(--nui-muted,#71717a)}
.nui-btn-sm{padding:6px 12px;font-size:12px}
.nui-btn-icon{flex-shrink:0;width:34px;height:34px;border:1px solid var(--nui-border,#27272a);border-radius:6px;background:var(--nui-card-hover,#26262f);color:var(--nui-muted,#71717a);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
.nui-btn-icon:hover{border-color:var(--nui-primary,#6366f1);color:var(--nui-primary,#6366f1)}
.nui-btn-row{display:flex;gap:10px}
.nui-btn-row .nui-btn{flex:1}
.nui-input{width:100%;padding:12px;border-radius:8px;border:1px solid var(--nui-border,#27272a);background:var(--nui-bg,#111118);color:var(--nui-text,#e4e4e7);font-family:monospace;font-size:13px;box-sizing:border-box}
.nui-input:focus{outline:none;border-color:var(--nui-primary,#6366f1)}
.nui-input-plain{width:100%;padding:10px;margin:0 0 12px;border-radius:8px;border:1px solid var(--nui-border,#27272a);background:var(--nui-bg,#111118);color:var(--nui-text,#e4e4e7);font-size:13px;box-sizing:border-box;font-family:inherit}
.nui-input-plain:focus{outline:none;border-color:var(--nui-primary,#6366f1)}
.nui-label{font-size:12px;color:var(--nui-muted,#71717a);margin-bottom:2px;display:block}
.nui-view-paste .nui-input{margin:12px 0}
.nui-view-qr{text-align:center}
.nui-qr-wrap{text-align:center;margin-bottom:12px}
.nui-qr-img{display:block;width:200px;height:200px}
.nui-qr-uri-row{display:flex;align-items:center;gap:6px;margin-bottom:12px}
.nui-qr-uri{flex:1;font-family:monospace;font-size:11px;color:var(--nui-muted,#71717a);word-break:break-all;padding:8px;background:var(--nui-bg,#111118);border-radius:6px;border:1px solid var(--nui-border,#27272a)}
.nui-qr-status{color:var(--nui-muted,#71717a);font-size:13px;margin-bottom:12px}
.nui-view-scan{text-align:center}
.nui-scan-wrap{position:relative;width:100%;max-width:300px;margin:0 auto 16px;border-radius:12px;overflow:hidden;background:#000}
.nui-scan-video{width:100%;display:block}
.nui-scan-status{color:var(--nui-muted,#71717a);font-size:13px;margin-bottom:12px}
.nui-view-deeplink{text-align:center}
.nui-deeplink-status{color:var(--nui-muted,#71717a);font-size:14px;margin-bottom:12px}
.nui-deeplink-help{font-size:12px;color:var(--nui-muted,#71717a);margin-bottom:16px;line-height:1.6}
.nui-recent-label{font-size:11px;color:var(--nui-muted,#71717a);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em;padding-top:8px}
.nui-recent-item{display:flex;align-items:center;gap:10px;padding:10px 12px;margin-bottom:6px;position:relative;background:var(--nui-bg,#111118);border:1px solid var(--nui-border,#27272a);border-radius:8px;cursor:pointer;transition:all .15s}
.nui-recent-item:hover{border-color:var(--nui-primary,#6366f1)}
.nui-recent-body{flex:1;min-width:0}
.nui-recent-name{font-size:13px;color:var(--nui-text,#e4e4e7);font-weight:500}
.nui-recent-sub{font-size:11px;color:var(--nui-muted,#71717a);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:flex;gap:8px}
.nui-recent-arrow{flex-shrink:0;color:var(--nui-muted,#71717a);transition:transform .15s,color .15s}
.nui-recent-item:hover .nui-recent-arrow{transform:translateX(2px);color:var(--nui-primary,#6366f1)}
.nui-recent-remove{position:absolute;top:4px;right:4px;width:20px;height:20px;border:none;background:transparent;color:var(--nui-muted,#71717a);cursor:pointer;padding:0;border-radius:4px;opacity:0;transition:opacity .15s,color .15s;display:flex;align-items:center;justify-content:center}
.nui-recent-item:hover .nui-recent-remove{opacity:1}
.nui-recent-remove:hover{color:var(--nui-error,#ef4444)}
.nui-more-btn{width:100%;padding:6px;border:none;background:transparent;color:var(--nui-muted,#71717a);font-size:12px;cursor:pointer;transition:color .15s;font-family:inherit}
.nui-more-btn:hover{color:var(--nui-primary,#6366f1)}
.nui-view-localdev textarea.nui-input{font-size:12px;line-height:1.5}
.nui-app-header{position:fixed;top:0;left:0;right:0;height:52px;background:var(--nui-card,#1c1c24);border-bottom:1px solid var(--nui-border,#27272a);display:flex;align-items:center;padding:0 16px;z-index:200;box-sizing:border-box}
.nui-app-header-inner{display:flex;align-items:center;gap:10px;min-width:0}
.nui-app-header-slot{flex:1;display:flex;align-items:center;gap:8px;padding:0 8px;min-width:0}
.nui-app-header-identity{display:flex;flex-direction:column;min-width:0}
.nui-app-header-name{font-size:14px;font-weight:600;color:var(--nui-text,#e4e4e7);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nui-app-header-npub{font-size:11px;color:var(--nui-muted,#71717a);font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nui-app-header-signout{flex-shrink:0;padding:6px 12px;border-radius:6px;border:1px solid var(--nui-border,#27272a);background:transparent;color:var(--nui-muted,#71717a);font-size:12px;cursor:pointer;transition:all .15s;font-family:inherit}
.nui-app-header-signout:hover{color:var(--nui-error,#ef4444);border-color:var(--nui-error,#ef4444)}
`;
}

/**
 * Full-featured login UI. Renders itself into a container element.
 * Handles all connection methods, recent connections with profile avatars,
 * camera QR scanning, deep-link probe, and post-login profile display.
 *
 * @example
 * const ui = new NostrLoginUI(document.getElementById('loginCard'), auth, {
 *   appName: 'My App',
 *   onConnected: (pubkey, profile) => { ... }  // profile may be null on first call
 * });
 * await ui.start();
 */
class NostrLoginUI {
  /**
   * @param {HTMLElement} containerEl
   * @param {NostrAuth}   auth
   * @param {object}      [options]
   * @param {string}      [options.appName='Nostr']
   * @param {string}      [options.appUrl]
   * @param {string[]}    [options.profileRelays=[]] Extra relays appended to auth.relays for profile fetch
   * @param {number}      [options.nip46Timeout=120000]
   * @param {boolean}     [options.useHistory=true]
   * @param {boolean}     [options.allowCamera=true]
   * @param {boolean}     [options.allowDeepLink=true]
   * @param {string}      [options.guestLabel]    HTML for the guest-mode button (default: "Just trying things out? <strong>Use Guest Mode</strong>")
   * @param {string}      [options.guestHint]     Optional muted hint line rendered under the guest button
   * @param {boolean}     [options.showHeader=true]   Mount a fixed app-header bar when connected; set false to suppress (e.g. host page renders its own nav chip)
   * @param {Function}    [options.onHeader]      (slotEl) => void — called once when the header is first created; populate slotEl with custom nav content
 * @param {Function}    [options.onConnected]  (pubkey, profile) => void — fired immediately with cached profile (may be null), again once live profile resolves
   * @param {Function}    [options.onDisconnect] () => void
   * @param {Function}    [options.onError]      (err) => void
   */
  constructor(containerEl, auth, options = {}) {
    this.el  = containerEl;
    this.auth = auth;
    this._appName        = options.appName    || 'Nostr';
    this._appUrl         = options.appUrl     || (typeof window !== 'undefined' ? window.location.origin : '');
    this._profileRelays  = options.profileRelays  || [];
    this._timeout        = options.nip46Timeout   ?? 120000;
    this._useHistory     = options.useHistory     !== false;
    this._allowCamera    = options.allowCamera    !== false;
    this._allowDeepLink  = options.allowDeepLink  !== false;
    this._guestLabel     = options.guestLabel     || `Just trying things out? <strong>Use Guest Mode</strong>`;
    this._guestHint      = options.guestHint      || '';
    this._showHeader     = options.showHeader     !== false;
    this._onHeaderCb     = options.onHeader       || null;
    this._onConnectedCb  = options.onConnected    || null;
    this._onDisconnectCb = options.onDisconnect   || null;
    this._onErrorCb      = options.onError        || null;
    this._recentKey      = auth.storageKey + '_recent';
    this._recentExpanded = false;
    this._pendingLocalKey  = null;
    this._pendingRecentIdx = null;
    this._qrSigner       = null;
    this._scanStream     = null;
    this._scanInterval   = null;
    this._countdownTimer = null;
    this._hasCamera      = null;
    this._view           = null;
    this._popHandler     = null;
    this._injectStyles();
    this._renderCard();
    this._probeCamera();
    this._clickHandler = e => {
      const t = e.target.closest('[data-a]');
      if (!t) return;
      this._dispatch(t.dataset.a, t, e);
    };
    this.el.addEventListener('click', this._clickHandler);
    this._keyHandler = e => {
      if (e.key === 'Enter' && this._view === 'paste')    this._doPasteSubmit();
      if (e.key === 'Enter' && this._view === 'localdev') this._doLocalDevSubmit();
    };
    this.el.addEventListener('keydown', this._keyHandler);
  }

  // ── Public ────────────────────────────────────────────────────────────────

  /** Restore session or show login options. Also polls for late-loading extensions. */
  async start() {
    if (this._useHistory) {
      history.replaceState({ _nuiView: 'options' }, '');
      this._popHandler = e => this._handlePop(e);
      window.addEventListener('popstate', this._popHandler);
    }
    this._migrateRecentStorage();
    if (this.auth.hasSavedSession()) {
      this._showLoading('Restoring session', 'Reconnecting to your signer\u2026');
      try {
        const pubkey = await this.auth.restoreSession(15000);
        if (pubkey) {
          const npub   = encodeNpub(pubkey);
          const recent = this._getRecent();
          const match  = recent.find(b => b.npub === npub);
          const label  = !match || match.type === 'extension' ? null
            : match.signer
              ? `${match.connType === 'nostrconnect' ? 'Nostr Connect' : 'Bunker'}: ${match.signer}`
              : null;
          await this._showConnected(pubkey, label);
          return;
        }
      } catch {}
    }
    this._showOptions();
    this._pollForExtension();
  }

  /** Release event listeners, camera, timers. */
  destroy() {
    this._stopCameraScan();
    this._clearCountdown();
    if (this._popHandler) {
      window.removeEventListener('popstate', this._popHandler);
      this._popHandler = null;
    }
    this.el.removeEventListener('click',   this._clickHandler);
    this.el.removeEventListener('keydown', this._keyHandler);
    if (this._qrSigner) { try { this._qrSigner.disconnect(); } catch {} this._qrSigner = null; }
  }

  // ── Style injection ────────────────────────────────────────────────────────

  _injectStyles() {
    if (NostrLoginUI._stylesInjected) return;
    NostrLoginUI._stylesInjected = true;
    const s = document.createElement('style');
    s.id = 'nui-styles';
    s.textContent = _nuiGetStyles();
    document.head.appendChild(s);
  }

  // ── Card HTML ──────────────────────────────────────────────────────────────

  _renderCard() {
    this.el.innerHTML =
      `<div class='nui-card'>` +
      `<div class='nui-header'><h1 class='nui-title'>Login with Nostr</h1><p class='nui-subtitle'>Choose how to sign in</p></div>` +
      `<div class='nui-status nui-hidden'></div>` +
      `<div class='nui-view-options nui-hidden'>` +
        `<div class='nui-recent-section'></div>` +
        `<div class='nui-group-label'>Connect with Nostr signer</div>` +
        `<div class='nui-connect-opts'></div>` +
        `<div class='nui-guest-section nui-hidden'>` +
          `<button class='nui-guest-btn' data-a='doGuest'>${this._guestLabel}</button>` +
          (this._guestHint ? `<p class='nui-guest-hint'>${this._guestHint}</p>` : ``) +
        `</div>` +
      `</div>` +
      `<div class='nui-view-paste nui-hidden'>` +
        `<input type='text' class='nui-input nui-paste-input' placeholder='bunker:// or nostrconnect://' spellcheck='false' autocomplete='off' style='margin:12px 0;'>` +
        `<label class='nui-label'>Connection Name</label>` +
        `<input type='text' class='nui-input-plain nui-name-input' placeholder='Leave blank for auto-name' spellcheck='false' autocomplete='off'>` +
        `<div class='nui-btn-row'>` +
          `<button class='nui-btn nui-btn-primary' data-a='doPasteSubmit'>Connect</button>` +
          `<button class='nui-btn nui-btn-ghost'   data-a='goBack'>Back</button>` +
        `</div>` +
      `</div>` +
      `<div class='nui-view-qr nui-hidden'>` +
        `<label class='nui-label'>Connection Name</label>` +
        `<input type='text' class='nui-input-plain nui-qr-name' placeholder='Leave blank for auto-name' spellcheck='false' autocomplete='off'>` +
        `<div class='nui-qr-wrap'><div style='background:#fff;padding:16px;border-radius:12px;display:inline-block;'>` +
          `<img class='nui-qr-img' src='' alt='QR' width='200' height='200'></div></div>` +
        `<button class='nui-btn nui-btn-ghost nui-deeplink-qr-btn' data-a='openDeepLinkFromQR' style='width:100%;margin-bottom:12px;display:flex;align-items:center;justify-content:center;gap:8px;'>` +
          `<svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'/><polyline points='15 3 21 3 21 9'/><line x1='10' y1='14' x2='21' y2='3'/></svg>` +
          `Open in Signer Mobile App</button>` +
        `<div class='nui-qr-uri-row'>` +
          `<div class='nui-qr-uri'></div>` +
          `<button class='nui-btn-icon' data-a='copyUri' title='Copy'>` +
            `<svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='9' y='9' width='13' height='13' rx='2'/><path d='M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'/></svg>` +
          `</button>` +
        `</div>` +
        `<p class='nui-qr-status'>Waiting for signer\u2026</p>` +
        `<button class='nui-btn nui-btn-ghost' data-a='cancelQR' style='width:100%;'>Cancel</button>` +
      `</div>` +
      `<div class='nui-view-scan nui-hidden'>` +
        `<div class='nui-scan-wrap'><video class='nui-scan-video' autoplay playsinline muted></video></div>` +
        `<p class='nui-scan-status'>Opening camera\u2026</p>` +
        `<button class='nui-btn nui-btn-ghost' data-a='cancelScan'>Cancel</button>` +
      `</div>` +
      `<div class='nui-view-deeplink nui-hidden'>` +
        `<p class='nui-deeplink-status'>Opening signer app\u2026</p>` +
        `<div class='nui-deeplink-help'>` +
          `<p>This requires a signer app (Amber, Keystache) installed on <strong>this phone</strong>.</p>` +
          `<p style='margin-top:6px;'>On desktop, use <strong>Show QR</strong> or <strong>Paste URL</strong> instead.</p>` +
        `</div>` +
        `<button class='nui-btn nui-btn-ghost' data-a='goBack'>Back</button>` +
      `</div>` +
      `<div class='nui-view-localdev nui-hidden'>` +
        `<p style='font-size:12px;color:var(--nui-error,#ef4444);margin-bottom:10px;font-weight:600;'>⚠️ Development use only. Do not import real keys.</p>` +
        `<textarea class='nui-input nui-localdev-input' rows='3' placeholder='nsec1… or 64-char hex private key' spellcheck='false' autocomplete='off' style='resize:none;margin-bottom:12px;'></textarea>` +
        `<div class='nui-btn-row'>` +
          `<button class='nui-btn nui-btn-primary' data-a='doLocalDevSubmit'>Connect</button>` +
          `<button class='nui-btn nui-btn-ghost'   data-a='doLocalDevGenerate'>Generate New</button>` +
        `</div>` +
        `<div style='margin-top:10px;'>` +
          `<button class='nui-btn nui-btn-ghost' data-a='goBack' style='width:100%;'>Back</button>` +
        `</div>` +
      `</div>` +
      `</div>`;
  }

  // ── DOM helpers ────────────────────────────────────────────────────────────

  _q(sel)  { return this.el.querySelector(sel); }

  _setTitle(title, subtitle) {
    this._q('.nui-title').textContent    = title;
    this._q('.nui-subtitle').textContent = subtitle || '';
  }

  _hideAll() {
    this._q('.nui-status').classList.add('nui-hidden');
    for (const v of ['options', 'paste', 'qr', 'scan', 'deeplink', 'localdev'])
      this._q(`.nui-view-${v}`)?.classList.add('nui-hidden');
    this._stopCameraScan();
  }

  _showView(name) {
    this._hideAll();
    this._view = name;
    this._q(`.nui-view-${name}`)?.classList.remove('nui-hidden');
  }

  // ── Status displays ────────────────────────────────────────────────────────

  _showLoading(step, detail) {
    this._clearCountdown();
    this._hideAll();
    this._setTitle(step, detail || '');
    const s = this._q('.nui-status');
    s.className = 'nui-status nui-loading';
    s.innerHTML = `<div class='nui-spinner'></div>`;
    s.classList.remove('nui-hidden');
  }

  _showError(msg) {
    const s = this._q('.nui-status');
    s.className = 'nui-status nui-error';
    s.innerHTML = `<div class='nui-status-step'>${_nuiE(msg)}</div>`;
    s.classList.remove('nui-hidden');
    this._onErrorCb?.(new Error(msg));
  }

  _showApproval(authUrl, timeoutSec) {
    this._clearCountdown();
    this._hideAll();
    this._setTitle('Approve Connection', 'Open your signer app and approve');
    let remaining = timeoutSec;
    const render = () => {
      const m  = Math.floor(remaining / 60);
      const ss = remaining % 60;
      const ts = `${m}:${String(ss).padStart(2, '0')}`;
      const s  = this._q('.nui-status');
      s.className = 'nui-status nui-approval';
      s.innerHTML = `<div class='nui-countdown-num'>${ts}</div>` +
        (authUrl && /^https?:\/\//i.test(authUrl) ? `<div class='nui-status-detail'><a href='${_nuiE(authUrl)}' target='_blank' rel='noopener'>Open signer app &rarr;</a></div>` : '');
      s.classList.remove('nui-hidden');
    };
    render();
    this._countdownTimer = setInterval(() => {
      remaining--;
      if (remaining <= 0) { this._clearCountdown(); return; }
      render();
    }, 1000);
  }

  _clearCountdown() {
    if (this._countdownTimer) { clearInterval(this._countdownTimer); this._countdownTimer = null; }
  }

  // ── Views ──────────────────────────────────────────────────────────────────

  _showOptions(fromPop) {
    this._recentExpanded = false;
    this._clearCountdown();
    this._hideAll();
    this.el.classList.remove('nui-hidden'); // un-hide card (e.g. after back-button logout)
    this._setTitle('Login with Nostr', 'Choose how to sign in');
    this._q('.nui-view-options').classList.remove('nui-hidden');
    this._view = 'options';
    if (!fromPop && this._useHistory) this._pushHistory('options');
    this._renderConnectOpts();
    this._renderRecentSection();
    if (this.auth.allowGuestMode) this._q('.nui-guest-section').classList.remove('nui-hidden');
  }

  _showPaste(fromPop) {
    this._clearCountdown();
    this._hideAll();
    this._setTitle('Connect', 'Paste a bunker:// or nostrconnect:// URL');
    this._q('.nui-view-paste').classList.remove('nui-hidden');
    this._view = 'paste';
    this._pendingLocalKey = null;
    this._q('.nui-name-input').value = '';
    if (!fromPop && this._useHistory) this._pushHistory('paste');
    this._q('.nui-paste-input').focus();
  }

  async _showConnected(pubkey) {
    this._clearCountdown();
    this._connected = true;
    const npub = encodeNpub(pubkey);
    // Hide the login card — caller owns the connected UI
    this.el.classList.add('nui-hidden');
    // Render header and fire callback immediately with whatever is cached
    const cached = getCachedProfile(pubkey);
    _nuiLog('_showConnected pubkey:', pubkey.slice(0,8)+'\u2026', '| cached:', cached ? (cached.display_name||cached.name||'no name') : 'null');
    this._renderHeader(pubkey, npub, cached);
    this._onConnectedCb?.(pubkey, cached);
    // Fetch fresh profile in background; re-render header and re-invoke callback when it arrives
    const allRelays = [...new Set([...this.auth.relays, ...this._profileRelays])];
    _nuiLog('_showConnected fetching profile on relays:', allRelays);
    fetchProfile(pubkey, allRelays, 8000).then(profile => {
      _nuiLog('_showConnected fetchProfile resolved:', profile ? (profile.display_name||profile.name||'no name') : 'null');
      if (profile && this._connected) {
        setCachedProfile(pubkey, profile);
        this._renderHeader(pubkey, npub, profile);
        this._onConnectedCb?.(pubkey, profile);
      }
    }).catch(err => { _nuiLog('_showConnected fetchProfile error:', err?.message); });
  }

  /** Re-surface the login card. Call this (after auth.logoutAll()) to let the user switch accounts. */
  showLogin() {
    this._connected = false;
    this._removeHeader();
    this.el.classList.remove('nui-hidden');
    this._showOptions();
  }

  // ── Event dispatch ─────────────────────────────────────────────────────────

  _dispatch(action, target, e) {
    switch (action) {
      case 'doExtension':        this._doExtension(); break;
      case 'doQR':               this._doQR(); break;
      case 'doScanQR':           this._doScanQR(); break;
      case 'doDeepLink':         this._doDeepLink(); break;
      case 'doPaste':            this._showPaste(); break;
      case 'doPasteSubmit':      this._doPasteSubmit(); break;
      case 'cancelQR':           this._cancelQR(); break;
      case 'cancelScan':         this._cancelScan(); break;
      case 'goBack':             this._goBack(); break;
      case 'doGuest':            this._doGuest(); break;
      case 'doDisconnect':       this._doDisconnect(); break;
      case 'copyUri':            this._copyUri(); break;
      case 'openDeepLinkFromQR': this._openDeepLinkFromQR(); break;
      case 'useRecent':          this._useRecent(parseInt(target.dataset.idx)); break;
      case 'removeRecent':       e.stopPropagation(); this._removeRecent(parseInt(target.dataset.idx)); break;
      case 'expandRecent':       this._recentExpanded = true; this._renderRecentSection(); break;
      case 'doLocalDev':         this._doLocalDev(); break;
      case 'doLocalDevSubmit':   this._doLocalDevSubmit(); break;
      case 'doLocalDevGenerate': this._doLocalDevGenerate(); break;
    }
  }

  // ── Actions ────────────────────────────────────────────────────────────────

  async _doExtension() {
    this._showLoading('Connecting', 'Waiting for browser extension\u2026');
    try {
      const pubkey = await this.auth.connectExtension();
      this._saveRecentExtension(pubkey);
      this._pendingRecentIdx = null; // fresh entry already unshifted; marking by the stale pre-reorder index corrupted an unrelated row
      await this._showConnected(pubkey);
    } catch (e) {
      if (this._pendingRecentIdx !== null) { this._markRecentFailed(this._pendingRecentIdx); this._pendingRecentIdx = null; }
      this._showOptions(); this._showError(this._friendlyError(e));
    }
  }

  async _doPasteSubmit() {
    const raw     = this._q('.nui-paste-input').value.trim();
    const nameVal = this._q('.nui-name-input').value.trim();
    if (!raw) return;
    let uri = raw.startsWith('nostrconnect://') ? raw.replace('nostrconnect://', 'bunker://') : raw;
    if (!uri.startsWith('bunker://')) {
      this._showError('Paste a bunker:// or nostrconnect:// URL from your signer'); return;
    }
    const localKey = this._pendingLocalKey ? hexToBytes(this._pendingLocalKey) : null;
    this._pendingLocalKey = null;
    this._showLoading('Connecting', 'Reaching remote signer via relay\u2026');
    try {
      const pubkey = await this.auth.connectBunker(uri, this._timeout, {
        localPrivateKey: localKey,
        onAuthUrl: url => this._showApproval(url, 120),
      });
      this._clearCountdown();
      const signer      = this.auth.getActiveSigner();
      const keyHex      = signer?.localPrivateKey ? bytesToHex(signer.localPrivateKey) : null;
      const ephemPub    = keyHex ? bytesToHex(getPublicKey(hexToBytes(keyHex))) : pubkey;
      const displayName = nameVal || encodeNpub(ephemPub).slice(0, 12);
      this._saveRecentBunker(raw, keyHex, displayName, 'bunker', pubkey);
      this._pendingRecentIdx = null; // fresh entry already unshifted; marking by the stale pre-reorder index corrupted an unrelated row
      await this._showConnected(pubkey, `Bunker: ${displayName}`);
    } catch (e) {
      this._clearCountdown();
      if (this._pendingRecentIdx !== null) { this._markRecentFailed(this._pendingRecentIdx); this._pendingRecentIdx = null; }
      this._showOptions(); this._showError(this._friendlyError(e));
    }
  }

  async _doQR() {
    this._showView('qr');
    this._setTitle('Nostr Connect', 'Scan QR, open signer, or copy the string');
    this._q('.nui-qr-name').value = '';
    this._q('.nui-qr-status').textContent = 'Generating\u2026';
    if (this._useHistory) this._pushHistory('qr');
    try {
      const session = this.auth.createNip46Session({ name: this._appName, url: this._appUrl });
      this._qrSigner = session.signer;
      this._q('.nui-qr-uri').textContent = session.uri;
      this._q('.nui-deeplink-qr-btn').dataset.uri = session.uri;
      this._q('.nui-qr-img').src = generateQRCode(session.uri, 5, 4, true);
      this._q('.nui-qr-status').textContent = 'Waiting for signer\u2026';
      session.signer.onAuthUrl = url => this._showApproval(url, 120);
      const pubkey = await this.auth.finalizeNip46(session.signer, this._timeout, stage => {
        if (stage === 'connected') this._showLoading('Signer connected', 'Getting your identity\u2026');
      });
      const nameVal    = this._q('.nui-qr-name')?.value?.trim() || '';
      const sig        = this._qrSigner;
      const keyHex     = sig?.localPrivateKey ? bytesToHex(sig.localPrivateKey) : null;
      const ephemPub   = keyHex ? bytesToHex(getPublicKey(hexToBytes(keyHex))) : pubkey;
      const displayName = nameVal || encodeNpub(ephemPub).slice(0, 12);
      if (sig?.remotePubkey && sig?.relays) {
        const params = sig.relays.map(r => 'relay=' + encodeURIComponent(r)).join('&');
        this._saveRecentBunker(`bunker://${sig.remotePubkey}?${params}`, keyHex, displayName, 'nostrconnect', pubkey);
      }
      await this._showConnected(pubkey, `Nostr Connect: ${displayName}`);
    } catch (e) {
      if (e.message?.includes('cancelled')) return;
      this._showOptions(); this._showError(this._friendlyError(e));
    }
  }

  _cancelQR() {
    if (this._qrSigner) { try { this._qrSigner.disconnect(); } catch {} this._qrSigner = null; }
    this._goBack();
  }

  async _doScanQR() {
    if (!this._allowCamera) return;
    if (typeof BarcodeDetector === 'undefined') {
      this._showOptions();
      this._showError('Camera scanning not supported in this browser. Paste a connection URL instead.');
      return;
    }
    this._showView('scan');
    this._setTitle('Scan QR', 'Point camera at your signer\u2019s QR code');
    if (this._useHistory) this._pushHistory('scan');
    const statusEl = this._q('.nui-scan-status');
    statusEl.textContent  = 'Opening camera\u2026';
    statusEl.style.color  = '';
    try {
      this._scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      const video = this._q('.nui-scan-video');
      video.srcObject = this._scanStream;
      await video.play();
      statusEl.textContent = 'Scanning\u2026';
      const detector = new BarcodeDetector({ formats: ['qr_code'] });
      this._scanInterval = setInterval(async () => {
        try {
          const codes = await detector.detect(video);
          for (const bc of codes) {
            const val = bc.rawValue;
            if (val && (val.startsWith('bunker://') || val.startsWith('nostrconnect://'))) {
              this._stopCameraScan();
              this._q('.nui-paste-input').value = val;
              this._q('.nui-name-input').value  = '';
              this._doPasteSubmit();
              return;
            }
          }
        } catch {}
      }, 300);
    } catch (e) {
      this._stopCameraScan(); this._showOptions();
      this._showError(e.name === 'NotAllowedError'
        ? 'Camera access denied. Paste a connection URL instead.'
        : 'Camera error: ' + e.message);
    }
  }

  _cancelScan() { this._stopCameraScan(); this._goBack(); }

  async _doDeepLink() {
    if (!this._allowDeepLink) return;
    this._hideAll();
    this._setTitle('Open Signer Mobile App', 'Launching on this device\u2026');
    this._q('.nui-view-deeplink').classList.remove('nui-hidden');
    this._view = 'deeplink';
    if (this._useHistory) this._pushHistory('deeplink');
    try {
      const session  = this.auth.createNip46Session({ name: this._appName, url: this._appUrl });
      const statusEl = this._q('.nui-deeplink-status');
      const helpEl   = this._q('.nui-deeplink-help');
      let opened = false;
      const onVis = () => { if (document.visibilityState === 'hidden') opened = true; };
      document.addEventListener('visibilitychange', onVis);
      window.location.href = session.uri;
      setTimeout(() => {
        document.removeEventListener('visibilitychange', onVis);
        if (!opened) {
          statusEl.textContent = 'No signer app found on this device.';
          statusEl.style.color = 'var(--nui-error,#ef4444)';
          helpEl.innerHTML =
            '<p>A signer app like <strong>Amber</strong> (Android) or <strong>Keystache</strong> (iOS) must be installed.</p>' +
            '<p style=\'margin-top:6px;\'>On desktop, go back and use <strong>Show QR</strong> or <strong>Paste URL</strong>.</p>';
        } else {
          statusEl.textContent = 'Waiting for signer to approve\u2026';
        }
      }, 1500);
      session.signer.onAuthUrl = url => this._showApproval(url, 120);
      const pubkey = await this.auth.finalizeNip46(session.signer, this._timeout, stage => {
        if (stage === 'connected') this._showLoading('Signer connected', 'Getting your identity\u2026');
      });
      const signer      = session.signer;
      const keyHex      = signer?.localPrivateKey ? bytesToHex(signer.localPrivateKey) : null;
      const ephemPub    = keyHex ? bytesToHex(getPublicKey(hexToBytes(keyHex))) : pubkey;
      const displayName = encodeNpub(ephemPub).slice(0, 12);
      if (signer?.remotePubkey && signer?.relays) {
        const params = signer.relays.map(r => 'relay=' + encodeURIComponent(r)).join('&');
        this._saveRecentBunker(`bunker://${signer.remotePubkey}?${params}`, keyHex, displayName, 'nostrconnect', pubkey);
      }
      await this._showConnected(pubkey, `Nostr Connect: ${displayName}`);
    } catch (e) {
      if (e.message?.includes('cancelled')) return;
      this._showOptions(); this._showError(this._friendlyError(e));
    }
  }

  _doGuest() {
    try {
      const pubkey = this.auth.connectGuest();
      this._saveRecentGuest(pubkey);
      this._showConnected(pubkey, 'Guest Mode');
    } catch (e) { this._showOptions(); this._showError(this._friendlyError(e)); }
  }

  _renderHeader(pubkey, npub, profile) {
    if (!this._showHeader) return;
    if (!this._headerEl) {
      this._headerEl = document.createElement('header');
      this._headerEl.className = 'nui-app-header';
      // Chip container — only this is rewritten on profile re-renders
      const inner = document.createElement('div');
      inner.className = 'nui-app-header-inner';
      this._headerEl.appendChild(inner);
      // Slot — stable; caller populates via onHeader callback
      const slot = document.createElement('div');
      slot.className = 'nui-app-header-slot';
      this._headerEl.appendChild(slot);
      // Sign-out — stable; listener attached once
      const signOut = document.createElement('button');
      signOut.className = 'nui-app-header-signout';
      signOut.textContent = 'Sign out';
      signOut.addEventListener('click', () => this._doDisconnect());
      this._headerEl.appendChild(signOut);
      document.body.appendChild(this._headerEl);
      document.body.style.paddingTop = '52px';
      this._onHeaderCb?.(slot);
    }
    // Update identity chip only — slot and sign-out are untouched
    const shortNpub = npub ? npub.slice(0, 12) + '\u2026' + npub.slice(-6) : '';
    const name      = nuiDisplayName(profile, npub);
    const avatar    = nuiAvatarHtml(profile, pubkey, 32);
    this._headerEl.querySelector('.nui-app-header-inner').innerHTML =
      avatar +
      `<div class='nui-app-header-identity'>` +
        `<span class='nui-app-header-name'>${_nuiE(name)}</span>` +
        `<span class='nui-app-header-npub'>${_nuiE(shortNpub)}</span>` +
      `</div>`;
  }

  _removeHeader() {
    if (!this._showHeader) return;
    if (this._headerEl) {
      this._headerEl.remove();
      this._headerEl = null;
      document.body.style.paddingTop = '';
    }
  }
  _doDisconnect() {
    this.auth.logoutAll();
    this._onDisconnectCb?.();
    this.showLogin();
  }

  // ── QR helpers ─────────────────────────────────────────────────────────────

  _copyUri() {
    const uri = this._q('.nui-qr-uri').textContent;
    const btn = this._q('[data-a=\'copyUri\']');
    navigator.clipboard.writeText(uri).then(() => {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='var(--nui-success,#22c55e)' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='20 6 9 17 4 12'/></svg>`;
      setTimeout(() => { btn.innerHTML = orig; }, 1500);
    }).catch(() => {});
  }

  _openDeepLinkFromQR() {
    const uri = this._q('.nui-deeplink-qr-btn')?.dataset?.uri;
    if (!uri) return;
    let opened = false;
    const onVis = () => { if (document.visibilityState === 'hidden') opened = true; };
    document.addEventListener('visibilitychange', onVis);
    window.location.href = uri;
    setTimeout(() => {
      document.removeEventListener('visibilitychange', onVis);
      if (!opened) {
        const s = this._q('.nui-qr-status');
        if (s) { s.textContent = 'No signer responded. Copy the string or scan QR from another device.'; s.style.color = 'var(--nui-error,#ef4444)'; }
      }
    }, 1500);
  }

  // ── Camera ─────────────────────────────────────────────────────────────────

  _stopCameraScan() {
    if (this._scanInterval) { clearInterval(this._scanInterval); this._scanInterval = null; }
    if (this._scanStream)   { this._scanStream.getTracks().forEach(t => t.stop()); this._scanStream = null; }
    const video = this._q('.nui-scan-video');
    if (video) video.srcObject = null;
  }

  async _probeCamera() {
    try {
      if (!navigator.mediaDevices?.enumerateDevices) { this._hasCamera = false; return; }
      const devs = await navigator.mediaDevices.enumerateDevices();
      this._hasCamera = devs.some(d => d.kind === 'videoinput');
    } catch { this._hasCamera = false; }
  }

  // ── Connect options ────────────────────────────────────────────────────────

  _getConnectOrder() {
    let order;
    if (this.auth.hasNip07()) {
      order = ['extension', 'showqr', 'paste', 'scanqr', 'deeplink'];
    } else if (detectPlatform().isMobile) {
      order = ['deeplink', 'paste', 'showqr', 'scanqr', 'extension'];
    } else {
      order = ['showqr', 'paste', 'deeplink', 'scanqr', 'extension'];
    }
    if (this._hasCamera === false) {
      order = order.filter(k => k !== 'scanqr');
      const ei = order.indexOf('extension');
      if (ei !== -1 && !this.auth.hasNip07()) order.splice(ei, 0, 'scanqr');
      else order.push('scanqr');
    }
    if (!this._allowDeepLink) order = order.filter(k => k !== 'deeplink');
    if (!this._allowCamera)   order = order.filter(k => k !== 'scanqr');
    if (this.auth.allowLocalDev && !order.includes('localdev')) order.push('localdev');
    return order;
  }

  _renderConnectOpts() {
    const OPTS = {
      extension: { label: 'Desktop Browser Extension', hint: 'nos2x, Alby, Flamingo', disabledHint: 'No extension detected', action: 'doExtension',
        icon: `<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z'/></svg>` },
      deeplink: { label: 'Open in Signer Mobile App', hint: 'Amber, Keystache, or other mobile signer', action: 'doDeepLink',
        icon: `<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'/><polyline points='15 3 21 3 21 9'/><line x1='10' y1='14' x2='21' y2='3'/></svg>` },
      showqr:  { label: 'Show QR for Mobile Signer', hint: 'Display a QR code for your mobile signer to scan', action: 'doQR',
        icon: `<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='3' width='7' height='7'/><rect x='14' y='3' width='7' height='7'/><rect x='3' y='14' width='7' height='7'/><rect x='14' y='14' width='3' height='3'/></svg>` },
      scanqr:  { label: 'Scan Signer\u2019s QR Code', hint: 'Point this device\u2019s camera at your signer\u2019s QR', action: 'doScanQR',
        icon: `<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z'/><circle cx='12' cy='13' r='4'/></svg>` },
      paste:   { label: 'Paste Connection URL', hint: 'Paste a bunker:// or nostrconnect:// URL', action: 'doPaste',
        icon: `<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2'/><rect x='8' y='2' width='8' height='4' rx='1'/></svg>` },
      localdev: { label: 'Local Dev Key (nsec/hex)', hint: 'Development only — directly import a private key', action: 'doLocalDev',
        icon: `<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='11' width='18' height='11' rx='2'/><path d='M7 11V7a5 5 0 0 1 10 0v4'/></svg>` },
    };
    const order = this._getConnectOrder();
    this._q('.nui-connect-opts').innerHTML = order.map(key => {
      const o       = OPTS[key];
      const noCamera = key === 'scanqr'    && this._hasCamera === false;
      const noExt    = key === 'extension' && !this.auth.hasNip07();
      const disabled = noCamera || noExt;
      const hint     = noExt ? (o.disabledHint || o.hint) : noCamera ? 'No camera detected' : o.hint;
      return `<button class='nui-opt-btn' data-a='${o.action}' ${disabled ? 'disabled' : ''} style='${disabled ? 'opacity:.45;' : ''}'>` +
        `<span class='nui-opt-icon'>${o.icon}</span>` +
        `<span class='nui-opt-label'>${_nuiE(o.label)}<small class='nui-opt-hint'>${_nuiE(hint)}</small></span>` +
        `</button>`;
    }).join('');
  }

  // ── Recent connections ─────────────────────────────────────────────────────

  _getRecent()         { try { return JSON.parse(localStorage.getItem(this._recentKey) || '[]'); } catch { return []; } }
  _setRecent(list)     { localStorage.setItem(this._recentKey, JSON.stringify(list)); }

  _saveRecentBunker(raw, localKeyHex, displayName, connType, userPubkey) {
    let name = null, npub = null, strippedUri = raw;
    try {
      const u = new URL(raw.replace('nostrconnect://', 'bunker://'));
      name = u.searchParams.get('name') || null;
      u.searchParams.delete('secret');
      if (u.hostname?.length === 64) npub = encodeNpub(u.hostname);
      strippedUri = u.toString();
    } catch {}
    let list = this._getRecent();
    const ct = connType || 'bunker';
    if (ct === 'nostrconnect' && localKeyHex) {
      list = list.filter(b => b.key !== localKeyHex);
    } else if (npub) {
      list = list.filter(b => !(b.npub === npub && b.type !== 'extension' && (b.connType || 'bunker') === ct));
    } else {
      list = list.filter(b => b.uri !== strippedUri);
    }
    const entry = { uri: strippedUri, signer: displayName || name || null, connType: ct, npub: npub || null, ts: Date.now() };
    if (localKeyHex) entry.key = localKeyHex;
    if (userPubkey)  entry.userNpub = encodeNpub(userPubkey);
    _nuiLog('saveRecent', ct, 'signer npub:', npub, 'user npub:', entry.userNpub || '(none)');
    list.unshift(entry);
    if (list.length > 10) list.length = 10;
    this._setRecent(list);
  }

  _saveRecentExtension(pubkey) {
    const npub = encodeNpub(pubkey);
    let list = this._getRecent();
    list = list.filter(b => !(b.type === 'extension' && b.npub === npub));
    list.unshift({ type: 'extension', signer: 'Browser Extension', npub, ts: Date.now() });
    if (list.length > 10) list.length = 10;
    this._setRecent(list);
  }

  _saveRecentGuest(pubkey) {
    const npub = encodeNpub(pubkey);
    let list = this._getRecent();
    list = list.filter(b => b.type !== 'guest');
    list.unshift({ type: 'guest', signer: 'Guest Mode', npub, ts: Date.now() });
    if (list.length > 10) list.length = 10;
    this._setRecent(list);
  }

  _removeRecent(idx)       { const l = this._getRecent(); l.splice(idx, 1); this._setRecent(l); this._renderRecentSection(); }
  _markRecentFailed(idx)   { const l = this._getRecent(); if (l[idx]) { l[idx].lastFailed = Date.now(); this._setRecent(l); } }
  _markRecentSuccess(idx)  { const l = this._getRecent(); if (l[idx]) { l[idx].lastFailed = null; l[idx].ts = Date.now(); this._setRecent(l); } }

  _useRecent(idx) {
    const entry = this._getRecent()[idx];
    if (!entry) return;
    this._pendingRecentIdx = idx;
    if (entry.type === 'guest') {
      this._doGuest();
    } else if (entry.type === 'extension') {
      this._doExtension();
    } else if (entry.uri) {
      this._q('.nui-paste-input').value = entry.uri;
      this._q('.nui-name-input').value  = (entry.signer && entry.signer !== 'Remote Signer') ? entry.signer : '';
      this._pendingLocalKey = entry.key || null;
      this._doPasteSubmit();
    }
  }

  _renderRecentSection() {
    const list = this._getRecent();
    const el   = this._q('.nui-recent-section');
    if (!list.length) { el.innerHTML = ''; return; }
    const sorted = list.map((b, i) => ({ ...b, _idx: i }));
    sorted.sort((a, b) => {
      const af = !!a.lastFailed, bf = !!b.lastFailed;
      if (af !== bf) return af ? 1 : -1;
      return (b.ts || 0) - (a.ts || 0);
    });
    const VISIBLE = 2;
    const visible = this._recentExpanded ? sorted : sorted.slice(0, VISIBLE);
    const hasMore = sorted.length > VISIBLE && !this._recentExpanded;
    const renderItem = b => {
      const i = b._idx;
      // userNpub is the actual identity key; npub may be the signer/bunker key
      const lookupNpub = b.userNpub || b.npub;
      const pubkeyHex  = lookupNpub ? (() => { try { return decodeNpub(lookupNpub); } catch { return null; } })() : null;
      const profile    = pubkeyHex ? getCachedProfile(pubkeyHex) : null;
      _nuiLog('recent[' + b._idx + ']', b.signer || b.type,
        '| lookupNpub:', lookupNpub?.slice(0, 16) + '…',
        '| cached:', profile ? (profile.display_name || profile.name || 'no name') : 'null');
      const typeLabel = b.type === 'guest' ? 'Guest Mode' : b.type === 'extension' ? 'Extension'
        : b.connType === 'nostrconnect' ? 'Nostr Connect' : 'Bunker';
      // Prefer profile display name; fall back to connection label
      const signerName = profile
        ? nuiDisplayName(profile, b.npub || '')
        : (b.type === 'guest' ? 'Guest Mode' : b.type === 'extension' ? 'Browser Extension' : b.signer ? `${typeLabel}: ${b.signer}` : typeLabel);
      const shortNpub = b.connType === 'nostrconnect'
        ? (b.key ? encodeNpub(b.key).slice(0, 16) + '\u2026' : '')
        : (b.npub ? b.npub.slice(0, 16) + '\u2026' : '');
      const ago        = b.ts ? _nuiTimeAgo(b.ts) : '';
      const failStyle  = b.lastFailed ? 'opacity:.5;' : '';
      const failBadge  = b.lastFailed ? `<span style='color:var(--nui-error,#ef4444);font-size:10px;margin-left:4px;'>failed</span>` : '';
      const avatar     = nuiAvatarHtml(profile, pubkeyHex, 28);
      return `<div class='nui-recent-item' style='${failStyle}' data-a='useRecent' data-idx='${i}'>` +
        avatar +
        `<div class='nui-recent-body'>` +
          `<div class='nui-recent-name'>${_nuiE(signerName)}${failBadge}</div>` +
          `<div class='nui-recent-sub'>` +
            (!profile && shortNpub ? `<span>${_nuiE(shortNpub)}</span>` : '') +
            (ago ? `<span style='margin-left:auto;'>${_nuiE(ago)}</span>` : '') +
          `</div>` +
        `</div>` +
        `<svg class='nui-recent-arrow' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M9 18l6-6-6-6'/></svg>` +
        `<button class='nui-recent-remove' data-a='removeRecent' data-idx='${i}' title='Remove'>` +
          `<svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5' stroke-linecap='round'><path d='M18 6L6 18M6 6l12 12'/></svg>` +
        `</button>` +
        `</div>`;
    };
    const moreBtn = hasMore
      ? `<button class='nui-more-btn' data-a='expandRecent'>${sorted.length - VISIBLE} more\u2026</button>`
      : '';
    el.innerHTML = '<div class=\'nui-recent-label\'>Recent</div>' + visible.map(renderItem).join('') + moreBtn;
  }


  // ── History ────────────────────────────────────────────────────────────────

  _pushHistory(view) {
    if (!this._useHistory) return;
    if (history.state?._nuiView !== view) history.pushState({ _nuiView: view }, '');
  }

  _goBack() {
    if (this._useHistory) history.back();
    else this._showOptions();
  }

  _handlePop(e) {
    this._stopCameraScan();
    if (this.auth.getActiveSigner()?.connected) {
      this.auth.logoutAll();
      this._removeHeader();
      this._onDisconnectCb?.();
      this._connected = false;
    }
    const view = e.state?._nuiView || 'options';
    if (view === 'paste') this._showPaste(true);
    else this._showOptions(true);
  }

  // ── Misc ───────────────────────────────────────────────────────────────────

  // ── Local dev key ──────────────────────────────────────────────────────────

  _doLocalDev() {
    if (!this.auth.allowLocalDev) return;
    this._clearCountdown();
    this._hideAll();
    this._setTitle('Local Dev Key', 'Paste an nsec or hex private key — development only');
    this._q('.nui-view-localdev').classList.remove('nui-hidden');
    this._view = 'localdev';
    if (this._useHistory) this._pushHistory('localdev');
    this._q('.nui-localdev-input').value = '';
    this._q('.nui-localdev-input').focus();
  }

  async _doLocalDevSubmit() {
    const raw = this._q('.nui-localdev-input').value.trim();
    if (!raw) return;
    this._showLoading('Connecting', 'Loading local key…');
    try {
      const pubkey = this.auth.addLocalSigner(raw);
      await this._showConnected(pubkey, 'Local Dev Key');
    } catch (e) {
      this._doLocalDev();
      this._showError(e.message || 'Invalid key');
    }
  }

  async _doLocalDevGenerate() {
    this._showLoading('Generating', 'Creating new keypair…');
    try {
      const { pubkey, nsec } = this.auth.generateLocalSigner();
      // generateLocalSigner already stored the signer; just show it
      this._doLocalDev();
      const el = this._q('.nui-localdev-input');
      if (el) {
        el.value = nsec;
        el.style.borderColor = 'var(--nui-success,#22c55e)';
        setTimeout(() => { el.style.borderColor = ''; }, 2000);
      }
      await this._showConnected(pubkey, 'Local Dev Key');
    } catch (e) {
      this._showOptions(); this._showError(this._friendlyError(e));
    }
  }
  _friendlyError(e) {
    const m = (e.message || String(e)).toLowerCase();
    if (m.includes('timeout') || m.includes('no response')) return e.message;
    if (m.includes('invalid secret')) return 'This bunker URL has already been used. Secrets are single-use. Generate a new URL in your signer app.';
    if (m.includes('relay') && m.includes('fail')) return 'Could not reach the relay. Check your internet connection and try again.';
    if (m.includes('rejected') || m.includes('denied') || m.includes('refused')) return 'The signer rejected the request. Try again or check your signer app.';
    if (m.includes('no permission')) return 'The signer denied permission. Reconnect and approve the requested permissions.';
    return e.message || 'Something went wrong. Please try again.';
  }

  _pollForExtension() {
    if (this.auth.hasNip07()) return;
    let n = 0;
    const poll = setInterval(() => {
      n++;
      if (this.auth.hasNip07()) { this._renderConnectOpts(); clearInterval(poll); }
      else if (n >= 20) clearInterval(poll);
    }, 100);
  }

  _migrateRecentStorage() {
    const OLD = 'nostr_recent_bunkers';
    const old = localStorage.getItem(OLD);
    if (old && !localStorage.getItem(this._recentKey)) {
      localStorage.setItem(this._recentKey, old);
      localStorage.removeItem(OLD);
    }
  }
}

/** @private */
NostrLoginUI._stylesInjected = false;

/** @private */
function _nuiTimeAgo(ts) {
  const sec = Math.floor((Date.now() - ts) / 1000);
  if (sec < 60)  return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60)  return `${min}m ago`;
  const hr  = Math.floor(min / 60);
  if (hr  < 24)  return `${hr}h ago`;
  const d   = Math.floor(hr  / 24);
  if (d   < 30)  return `${d}d ago`;
  return new Date(ts).toLocaleDateString();
}
// ============================================================================
// EXPORTS
// ============================================================================

export {
  // Main Auth Manager
  NostrAuth,

  // Login UI
  NostrLoginFlow,
  LoginState,
  NostrLoginUI,

  // Profile utilities
  fetchProfile,
  getCachedProfile,
  setCachedProfile,
  setProfileOverride,

  // Profile rendering helpers
  nuiAvatarHtml,
  nuiDisplayName,

  // QR Code
  generateQRCode,
  generateQRCodeSVG,

  // Signers
  BaseSigner,
  Nip07Signer,
  Nip46Signer,
  LocalSigner,

  // Relay Pool
  RelayPool,

  // Event handling
  createEvent,
  signEvent,
  verifyEvent,
  getEventHash,

  // NIP-98 HTTP Auth
  createNip98Event,
  signNip98,

  // Crypto utilities
  generatePrivateKey,
  getPublicKey,
  hexToBytes,
  bytesToHex,

  // Encoding
  encodeNpub,
  encodeNsec,
  decodeNpub,
  decodeNsec,

  // NIP-04
  nip04Encrypt,
  nip04Decrypt,

  // NIP-44
  nip44Encrypt,
  nip44Decrypt,

  // Error types
  NostrError,
  TimeoutError,
  SignerRejectedError,
  RelayError,
  AuthChallengeError,
  InvalidSecretError,

  // Platform detection
  detectPlatform,
  getLoginMethods
};
