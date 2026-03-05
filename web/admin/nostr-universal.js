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

function getPublicKey(privateKey) {
  const sk = bytesToBigInt(privateKey);
  const point = pointMultiply(sk);
  return bigIntToBytes(point[0]);
}

async function taggedHash(tag, ...data) {
  const tagHash = await sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, ...data));
}

async function schnorrSign(message, privateKey) {
  const d = bytesToBigInt(privateKey);
  const P = pointMultiply(d);
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

async function deriveSharedSecret(privateKey, publicKey) {
  const sk = bytesToBigInt(privateKey);
  const pk = bytesToBigInt(publicKey);

  // Lift x to point
  const x = pk;
  const y2 = mod(x ** 3n + 7n);
  let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
  if (y % 2n !== 0n) y = CURVE.P - y; // even y

  const point = [x, y];
  const shared = pointMultiply(sk, point);
  return bigIntToBytes(shared[0]);
}

async function nip04Encrypt(content, privateKey, publicKey) {
  const sharedSecret = await deriveSharedSecret(privateKey, publicKey);
  const iv = getRandomBytes(16);

  const key = await crypto.subtle.importKey(
    'raw', sharedSecret, { name: 'AES-CBC' }, false, ['encrypt']
  );

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

  const key = await crypto.subtle.importKey(
    'raw', sharedSecret, { name: 'AES-CBC' }, false, ['decrypt']
  );

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
 * NIP-44 v2 encryption
 */
async function nip44Encrypt(content, privateKey, publicKey) {
  const plaintext = utf8ToBytes(content);

  // Step 1: Calculate padded length (NIP-44 padding spec)
  // Minimum 32 bytes, round up to next power of 2
  const unpadded = 2 + plaintext.length; // 2 bytes for length prefix
  let paddedLen = 32;
  while (paddedLen < unpadded) paddedLen *= 2;
  if (paddedLen > 65535) throw new Error('Message too long for NIP-44');

  // Step 2: Create padded message: 2-byte BE length + message + zeros
  const padded = new Uint8Array(paddedLen);
  padded[0] = (plaintext.length >> 8) & 0xff;
  padded[1] = plaintext.length & 0xff;
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
  const id = await getEventHash(event);
  const sig = await schnorrSign(hexToBytes(id), privateKey);
  return {
    ...event,
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
// RELAY POOL
// ============================================================================

class RelayPool {
  constructor(options = {}) {
    this.relays = new Map(); // url -> { ws, status, queue, pingInterval }
    this.subscriptions = new Map(); // subId -> { filters, relays, callbacks }
    this.connectionTimeout = options.connectionTimeout || 20000; // 20 seconds
    this.pingInterval = options.pingInterval || 30000; // 30 seconds keepalive
  }

  async connect(url) {
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
      try {
        relay.ws = new WebSocket(url);
      } catch (err) {
        relay.status = 'failed';
        this.relays.delete(url);
        reject(err);
        return;
      }

      const timeout = setTimeout(() => {
        relay.status = 'failed';
        try { relay.ws.close(); } catch (e) {}
        this.relays.delete(url);
        reject(new Error(`Connection timeout: ${url}`));
      }, this.connectionTimeout);

      relay.ws.onopen = () => {
        clearTimeout(timeout);
        relay.status = 'connected';

        // Start keepalive ping
        relay.pingTimer = setInterval(() => {
          if (relay.ws && relay.ws.readyState === WebSocket.OPEN) {
            try {
              // Send a REQ with empty filter that returns nothing - acts as ping
              relay.ws.send(JSON.stringify(['REQ', 'ping_' + Date.now(), { limit: 0 }]));
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
      console.warn(`Relay ${url} failed:`, e.message);
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
          }, 10000);
        });
      })
    );
    return results;
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
      const handler = (data) => {
        if (data[0] === 'EVENT' && data[1] === subId) {
          callbacks.onEvent?.(data[2], url);
        } else if (data[0] === 'EOSE' && data[1] === subId) {
          callbacks.onEose?.(url);
        }
      };
      relay.messageHandlers.add(handler);
      sub.handlers.set(url, handler);

      try {
        relay.ws.send(JSON.stringify(['REQ', subId, ...filters]));
      } catch (e) {
        console.warn(`Failed to send to ${url}:`, e);
      }
    });

    return sub;
  }

  close() {
    this.subscriptions.forEach(sub => sub.close());
    this.relays.forEach(relay => {
      if (relay.pingTimer) clearInterval(relay.pingTimer);
      if (relay.ws) relay.ws.close();
    });
    this.relays.clear();
    this.subscriptions.clear();
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
      throw new Error('No NIP-07 extension found');
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
    if (!window.nostr.nip04) throw new Error('NIP-04 not supported');
    return await window.nostr.nip04.encrypt(pubkey, content);
  }

  async nip04Decrypt(content, pubkey) {
    if (!window.nostr.nip04) throw new Error('NIP-04 not supported');
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
      throw new Error('No remote pubkey - cannot reconnect');
    }

    const timeout = timeoutMs || this.timeout;

    // Connect to relays
    for (const relay of this.relays) {
      try {
        await this.pool.connect(relay);
      } catch (e) {
        console.warn(`Failed to connect to ${relay}:`, e);
      }
    }

    // Start listening for responses
    this._startListening();

    // Send a ping to verify the connection is still valid
    try {
      const result = await this._rpc('ping', [], Math.min(timeout, 10000));
      if (result === 'pong') {
        this.connected = true;
        return this.remotePubkey;
      }
    } catch (e) {
      // Ping failed, but some signers may not implement ping
      // Try get_public_key as a fallback
      try {
        const pubkey = await this._rpc('get_public_key', [], Math.min(timeout, 10000));
        if (pubkey) {
          this.connected = true;
          return this.remotePubkey;
        }
      } catch (e2) {
        this.disconnect();
        throw new Error('Failed to reconnect to signer');
      }
    }

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
      timeout: options.timeout || 60000
    });

    signer.remotePubkey = parsed.pubkey;
    signer.bunkerSecret = parsed.secret;

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
    if (metadata.perms) params.set('perms', metadata.perms);

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

    // Start listening for responses
    this._startListening();

    // Send connect request to the bunker
    const connectParams = [localPubkeyHex];
    if (this.bunkerSecret) {
      connectParams.push(this.bunkerSecret);
    }

    try {
      const result = await this._rpc('connect', connectParams, timeout);

      if (result === 'ack' || result === true || result === 'true') {
        this.connected = true;
        // Request relay switch per NIP-46 spec
        await this.switchRelays();
        return this.remotePubkey;
      } else {
        throw new SignerRejectedError('Bunker rejected connection');
      }
    } catch (e) {
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
        reject(new TimeoutError('Connection timeout - no response from signer'));
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

                // Validate secret if we have one (NIP-46 requirement)
                if (this.connectSecret && msg.params) {
                  const returnedSecret = msg.params[1]; // [pubkey, secret?, perms?]
                  if (returnedSecret !== this.connectSecret) {
                    // Invalid secret - potential spoofing, ignore this message
                    return;
                  }
                }

                this.remotePubkey = event.pubkey;
                await this._sendResponse(msg.id, 'ack');

                resolved = true;
                this.connected = true;
                clearTimeout(timer);
                this._startListening();
                resolve(this.remotePubkey);
                return;
              }

              // Handle ack/secret result (for connect responses)
              if (msg.result) {
                if (resolved) return;

                // Validate secret if we have one (NIP-46 requirement)
                // The result should be the secret we sent, or 'ack' for compatibility
                if (this.connectSecret && msg.result !== this.connectSecret && msg.result !== 'ack') {
                  // Invalid secret - potential spoofing, ignore this message
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
    const encrypted = await nip44Encrypt(
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

    await this.pool.publish(this.relays, event);
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
                // Don't delete the pending request - we'll get another response after auth
                reject(new AuthChallengeError(msg.error, msg.id));
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
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new TimeoutError(`NIP-46 RPC timeout for method: ${method}`));
      }, timeout);

      this.pendingRequests.set(id, {
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        }
      });
    });

    // Now prepare and send the request (NIP-44 encrypted per spec)
    const request = { id, method, params };
    const encrypted = await nip44Encrypt(
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

    await this.pool.publish(this.relays, event);

    return responsePromise;
  }

  async getPublicKey() {
    return await this._rpc('get_public_key');
  }

  async sign(event) {
    const result = await this._rpc('sign_event', [event]);
    // Result might be the signed event or just the signature
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
    if (this.subscription) {
      this.subscription.close();
      this.subscription = null;
    }
    this.pool.close();
    this.connected = false;
    this.remotePubkey = null;
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
      throw new Error('No NIP-07 extension available');
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

    // Request relay switch per NIP-46 spec (signer may want different relays)
    await signer.switchRelays();

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
  async connectBunker(bunkerUri, timeoutMs) {
    // Parse and validate the URI
    const parsed = Nip46Signer.parseURI(bunkerUri);

    if (parsed.type !== 'bunker') {
      throw new Error('Expected bunker:// URI. For nostrconnect://, use createNip46Session()');
    }

    // Create signer from bunker URI
    const signer = Nip46Signer.fromBunkerURI(bunkerUri, {
      timeout: timeoutMs || this.timeout
    });

    // Connect to the bunker
    await signer.connectToBunker(timeoutMs || this.timeout);

    // Get the user's pubkey from the signer
    const pubkey = await signer.getPublicKey();

    this._addAccount(pubkey, signer, 'nip46', {
      remotePubkey: parsed.pubkey,
      bunkerUri: bunkerUri
    });
    this._setActive(pubkey);

    return pubkey;
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
      if (account.type === 'nip46' && account.signer.disconnect) {
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
      if (account.type === 'nip46' && account.signer.disconnect) {
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
    if (!signer) throw new Error('No active signer');
    return await signer.sign(event);
  }

  async getPublicKey() {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('No active signer');
    return await signer.getPublicKey();
  }

  async nip04Encrypt(content, pubkey) {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('No active signer');
    return await signer.nip04Encrypt(content, pubkey);
  }

  async nip04Decrypt(content, pubkey) {
    const signer = this.getActiveSigner();
    if (!signer) throw new Error('No active signer');
    return await signer.nip04Decrypt(content, pubkey);
  }

  // ---------- Session Persistence ----------

  _saveSession() {
    try {
      const data = {
        active: this.activePubkey,
        accounts: Array.from(this.accounts.entries()).map(([pubkey, acc]) => {
          const saved = { pubkey, type: acc.type, metadata: acc.metadata || {} };

          // For NIP-46, save the session credentials (ephemeral key is safe to store)
          if (acc.type === 'nip46' && acc.signer) {
            saved.nip46 = {
              localPrivateKey: bytesToHex(acc.signer.localPrivateKey),
              remotePubkey: acc.signer.remotePubkey,
              relays: acc.signer.relays
            };
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
  async connectBunker(bunkerUri) {
    this._setState(LoginState.CHECKING);

    try {
      // Validate URI format
      const parsed = NostrAuth.parseNip46URI(bunkerUri);

      if (parsed.type === 'nostrconnect') {
        throw new Error('This is a nostrconnect:// URI. Use the QR code flow instead, or provide a bunker:// URI.');
      }

      const pubkey = await this.auth.connectBunker(bunkerUri, this.nip46Timeout);
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
// EXPORTS
// ============================================================================

export {
  // Main Auth Manager
  NostrAuth,

  // Login UI Helper
  NostrLoginFlow,
  LoginState,

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
  InvalidSecretError
};
