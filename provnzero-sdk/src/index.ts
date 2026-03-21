import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";

// --- RFC 9180 HKDF primitives using noble ---
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return new Uint8Array(hmac(sha256, salt.length === 0 ? new Uint8Array(32) : salt, ikm));
}

function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const result = new Uint8Array(length);
  const t = new Uint8Array(32 + info.length + 1);
  let tr = new Uint8Array(0);
  let generated = 0;
  let blockIndex = 1;

  while (generated < length) {
    t.set(tr, 0);
    t.set(info, tr.length);
    t.set([blockIndex], tr.length + info.length);
    const m = t.subarray(0, tr.length + info.length + 1);
    tr = new Uint8Array(hmac(sha256, prk, m));
    
    const toCopy = Math.min(tr.length, length - generated);
    result.set(tr.subarray(0, toCopy), generated);
    generated += toCopy;
    blockIndex++;
  }
  return result;
}

// Labeled extraction according to HPKE standard
function labeledExtract(salt: Uint8Array, suiteId: Uint8Array, label: string, ikm: Uint8Array = new Uint8Array(0)): Uint8Array {
  const encoder = new TextEncoder();
  const labelPrefix = encoder.encode("HPKE-v1");
  const labeledIkm = new Uint8Array(labelPrefix.length + suiteId.length + label.length + ikm.length);
  
  let offset = 0;
  labeledIkm.set(labelPrefix, offset); offset += labelPrefix.length;
  labeledIkm.set(suiteId, offset); offset += suiteId.length;
  labeledIkm.set(encoder.encode(label), offset); offset += label.length;
  labeledIkm.set(ikm, offset);
  
  return hkdfExtract(salt, labeledIkm);
}

function labeledExpand(prk: Uint8Array, suiteId: Uint8Array, label: string, info: Uint8Array, L: number): Uint8Array {
  const encoder = new TextEncoder();
  const labelPrefix = encoder.encode("HPKE-v1");
  const labelBytes = encoder.encode(label);
  
  // Build labeledInfo: length (2 bytes) + "HPKE-v1" + suite_id + label + info
  const labeledInfo = new Uint8Array(2 + labelPrefix.length + suiteId.length + labelBytes.length + info.length);
  
  // Set L (length in 2 bytes, network byte order)
  labeledInfo[0] = (L >> 8) & 0xFF;
  labeledInfo[1] = L & 0xFF;
  
  let offset = 2;
  labeledInfo.set(labelPrefix, offset); offset += labelPrefix.length;
  labeledInfo.set(suiteId, offset); offset += suiteId.length;
  labeledInfo.set(labelBytes, offset); offset += labelBytes.length;
  labeledInfo.set(info, offset);
  
  return hkdfExpand(prk, labeledInfo, L);
}

function i2osp(value: number, length: number): Uint8Array {
  const res = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xFF;
    value >>= 8;
  }
  return res;
}

const SUITE_ID = new Uint8Array([0x4B, 0x45, 0x4D, 0x00, 0x20]); // KEM DHKEM(X25519, HKDF-SHA256) (0x0020)
// For whole suite (KEM=0x0020, KDF=0x0001, AEAD=0x0002)
const FULL_SUITE_ID = new Uint8Array([0x48, 0x50, 0x4B, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x02]);

interface EphemeralKeyResponse {
  pubkey: string;
  key_id: string;
}

interface EncryptedRequest {
  key_id: string;
  encapsulated_key: string;
  ciphertext: string;
  provider?: string;
}

interface EncryptedResponse {
  encapsulated_key: string;
  ciphertext: string;
  done: boolean;
  receipt?: string;
  provider?: string;
}

function base64Encode(data: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("base64");
  }
  return btoa(String.fromCharCode(...data));
}

function base64Decode(data: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(data, "base64"));
  }
  return new Uint8Array(atob(data).split("").map(c => c.charCodeAt(0)));
}

function getRandomBytes(len: number): Uint8Array {
  const bytes = new Uint8Array(len);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else if (typeof Buffer !== "undefined") {
    const nodeCrypto = require("crypto");
    const buf = nodeCrypto.randomBytes(len);
    bytes.set(buf);
  } else {
    throw new Error("No secure random source found");
  }
  return bytes;
}

export class ProvnZeroClient {
  private serverUrl: string;
  private keyId: string | null = null;
  private serverPk: Uint8Array | null = null;

  constructor(serverUrl: string) {
    this.serverUrl = serverUrl;
  }

  async init(): Promise<void> {
    const response = await fetch(`${this.serverUrl}/v1/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });

    if (!response.ok) {
      throw new Error(`Init failed: ${response.status}`);
    }

    const keyData = await response.json() as any as EphemeralKeyResponse;
    this.keyId = keyData.key_id;
    this.serverPk = base64Decode(keyData.pubkey);
  }

  // Implementation of HPKE SetupBaseS
  private setupBaseS(pkR: Uint8Array, info: Uint8Array): { enc: Uint8Array, skE: Uint8Array, context: { key: Uint8Array, baseNonce: Uint8Array, seq: number } } {
    // Generate ephemeral key pair
    const skE = x25519.utils.randomSecretKey();
    const pkE = x25519.getPublicKey(skE);
    
    // DH
    const sharedSecret = x25519.getSharedSecret(skE, pkR);
    
    // Encap
    const enc = pkE;
    
    // ExtractAndExpand
    const kemContext = new Uint8Array(enc.length + pkR.length);
    kemContext.set(enc, 0);
    kemContext.set(pkR, enc.length);
    
    const sharedSecretExt = labeledExtract(new Uint8Array(0), SUITE_ID, "eae_prk", sharedSecret);
    
    // Clean up sharedSecret
    sharedSecret.fill(0);

    const L = 32; // Nhash
    const sharedSecretKem = labeledExpand(sharedSecretExt, SUITE_ID, "shared_secret", kemContext, L);
    
    // KeySchedule
    const pskIdHash = labeledExtract(new Uint8Array(0), FULL_SUITE_ID, "psk_id_hash", new Uint8Array(0));
    const infoHash = labeledExtract(new Uint8Array(0), FULL_SUITE_ID, "info_hash", info);
    const keyScheduleContext = new Uint8Array(1 + pskIdHash.length + infoHash.length);
    keyScheduleContext[0] = 0; // mode base
    keyScheduleContext.set(pskIdHash, 1);
    keyScheduleContext.set(infoHash, 1 + pskIdHash.length);
    
    const secret = labeledExtract(sharedSecretKem, FULL_SUITE_ID, "secret", new Uint8Array(0));
    
    const key = labeledExpand(secret, FULL_SUITE_ID, "key", keyScheduleContext, 32); // Nk
    const baseNonce = labeledExpand(secret, FULL_SUITE_ID, "base_nonce", keyScheduleContext, 12); // Nn
    
    // Cleanup
    sharedSecretExt.fill(0);
    sharedSecretKem.fill(0);
    secret.fill(0);
    
    return { enc, skE, context: { key, baseNonce, seq: 0 } };
  }

  // Compute nonce via XOR sequence
  private computeNonce(baseNonce: Uint8Array, seq: number): Uint8Array {
    const seqBytes = i2osp(seq, 8);
    const nonce = new Uint8Array(baseNonce);
    // XOR from the right
    for (let i = 0; i < 8; i++) {
        nonce[nonce.length - 8 + i] ^= seqBytes[i];
    }
    return nonce;
  }

  // Implementation of HPKE SetupBaseR
  private setupBaseR(enc: Uint8Array, skR: Uint8Array, pkR: Uint8Array, info: Uint8Array): { context: { key: Uint8Array, baseNonce: Uint8Array, seq: number } } {
    // DH
    const sharedSecret = x25519.getSharedSecret(skR, enc);
    
    // ExtractAndExpand
    const kemContext = new Uint8Array(enc.length + pkR.length);
    kemContext.set(enc, 0);
    kemContext.set(pkR, enc.length);
    
    const sharedSecretExt = labeledExtract(new Uint8Array(0), SUITE_ID, "eae_prk", sharedSecret);
    sharedSecret.fill(0); // cleanup

    const L = 32; // Nhash
    const sharedSecretKem = labeledExpand(sharedSecretExt, SUITE_ID, "shared_secret", kemContext, L);
    
    // KeySchedule
    const pskIdHash = labeledExtract(new Uint8Array(0), FULL_SUITE_ID, "psk_id_hash", new Uint8Array(0));
    const infoHash = labeledExtract(new Uint8Array(0), FULL_SUITE_ID, "info_hash", info);
    const keyScheduleContext = new Uint8Array(1 + pskIdHash.length + infoHash.length);
    keyScheduleContext[0] = 0; // mode base
    keyScheduleContext.set(pskIdHash, 1);
    keyScheduleContext.set(infoHash, 1 + pskIdHash.length);
    
    const secret = labeledExtract(sharedSecretKem, FULL_SUITE_ID, "secret", new Uint8Array(0));
    
    const key = labeledExpand(secret, FULL_SUITE_ID, "key", keyScheduleContext, 32); // Nk
    const baseNonce = labeledExpand(secret, FULL_SUITE_ID, "base_nonce", keyScheduleContext, 12); // Nn
    
    // Cleanup
    sharedSecretExt.fill(0);
    sharedSecretKem.fill(0);
    secret.fill(0);
    
    return { context: { key, baseNonce, seq: 0 } };
  }

  async send(prompt: string, provider?: string): Promise<{ text: string; receipt?: string }> {
    if (!this.keyId || !this.serverPk) {
      throw new Error("Client not initialized. Call init() first.");
    }

    const encoder = new TextEncoder();
    const info = encoder.encode("provnzero-v2");
    
    // 1. HPKE Seal (SetupBaseS + Encrypt)
    const { enc, skE, context } = this.setupBaseS(this.serverPk, info);
    const pkE = enc;
    
    const plaintext = encoder.encode(prompt);
    const nonce = this.computeNonce(context.baseNonce, context.seq++);
    const aes = gcm(context.key, nonce);
    const ciphertext = aes.encrypt(plaintext);

    // 2. Build request
    const request: EncryptedRequest = {
      key_id: this.keyId,
      encapsulated_key: base64Encode(enc),
      ciphertext: base64Encode(ciphertext),
      provider
    };

    // 3. Clean up the sender AEAD context securely
    context.key.fill(0);

    // 4. Send to proxy
    const response = await fetch(`${this.serverUrl}/v1/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request)
    });

    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }

    const encryptedResponse = await response.json() as any as EncryptedResponse;

    // 5. HPKE Open Response
    // The server sent back an encapsulated key representing its own ephemeral public key
    const serverResponseEnc = base64Decode(encryptedResponse.encapsulated_key);
    const responseCiphertext = base64Decode(encryptedResponse.ciphertext);
    
    // We act as the receiver. Our "Static" key pair for this inner exchange is our skE & pkE
    const recvContext = this.setupBaseR(serverResponseEnc, skE, pkE, info).context;
    
    // Destroy skE for total memory wiping
    skE.fill(0);
    
    const responseNonce = this.computeNonce(recvContext.baseNonce, recvContext.seq++);
    const responseAes = gcm(recvContext.key, responseNonce);
    
    const decrypted = responseAes.decrypt(responseCiphertext);
    recvContext.key.fill(0); // Wipe again
    
    const decoder = new TextDecoder();
    const text = decoder.decode(decrypted);
    
    decrypted.fill(0); // Wipe again

    return {
      text,
      receipt: encryptedResponse.receipt
    };
  }
}
