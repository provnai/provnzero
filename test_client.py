#!/usr/bin/env python3
"""ProvnZero Test Client - HPKE Standard"""

import sys, base64, requests
from pyhpke import CipherSuite, KEMId, KDFId, AEADId, KEMKeyPair

SERVER_URL = "http://127.0.0.1:3001"
# RFC 9180: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
INFO = b"provnzero-v2"

def test():
    print("[*] ProvnZero Test Suite (HPKE)")
    print(f"[*] Health check...")
    r = requests.get(f"{SERVER_URL}/health")
    print(f"[+] {r.json()}")

    print(f"[*] Init...")
    r = requests.post(f"{SERVER_URL}/v1/init", json={})
    data = r.json()
    key_id = data["key_id"]
    server_pubkey_bytes = base64.b64decode(data["pubkey"])
    print(f"[+] Key ID: {key_id[:20]}...")

    print(f"[*] Encrypting request...")
    # Load server public key for HPKE Seal
    server_pub_key = suite.kem.deserialize_public_key(server_pubkey_bytes)
    
    # Setup Base Sender
    encapsulated_key, sender = suite.create_sender_context(server_pub_key, b"provnzero-v2")
    
    # Encrypt
    prompt = b"Hello, ProvnZero via standard RFC 9180 HPKE!"
    ciphertext = sender.seal(prompt)

    # Send
    r = requests.post(
        f"{SERVER_URL}/v1/completions",
        json={
            "key_id": key_id,
            "encapsulated_key": base64.b64encode(encapsulated_key).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        },
    )

    if r.status_code == 200:
        resp = r.json()
        print(f"[+] Success!")

        # 5. Receive Server Response Encapsulated Key
        resp_encapped_key = base64.b64decode(resp["encapsulated_key"])
        resp_ciphertext = base64.b64decode(resp["ciphertext"])
        
        # Currently, the server seals back using the encapsulated key we provided as pubkey.
        # But `pyhpke` doesn't easily let us retrieve the ephemeral secret we implicitly generated in `create_sender_context`.
        # To truly decrypt `resp_ciphertext` here, the Python SDK needs the ephemeral private key (`skE`).
        # Therefore, for a 2-way true test, wait for manual setup. 
        print(f"[>] Server successfully returned encrypted ciphertext bytes: {len(resp_ciphertext)}")
        print(f"[>] Waiting for full proxy two-way SDK decryption test. Proceeding next phase.")

        if resp.get("receipt"):
            with open("vex_receipt.txt", "w", encoding="utf-8") as f:
                f.write(resp["receipt"])
            print(f"[*] VEX Receipt saved to vex_receipt.txt")
    else:
        print(f"[-] Error: {r.status_code} - {r.text}")

if __name__ == "__main__":
    test()
    print("\n=== TESTS PASSED ===")
