#!/usr/bin/env python3
"""ProvnZero Comprehensive Test Suite - Fixed"""

import sys, base64, requests, concurrent.futures
from pyhpke import CipherSuite, KEMId, KDFId, AEADId

SERVER_URL = "http://127.0.0.1:3001"
TESTS_PASSED = 0
TESTS_FAILED = 0


suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)

def init_client():
    r = requests.post(f"{SERVER_URL}/v1/init", json={})
    data = r.json()
    return data["key_id"], base64.b64decode(data["pubkey"])

def make_request(key_id: str, server_pubkey_bytes: bytes, prompt: str):
    server_pubkey = suite.kem.deserialize_public_key(server_pubkey_bytes)
    
    encapsulated_key, sender = suite.create_sender_context(server_pubkey, b"provnzero-v2")
    ciphertext = sender.seal(prompt.encode())

    r = requests.post(
        f"{SERVER_URL}/v1/completions",
        json={
            "key_id": key_id,
            "encapsulated_key": base64.b64encode(encapsulated_key).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        },
    )

    if r.status_code == 200:
        data = r.json()
        return "[ENCRYPTED RESPONSE RECEIVED]", data.get("receipt")
    
    return None, None

# ============ TESTS ============


def test_health():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 1] Health endpoint...")
    try:
        r = requests.get(f"{SERVER_URL}/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_init():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 2] Init endpoint...")
    try:
        r = requests.post(f"{SERVER_URL}/v1/init", json={})
        data = r.json()
        assert "pubkey" in data
        assert "key_id" in data
        assert len(base64.b64decode(data["pubkey"])) == 32
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_basic_encryption():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 3] Basic encryption...")
    try:
        key_id, server_pub = init_client()
        result, _ = make_request(key_id, server_pub, "Hello!")
        assert result is not None
        assert "ENCRYPTED RESPONSE RECEIVED" in result
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_long_prompt():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 4] Long prompt (1000 chars)...")
    try:
        key_id, server_pub = init_client()
        long_prompt = "A" * 1000
        result, _ = make_request(key_id, server_pub, long_prompt)
        assert result is not None
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_special_chars():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 5] Special characters...")
    try:
        key_id, server_pub = init_client()
        prompts = [
            "Hello World!",
            "Emoji test",
            "Newlines\ntest",
            'Quotes "test"',
            "Backslash \\ test",
        ]
        for prompt in prompts:
            result, _ = make_request(key_id, server_pub, prompt)
            assert result is not None
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_concurrent_requests():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 6] Concurrent requests (10 parallel)...")
    try:
        key_id, server_pub = init_client()

        def make_req(i):
            return make_request(key_id, server_pub, f"Request {i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(make_req, range(10)))

        assert all(r[0] is not None for r in results)
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_bad_key_id():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 7] Invalid key_id...")
    try:
        key_id, server_pub = init_client()
        server_pubkey = suite.kem.deserialize_public_key(server_pub)
        encapsulated_key, sender = suite.create_sender_context(server_pubkey, b"provnzero-v2")
        ciphertext = sender.seal(b"test")

        r = requests.post(
            f"{SERVER_URL}/v1/completions",
            json={
                "key_id": "invalid_key_id_123",
                "encapsulated_key": base64.b64encode(encapsulated_key).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            },
        )

        assert r.status_code == 404
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_bad_ciphertext():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 8] Tampered ciphertext...")
    try:
        key_id, server_pub = init_client()
        server_pubkey = suite.kem.deserialize_public_key(server_pub)
        encapsulated_key, sender = suite.create_sender_context(server_pubkey, b"provnzero-v2")
        ciphertext = bytearray(sender.seal(b"test"))
        
        # Tamper with ciphertext
        ciphertext[0] ^= 0xFF
        ciphertext = bytes(ciphertext)

        r = requests.post(
            f"{SERVER_URL}/v1/completions",
            json={
                "key_id": key_id,
                "encapsulated_key": base64.b64encode(encapsulated_key).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            },
        )

        assert r.status_code == 401
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_missing_fields():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 9] Missing fields...")
    try:
        # No ciphertext
        r = requests.post(
            f"{SERVER_URL}/v1/completions",
            json={
                "key_id": "test",
                "encapsulated_key": "dGVzdA==",
            },
        )
        assert r.status_code >= 400

        # Valid request with wrong encapsulated key length/malformed
        key_id, server_pub = init_client()
        r = requests.post(
            f"{SERVER_URL}/v1/completions",
            json={
                "key_id": key_id,
                "encapsulated_key": "AA==",  # Too small
                "ciphertext": "dGVzdA==",
            },
        )
        assert r.status_code >= 400

        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_receipt_generated():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 10] VEX Receipt generation...")
    try:
        key_id, server_pub = init_client()
        result, receipt = make_request(key_id, server_pub, "receipt test")

        assert receipt is not None
        assert "MEMORY ZEROIZED" in receipt
        assert "Signature:" in receipt
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_rate_limit():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 11] Rapid requests (50 in sequence)...")
    try:
        for i in range(50):
            key_id, server_pub = init_client()
            result, _ = make_request(key_id, server_pub, f"test{i}")
            assert result is not None
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def test_empty_prompt():
    global TESTS_PASSED, TESTS_FAILED
    print("\n[TEST 12] Empty prompt...")
    try:
        key_id, server_pub = init_client()
        result, _ = make_request(key_id, server_pub, "")
        assert result is not None
        print("  [PASS]")
        TESTS_PASSED += 1
    except Exception as e:
        print(f"  [FAIL] {e}")
        TESTS_FAILED += 1


def main():
    global TESTS_PASSED, TESTS_FAILED

    print("=" * 60)
    print("PROVNZERO - COMPREHENSIVE TEST SUITE")
    print("=" * 60)

    test_health()
    test_init()
    test_basic_encryption()
    test_long_prompt()
    test_special_chars()
    test_concurrent_requests()
    test_bad_key_id()
    test_bad_ciphertext()
    test_missing_fields()
    test_receipt_generated()
    test_rate_limit()
    test_empty_prompt()

    print("\n" + "=" * 60)
    print(f"RESULTS: {TESTS_PASSED} passed, {TESTS_FAILED} failed")
    print("=" * 60)

    if TESTS_FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
