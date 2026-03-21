import asyncio
import aiohttp
import time
import json
import statistics
import base64
from pyhpke import CipherSuite, KEMId, KDFId, AEADId

PROXY_URL = "http://localhost:3001"
TOTAL_REQUESTS = 25
CONCURRENCY = 10

suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)

async def init_session(session: aiohttp.ClientSession):
    async with session.post(f"{PROXY_URL}/v1/init") as resp:
        data = await resp.json()
        return data["key_id"], base64.b64decode(data["pubkey"])

async def send_valid_request(session: aiohttp.ClientSession, key_id: str, server_pubkey_bytes: bytes, sem: asyncio.Semaphore):
    async with sem:
        start_time = time.time()
        
        # 1. Perform REAL HPKE encryption on the client
        try:
            server_pubkey = suite.kem.deserialize_public_key(server_pubkey_bytes)
            encapsulated_key, sender = suite.create_sender_context(server_pubkey, b"provnzero-v2")
            
            prompt = "Simulated benchmark prompt. Hello LLM."
            ciphertext = sender.seal(prompt.encode())

            payload = {
                "key_id": key_id,
                "encapsulated_key": base64.b64encode(encapsulated_key).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "provider": "openai"
            }
        except Exception:
            return -1.0, 500

        # 2. Send over the wire to Rust Proxy
        try:
            async with session.post(f"{PROXY_URL}/v1/completions", json=payload) as resp:
                data = await resp.json() 
                
                # Verify we actually got a response ciphertext + VEX receipt back
                if "ciphertext" not in data or "receipt" not in data:
                    return -1.0, 500

                latency = (time.time() - start_time) * 1000 # ms
                return latency, resp.status
        except Exception:
            return -1.0, 500

async def main():
    print(f"Starting ProvnZero REAL CRYPTO Benchmark...")
    print(f"Total Requests: {TOTAL_REQUESTS}")
    print(f"Concurrency Limit: {CONCURRENCY}\n")

    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Get one session
        try:
            key_id, pubkey = await init_session(session)
        except Exception as e:
            print(f"Failed to connect to proxy: {e}")
            return

        sem = asyncio.Semaphore(CONCURRENCY)
        
        start_wall = time.time()
        tasks = [send_valid_request(session, key_id, pubkey, sem) for _ in range(TOTAL_REQUESTS)]
        
        results = await asyncio.gather(*tasks)
        end_wall = time.time()

    latencies = [r[0] for r in results if r[1] == 200 and r[0] > 0]
    errors = len(results) - len(latencies)
    
    if not latencies:
        print("All requests failed! Check the proxy logs for 400/401s.")
        return

    avg_latency = statistics.mean(latencies)
    p95 = statistics.quantiles(latencies, n=100)[94] if len(latencies) > 100 else max(latencies)
    p99 = statistics.quantiles(latencies, n=100)[98] if len(latencies) > 100 else max(latencies)
    
    rps = TOTAL_REQUESTS / (end_wall - start_wall)

    print("=======================================")
    print("      REAL HPKE BENCHMARK RESULTS      ")
    print("=======================================")
    print(f"Total Time:      {end_wall - start_wall:.2f} seconds")
    print(f"Throughput:      {rps:.2f} req/sec")
    print(f"Success Rate:    {len(latencies)}/{TOTAL_REQUESTS} ({errors} errors)")
    print(f"Avg Latency:     {avg_latency:.2f} ms")
    print(f"P95 Latency:     {p95:.2f} ms")
    print(f"P99 Latency:     {p99:.2f} ms")
    print("=======================================")

if __name__ == "__main__":
    asyncio.run(main())
