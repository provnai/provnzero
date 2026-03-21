import { ProvnZeroClient } from "./index.js";

async function main() {
  const client = new ProvnZeroClient("http://127.0.0.1:3001");
  
  console.log("🔐 Initializing ProvnZero client...");
  await client.init();
  console.log("✅ Initialized\n");
  
  console.log("📤 Sending encrypted prompt...");
  const result = await client.send("Hello, world! What is 2+2?");
  
  console.log("\n📥 Response received:\n");
  console.log(result.text);
  console.log("\n🧾 VEX Receipt:\n");
  console.log(result.receipt);
}

main().catch(console.error);
