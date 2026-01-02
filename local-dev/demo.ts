/**
 * LuxFHE Local Demo
 * 
 * Demonstrates v1-sdk and v2-sdk connecting to local Go TFHE server
 * 
 * Usage:
 *   npx ts-node demo.ts
 */

import { LuxFHEClient, FheUintType } from '../js/v1-sdk/src/luxd/client';

const FHE_SERVER_URL = process.env.FHE_SERVER_URL || 'http://localhost:8448';

async function main() {
  console.log('🔐 LuxFHE Local Demo\n');
  console.log(`Connecting to FHE server: ${FHE_SERVER_URL}\n`);

  // Create client
  const client = new LuxFHEClient({
    serverUrl: FHE_SERVER_URL,
    thresholdMode: false,
  });

  // Check health
  console.log('1. Checking server health...');
  try {
    const health = await client.health();
    console.log(`   ✓ Status: ${health.status}`);
    console.log(`   ✓ Threshold mode: ${health.threshold}`);
    console.log(`   ✓ Parties: ${health.parties}\n`);
  } catch (e) {
    console.error('   ✗ Server not reachable. Make sure to run:');
    console.error('     cd ~/work/lux/tfhe && ./bin/fhe-server\n');
    process.exit(1);
  }

  // Get public key
  console.log('2. Fetching public key...');
  const pk = await client.getPublicKey();
  console.log(`   ✓ Public key: ${pk.length} bytes\n`);

  // Encrypt values
  console.log('3. Encrypting values...');
  const a = 42;
  const b = 17;
  
  const encA = await client.encrypt({ value: a, bitWidth: 32 });
  console.log(`   ✓ Encrypted ${a}: ${encA.length} bytes`);
  
  const encB = await client.encrypt({ value: b, bitWidth: 32 });
  console.log(`   ✓ Encrypted ${b}: ${encB.length} bytes\n`);

  // Evaluate FHE operations
  console.log('4. Evaluating FHE operations...');
  
  // Add
  const encSum = await client.evaluate({
    op: 'add',
    left: encA,
    right: encB,
    bitWidth: 32,
  });
  console.log(`   ✓ add(${a}, ${b}) = encrypted result (${encSum.length} bytes)`);
  
  // Subtract
  const encDiff = await client.evaluate({
    op: 'sub',
    left: encA,
    right: encB,
    bitWidth: 32,
  });
  console.log(`   ✓ sub(${a}, ${b}) = encrypted result (${encDiff.length} bytes)`);
  
  // Compare
  const encLt = await client.evaluate({
    op: 'lt',
    left: encA,
    right: encB,
    bitWidth: 32,
  });
  console.log(`   ✓ lt(${a}, ${b}) = encrypted result (${encLt.length} bytes)\n`);

  // Verify computation
  console.log('5. Verifying computation...');
  const verified = await client.verify(encSum);
  console.log(`   ✓ ZK verification: ${verified}\n`);

  console.log('✅ Demo complete!\n');
  console.log('Expected results (if decrypted):');
  console.log(`   add(${a}, ${b}) = ${a + b}`);
  console.log(`   sub(${a}, ${b}) = ${a - b}`);
  console.log(`   lt(${a}, ${b}) = ${a < b}`);
}

main().catch(console.error);
