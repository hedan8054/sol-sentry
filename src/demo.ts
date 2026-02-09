/**
 * SolSentry Demo Script
 * 
 * Scans a well-known Solana wallet to showcase the full
 * security report output. Used for demos and screenshots.
 */

import { SolSentry, printReport, MAINNET_RPC, DEVNET_RPC } from './index.js';

// Well-known wallets for demo purposes
const DEMO_WALLETS = {
  // Solana Foundation
  solanaFoundation: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
  // Phantom wallet (public known address)
  phantom: 'CE2et8p9d4oBPAYSJMCxWqZadqMaNEh6o6GMFEdVkp3a',
  // A Solana validator
  validator: 'CertusDeBmqN8ZawdkxhsGBDUDSqBtkGBMMb3BPYTRiP',
};

async function runDemo() {
  console.log(`
  ╔═══════════════════════════════════════════════════════╗
  ║                                                       ║
  ║   🛡️  SolSentry — AI-Powered Solana Wallet Guardian   ║
  ║                                                       ║
  ║   Real-time threat detection & security reports       ║
  ║   Built for Colosseum Agent Hackathon 2026            ║
  ║                                                       ║
  ╚═══════════════════════════════════════════════════════╝
  `);

  const walletArg = process.argv[2];
  const useDevnet = process.argv.includes('--devnet');
  const wallet = walletArg || DEMO_WALLETS.solanaFoundation;
  const rpcUrl = useDevnet ? DEVNET_RPC : MAINNET_RPC;

  console.log(`🎯 Demo target: ${wallet === DEMO_WALLETS.solanaFoundation ? 'Solana Foundation' : wallet}`);
  console.log(`🌐 Network: ${useDevnet ? 'devnet' : 'mainnet'}\n`);

  try {
    const sentry = new SolSentry(wallet, rpcUrl);
    const report = await sentry.generateReport();
    printReport(report);

    // Also output JSON for programmatic consumers
    console.log('\n📋 JSON Report (for API consumers):');
    console.log('─'.repeat(60));
    console.log(JSON.stringify(report, null, 2));
  } catch (err: any) {
    console.error(`\n❌ Demo failed: ${err.message}`);
    console.log('\n💡 Tip: If mainnet RPC is rate-limited, try --devnet');
    process.exit(1);
  }
}

runDemo().catch(console.error);
