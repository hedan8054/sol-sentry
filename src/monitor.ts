/**
 * SolSentry Real-Time Monitor
 * 
 * Subscribes to wallet transactions via WebSocket and
 * performs real-time threat detection with alerts.
 */

import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { SolSentry, printReport, MAINNET_RPC, DEVNET_RPC } from './index.js';

// WebSocket-enabled RPC endpoints
const WS_MAINNET = 'wss://api.mainnet-beta.solana.com';
const WS_DEVNET = 'wss://api.devnet.solana.com';

interface MonitorConfig {
  walletAddress: string;
  rpcUrl?: string;
  wsUrl?: string;
  /** Run a full scan on startup */
  initialScan?: boolean;
  /** Callback for threat alerts */
  onAlert?: (alert: AlertEvent) => void;
}

export interface AlertEvent {
  type: 'threat' | 'info';
  wallet: string;
  signature: string;
  message: string;
  severity?: string;
  timestamp: Date;
}

export class SolSentryMonitor {
  private connection: Connection;
  private wsConnection: Connection;
  private wallet: PublicKey;
  private walletAddress: string;
  private subscriptionId: number | null = null;
  private onAlert: (alert: AlertEvent) => void;
  private sentry: SolSentry;
  private running = false;

  constructor(config: MonitorConfig) {
    const rpcUrl = config.rpcUrl || MAINNET_RPC;
    const wsUrl = config.wsUrl || (rpcUrl.includes('devnet') ? WS_DEVNET : WS_MAINNET);

    this.walletAddress = config.walletAddress;
    this.wallet = new PublicKey(config.walletAddress);
    this.connection = new Connection(rpcUrl, 'confirmed');
    this.wsConnection = new Connection(rpcUrl, {
      commitment: 'confirmed',
      wsEndpoint: wsUrl,
    });
    this.sentry = new SolSentry(config.walletAddress, rpcUrl);
    this.onAlert = config.onAlert || this.defaultAlertHandler;
  }

  /** Default alert handler — prints to console */
  private defaultAlertHandler(alert: AlertEvent): void {
    const icon = alert.type === 'threat' ? '🚨' : 'ℹ️';
    const sevIcon = alert.severity === 'critical' ? '🔴' :
                    alert.severity === 'high' ? '🟠' :
                    alert.severity === 'medium' ? '🟡' : '🟢';
    console.log(`\n${icon} [${alert.timestamp.toISOString()}] ${alert.severity ? sevIcon + ' ' : ''}${alert.message}`);
    if (alert.signature) {
      console.log(`   🔗 https://solscan.io/tx/${alert.signature}`);
    }
  }

  /** Start monitoring */
  async start(initialScan = true): Promise<void> {
    if (this.running) {
      console.log('⚠️  Monitor already running');
      return;
    }
    this.running = true;

    console.log('═'.repeat(60));
    console.log('🛡️  SolSentry Real-Time Monitor');
    console.log('═'.repeat(60));
    console.log(`📍 Watching: ${this.walletAddress}`);
    console.log(`🕐 Started:  ${new Date().toISOString()}`);
    console.log('─'.repeat(60));

    // Optional initial scan
    if (initialScan) {
      console.log('\n📊 Running initial wallet scan...');
      try {
        const report = await this.sentry.generateReport();
        printReport(report);
      } catch (err: any) {
        console.error(`⚠️  Initial scan failed: ${err.message}`);
      }
    }

    // Subscribe to account changes (transaction notifications)
    console.log('\n👁️  Subscribing to real-time transactions...\n');

    try {
      this.subscriptionId = this.wsConnection.onAccountChange(
        this.wallet,
        async (accountInfo, context) => {
          const balance = accountInfo.lamports / LAMPORTS_PER_SOL;
          this.onAlert({
            type: 'info',
            wallet: this.walletAddress,
            signature: `slot-${context.slot}`,
            message: `Account change detected — new balance: ${balance.toFixed(4)} SOL (slot ${context.slot})`,
            timestamp: new Date(),
          });

          // Fetch and analyze the latest transaction
          try {
            const sigs = await this.connection.getSignaturesForAddress(this.wallet, { limit: 1 });
            if (sigs.length > 0) {
              const tx = await this.connection.getParsedTransaction(sigs[0].signature, {
                maxSupportedTransactionVersion: 0,
              });
              if (tx) {
                const threats = this.sentry.analyzeThreat(tx);
                for (const threat of threats) {
                  this.onAlert({
                    type: 'threat',
                    wallet: this.walletAddress,
                    signature: threat.signature,
                    message: `${threat.ruleName}: ${threat.description}`,
                    severity: threat.severity,
                    timestamp: new Date(),
                  });
                }
                if (threats.length === 0) {
                  this.onAlert({
                    type: 'info',
                    wallet: this.walletAddress,
                    signature: sigs[0].signature,
                    message: 'Transaction analyzed — no threats detected',
                    timestamp: new Date(),
                  });
                }
              }
            }
          } catch (err: any) {
            console.error(`   ⚠️  Failed to analyze transaction: ${err.message}`);
          }
        },
        'confirmed'
      );

      console.log(`✅ Subscribed (id: ${this.subscriptionId}). Waiting for transactions...`);
      console.log('   Press Ctrl+C to stop.\n');
    } catch (err: any) {
      console.error(`❌ WebSocket subscription failed: ${err.message}`);
      console.log('   Falling back to polling mode (every 30s)...\n');
      this.startPolling();
    }
  }

  /** Fallback polling mode */
  private startPolling(): void {
    let lastSig = '';
    const poll = async () => {
      if (!this.running) return;
      try {
        const sigs = await this.connection.getSignaturesForAddress(this.wallet, { limit: 1 });
        if (sigs.length > 0 && sigs[0].signature !== lastSig) {
          lastSig = sigs[0].signature;
          const tx = await this.connection.getParsedTransaction(sigs[0].signature, {
            maxSupportedTransactionVersion: 0,
          });
          if (tx) {
            const threats = this.sentry.analyzeThreat(tx);
            if (threats.length > 0) {
              for (const t of threats) {
                this.onAlert({
                  type: 'threat',
                  wallet: this.walletAddress,
                  signature: t.signature,
                  message: `${t.ruleName}: ${t.description}`,
                  severity: t.severity,
                  timestamp: new Date(),
                });
              }
            }
          }
        }
      } catch { /* ignore polling errors */ }
      setTimeout(poll, 30_000);
    };
    poll();
  }

  /** Stop monitoring */
  async stop(): Promise<void> {
    this.running = false;
    if (this.subscriptionId !== null) {
      try {
        await this.wsConnection.removeAccountChangeListener(this.subscriptionId);
      } catch { /* ignore */ }
      this.subscriptionId = null;
    }
    console.log('\n🛑 SolSentry Monitor stopped.');
  }
}

// --- CLI ---
async function main() {
  const wallet = process.argv[2];
  const useDevnet = process.argv.includes('--devnet');

  if (!wallet) {
    console.log('Usage: tsx src/monitor.ts <WALLET_ADDRESS> [--devnet]');
    process.exit(1);
  }

  const rpcUrl = useDevnet ? DEVNET_RPC : MAINNET_RPC;
  const monitor = new SolSentryMonitor({ walletAddress: wallet, rpcUrl });

  // Graceful shutdown
  process.on('SIGINT', async () => {
    await monitor.stop();
    process.exit(0);
  });

  await monitor.start(true);
}

const isMain = process.argv[1]?.includes('monitor');
if (isMain) {
  main().catch(console.error);
}
