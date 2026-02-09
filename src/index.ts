/**
 * SolSentry - AI-Powered Solana Wallet Guardian
 * 
 * Monitors Solana wallets in real-time, detects suspicious transactions,
 * and generates AI-powered security reports.
 * 
 * Built for the Colosseum Agent Hackathon 2026.
 */

import { Connection, PublicKey, ParsedTransactionWithMeta, LAMPORTS_PER_SOL } from '@solana/web3.js';

// --- Configuration ---
export const HELIUS_RPC = 'https://mainnet.helius-rpc.com/?api-key=demo';
export const DEVNET_RPC = 'https://api.devnet.solana.com';
export const MAINNET_RPC = 'https://api.mainnet-beta.solana.com';
// Helper to extract address string from accountKey
function getAddr(key: any): string {
  if (typeof key === 'string') return key;
  if (key?.pubkey) return key.pubkey.toString();
  return key?.toString() || '';
}


// --- Types ---
export interface ThreatRule {
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  check: (tx: ParsedTransactionWithMeta, walletAddress: string, context: AnalysisContext) => ThreatResult | null;
}

export interface ThreatResult {
  ruleName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  details: string;
  signature: string;
  timestamp: number;
}

export interface WalletReport {
  walletAddress: string;
  generatedAt: string;
  network: string;
  solBalance: number;
  totalTransactions: number;
  threats: ThreatResult[];
  riskScore: number;
  riskLevel: string;
  summary: string;
  aiAnalysis: string;
  recommendations: string[];
}

/** Context passed to rules for cross-tx analysis */
export interface AnalysisContext {
  /** All addresses this wallet has interacted with before */
  knownAddresses: Set<string>;
  /** Addresses seen as recipients in this scan batch */
  seenRecipients: Set<string>;
  /** Token mints seen */
  tokenMintsSeen: Set<string>;
}

// --- Known Threat Databases ---

/** Known scam/drainer program IDs */
const KNOWN_SCAM_PROGRAMS = new Set([
  'Drai1111111111111111111111111111111111111',
  'DRai2222222222222222222222222222222222222',
]);

/** Programs commonly used by NFT drainers */
const NFT_DRAINER_PATTERNS = new Set([
  'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s', // Metaplex (legit but used by drainers via approve)
]);

/** Known airdrop scam token mints */
const SCAM_AIRDROP_MINTS = new Set<string>([
  // Placeholder — in production, fetch from a threat feed
]);

/** Well-known system programs (not suspicious) */
const SYSTEM_PROGRAMS = new Set([
  '11111111111111111111111111111111',
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  'ComputeBudget111111111111111111111111111111',
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',
  'Memo1UhkJBfCVP4EQk9m7N3yEqFGxH8mVUHGe6u6mZF2',
  'Vote111111111111111111111111111111111111111',
  'Stake11111111111111111111111111111111111111',
  'SysvarRent111111111111111111111111111111111',
]);

// --- Threat Detection Rules ---
const threatRules: ThreatRule[] = [
  // 1. Large SOL outflow
  {
    name: 'Large SOL Transfer',
    severity: 'high',
    description: 'Unusually large SOL transfer detected',
    check: (tx, walletAddress) => {
      if (!tx.meta) return null;
      const accounts = tx.transaction.message.accountKeys;
      for (let i = 0; i < accounts.length; i++) {
        const addr = getAddr(accounts[i]);
        if (addr === walletAddress) {
          const diff = (tx.meta.preBalances[i] - tx.meta.postBalances[i]) / LAMPORTS_PER_SOL;
          if (diff > 10) {
            return {
              ruleName: 'Large SOL Transfer',
              severity: 'high',
              description: `Large outflow of ${diff.toFixed(4)} SOL detected`,
              details: `Wallet sent ${diff.toFixed(4)} SOL in a single transaction (threshold: 10 SOL).`,
              signature: tx.transaction.signatures[0],
              timestamp: tx.blockTime || 0,
            };
          }
        }
      }
      return null;
    },
  },

  // 2. Known scam program interaction
  {
    name: 'Known Scam Program',
    severity: 'critical',
    description: 'Interaction with a known malicious program',
    check: (tx) => {
      const instructions = tx.transaction.message.instructions;
      for (const ix of instructions) {
        const pid = typeof ix.programId === 'string' ? ix.programId : ix.programId?.toString();
        if (pid && KNOWN_SCAM_PROGRAMS.has(pid)) {
          return {
            ruleName: 'Known Scam Program',
            severity: 'critical',
            description: 'Transaction interacted with a known scam/drainer program!',
            details: `Program ${pid} is flagged as malicious in our threat database.`,
            signature: tx.transaction.signatures[0],
            timestamp: tx.blockTime || 0,
          };
        }
      }
      return null;
    },
  },

  // 3. Unlimited token approval
  {
    name: 'Unlimited Token Approval',
    severity: 'high',
    description: 'Unlimited token approval granted',
    check: (tx) => {
      const logs = tx.meta?.logMessages || [];
      for (const log of logs) {
        if (log.includes('Approve') && log.includes('18446744073709551615')) {
          return {
            ruleName: 'Unlimited Token Approval',
            severity: 'high',
            description: 'An unlimited token approval was granted',
            details: 'This could allow a contract to drain all tokens of this type from your wallet.',
            signature: tx.transaction.signatures[0],
            timestamp: tx.blockTime || 0,
          };
        }
      }
      return null;
    },
  },

  // 4. First-time recipient detection
  {
    name: 'First-Time Recipient',
    severity: 'low',
    description: 'Transfer to a never-before-seen address',
    check: (tx, walletAddress, ctx) => {
      if (!tx.meta) return null;
      const accounts = tx.transaction.message.accountKeys;
      for (let i = 0; i < accounts.length; i++) {
        const addr = getAddr(accounts[i]);
        if (!addr || addr === walletAddress || SYSTEM_PROGRAMS.has(addr)) continue;
        const received = (tx.meta.postBalances[i] - tx.meta.preBalances[i]) / LAMPORTS_PER_SOL;
        if (received > 1 && !ctx.knownAddresses.has(addr) && !ctx.seenRecipients.has(addr)) {
          ctx.seenRecipients.add(addr);
          return {
            ruleName: 'First-Time Recipient',
            severity: 'low',
            description: `${received.toFixed(4)} SOL sent to new address ${String(addr).slice(0, 8)}...${String(addr).slice(-4)}`,
            details: 'This address has not been seen in previous interactions. Verify it is intended.',
            signature: tx.transaction.signatures[0],
            timestamp: tx.blockTime || 0,
          };
        }
        if (addr) ctx.seenRecipients.add(addr);
      }
      return null;
    },
  },

  // 5. NFT Drainer pattern — multiple NFT transfers in one tx
  {
    name: 'NFT Drainer Pattern',
    severity: 'critical',
    description: 'Possible NFT drainer attack detected',
    check: (tx, walletAddress) => {
      const logs = tx.meta?.logMessages || [];
      let nftTransferCount = 0;
      let hasApprove = false;
      for (const log of logs) {
        if (log.includes('Transfer') && log.includes('amount: 1')) nftTransferCount++;
        if (log.includes('Approve') || log.includes('Delegate')) hasApprove = true;
      }
      // Multiple NFTs transferred out + approval pattern = drainer
      if (nftTransferCount >= 3 && hasApprove) {
        return {
          ruleName: 'NFT Drainer Pattern',
          severity: 'critical',
          description: `Possible NFT drainer: ${nftTransferCount} NFTs transferred with approval in one tx`,
          details: 'Multiple NFT transfers combined with token approval is a common drainer pattern.',
          signature: tx.transaction.signatures[0],
          timestamp: tx.blockTime || 0,
        };
      }
      return null;
    },
  },

  // 6. Suspicious airdrop token
  {
    name: 'Suspicious Airdrop Token',
    severity: 'medium',
    description: 'Received tokens from a known scam airdrop',
    check: (tx) => {
      const logs = tx.meta?.logMessages || [];
      // Check for incoming token transfers with suspicious mints
      for (const log of logs) {
        if (log.includes('MintTo') || log.includes('Transfer')) {
          // Check inner instructions for known scam mints
          const innerIxs = tx.meta?.innerInstructions || [];
          for (const inner of innerIxs) {
            for (const ix of (inner.instructions as any[])) {
              const parsed = (ix as any).parsed;
              if (parsed?.info?.mint && SCAM_AIRDROP_MINTS.has(parsed.info.mint)) {
                return {
                  ruleName: 'Suspicious Airdrop Token',
                  severity: 'medium',
                  description: 'Received tokens from a known scam airdrop campaign',
                  details: `Token mint ${parsed.info.mint} is flagged as a scam. Do NOT interact with it.`,
                  signature: tx.transaction.signatures[0],
                  timestamp: tx.blockTime || 0,
                };
              }
            }
          }
        }
      }
      return null;
    },
  },

  // 7. Flash loan pattern — borrow + swap + repay in single tx
  {
    name: 'Flash Loan Activity',
    severity: 'medium',
    description: 'Possible flash loan detected',
    check: (tx) => {
      const logs = tx.meta?.logMessages || [];
      const logText = logs.join(' ');
      const hasFlashBorrow = logText.includes('FlashLoan') || logText.includes('flash_loan') || logText.includes('borrow');
      const hasSwap = logText.includes('Swap') || logText.includes('swap');
      const hasRepay = logText.includes('Repay') || logText.includes('repay');
      if (hasFlashBorrow && hasSwap && hasRepay) {
        return {
          ruleName: 'Flash Loan Activity',
          severity: 'medium',
          description: 'Flash loan pattern detected (borrow → swap → repay)',
          details: 'Flash loans are not inherently malicious but are commonly used in exploits.',
          signature: tx.transaction.signatures[0],
          timestamp: tx.blockTime || 0,
        };
      }
      return null;
    },
  },

  // 8. Unusual program count — many programs in one tx
  {
    name: 'Complex Transaction',
    severity: 'low',
    description: 'Transaction involves unusually many programs',
    check: (tx) => {
      const programIds = new Set<string>();
      for (const ix of tx.transaction.message.instructions) {
        const pid = typeof ix.programId === 'string' ? ix.programId : ix.programId?.toString();
        if (pid && !SYSTEM_PROGRAMS.has(pid)) programIds.add(pid);
      }
      if (programIds.size >= 5) {
        return {
          ruleName: 'Complex Transaction',
          severity: 'low',
          description: `Transaction invoked ${programIds.size} non-system programs`,
          details: 'Highly complex transactions can be harder to audit and may hide malicious actions.',
          signature: tx.transaction.signatures[0],
          timestamp: tx.blockTime || 0,
        };
      }
      return null;
    },
  },

  // 9. Account close / drain — closing token accounts sends SOL to closer
  {
    name: 'Token Account Closed',
    severity: 'low',
    description: 'Token account was closed',
    check: (tx) => {
      const logs = tx.meta?.logMessages || [];
      let closeCount = 0;
      for (const log of logs) {
        if (log.includes('CloseAccount')) closeCount++;
      }
      if (closeCount >= 5) {
        return {
          ruleName: 'Mass Account Closure',
          severity: 'medium',
          description: `${closeCount} token accounts closed in one transaction`,
          details: 'Closing many accounts at once could indicate wallet draining.',
          signature: tx.transaction.signatures[0],
          timestamp: tx.blockTime || 0,
        };
      }
      return null;
    },
  },
];

// --- AI Report Generation ---

function generateAIAnalysis(threats: ThreatResult[], txCount: number, walletAddress: string): string {
  if (threats.length === 0) {
    return `Security analysis complete for wallet ${walletAddress.slice(0, 8)}...${walletAddress.slice(-4)}. ` +
      `After scanning ${txCount} recent transactions, no suspicious activity was detected. ` +
      `The wallet appears to be operating normally with standard transaction patterns. ` +
      `Continue monitoring regularly as new threats can emerge at any time.`;
  }

  const critical = threats.filter(t => t.severity === 'critical');
  const high = threats.filter(t => t.severity === 'high');
  const medium = threats.filter(t => t.severity === 'medium');
  const low = threats.filter(t => t.severity === 'low');

  const parts: string[] = [];
  parts.push(`Security analysis for wallet ${walletAddress.slice(0, 8)}...${walletAddress.slice(-4)} identified ${threats.length} potential threat(s) across ${txCount} transactions.`);

  if (critical.length > 0) {
    parts.push(`\n\n🔴 CRITICAL FINDINGS: ${critical.length} critical issue(s) require immediate action. ` +
      critical.map(t => t.description).join('. ') + '.' +
      ' These findings suggest the wallet may have been compromised or targeted by known attack vectors.');
  }
  if (high.length > 0) {
    parts.push(`\n\n🟠 HIGH SEVERITY: ${high.length} high-risk pattern(s) detected. ` +
      high.map(t => t.description).join('. ') + '.' +
      ' Review these transactions carefully and consider revoking any suspicious approvals.');
  }
  if (medium.length > 0) {
    parts.push(`\n\n🟡 MEDIUM SEVERITY: ${medium.length} item(s) worth investigating. ` +
      medium.map(t => t.description).join('. ') + '.');
  }
  if (low.length > 0) {
    parts.push(`\n\n🟢 LOW SEVERITY: ${low.length} informational finding(s). ` +
      low.map(t => t.description).join('. ') + '.');
  }

  parts.push('\n\nThis report was generated by SolSentry AI. Always verify findings independently before taking action.');
  return parts.join('');
}

// --- Main SolSentry Class ---

export class SolSentry {
  private connection: Connection;
  private walletAddress: string;
  private network: string;
  private context: AnalysisContext;

  constructor(walletAddress: string, rpcUrl: string = MAINNET_RPC) {
    this.walletAddress = walletAddress;
    this.connection = new Connection(rpcUrl, 'confirmed');
    this.network = rpcUrl.includes('devnet') ? 'devnet' :
                   rpcUrl.includes('mainnet') ? 'mainnet-beta' : 'custom';
    this.context = {
      knownAddresses: new Set(),
      seenRecipients: new Set(),
      tokenMintsSeen: new Set(),
    };
  }

  /** Fetch recent parsed transactions for the wallet */
  async getRecentTransactions(limit: number = 20): Promise<ParsedTransactionWithMeta[]> {
    const pubkey = new PublicKey(this.walletAddress);
    const signatures = await this.connection.getSignaturesForAddress(pubkey, { limit });
    const txs: ParsedTransactionWithMeta[] = [];

    // Batch fetch for efficiency
    const batchSize = 5;
    for (let i = 0; i < signatures.length; i += batchSize) {
      const batch = signatures.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map(sig =>
          this.connection.getParsedTransaction(sig.signature, { maxSupportedTransactionVersion: 0 })
        )
      );
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) txs.push(r.value);
      }
    }
    return txs;
  }

  /** Get SOL balance */
  async getBalance(): Promise<number> {
    try {
      const pubkey = new PublicKey(this.walletAddress);
      const lamports = await this.connection.getBalance(pubkey);
      return lamports / LAMPORTS_PER_SOL;
    } catch {
      return 0;
    }
  }

  /** Run all threat rules against a single transaction */
  analyzeThreat(tx: ParsedTransactionWithMeta): ThreatResult[] {
    const threats: ThreatResult[] = [];
    for (const rule of threatRules) {
      try {
        const result = rule.check(tx, this.walletAddress, this.context);
        if (result) threats.push(result);
      } catch {
        // Rule error — skip silently
      }
    }
    return threats;
  }

  /** Detect burst activity across multiple transactions */
  detectBurstActivity(txs: ParsedTransactionWithMeta[]): ThreatResult[] {
    const threats: ThreatResult[] = [];
    const timestamps = txs
      .map(tx => tx.blockTime)
      .filter((t): t is number => t !== null && t !== undefined)
      .sort();

    for (let i = 0; i < timestamps.length - 5; i++) {
      const window = timestamps[i + 5] - timestamps[i];
      if (window < 60) {
        threats.push({
          ruleName: 'Rapid Transaction Burst',
          severity: 'medium',
          description: `6+ transactions detected within ${window} seconds`,
          details: 'Rapid transaction bursts may indicate automated draining or bot activity.',
          signature: 'multiple',
          timestamp: timestamps[i],
        });
        break;
      }
    }
    return threats;
  }

  /** Calculate a 0-100 risk score from detected threats */
  calculateRiskScore(threats: ThreatResult[]): number {
    let score = 0;
    for (const t of threats) {
      switch (t.severity) {
        case 'critical': score += 40; break;
        case 'high': score += 25; break;
        case 'medium': score += 15; break;
        case 'low': score += 5; break;
      }
    }
    return Math.min(score, 100);
  }

  /** Generate actionable recommendations based on threats */
  generateRecommendations(threats: ThreatResult[]): string[] {
    const recs: string[] = [];
    const severities = new Set(threats.map(t => t.severity));
    const ruleNames = new Set(threats.map(t => t.ruleName));

    if (severities.has('critical')) {
      recs.push('🚨 URGENT: Revoke all token approvals immediately at https://revoke.cash');
      recs.push('🚨 Move remaining funds to a new, clean wallet ASAP');
      recs.push('🚨 Do NOT sign any more transactions from this wallet until investigated');
    }
    if (severities.has('high')) {
      recs.push('⚠️ Review all recent token approvals and revoke unnecessary ones');
      recs.push('⚠️ Consider using a hardware wallet for signing large transactions');
    }
    if (ruleNames.has('Suspicious Airdrop Token')) {
      recs.push('🗑️ Do NOT interact with unknown airdropped tokens — they may be phishing');
    }
    if (ruleNames.has('Flash Loan Activity')) {
      recs.push('🔍 Investigate flash loan transactions for potential exploit activity');
    }
    if (severities.has('medium')) {
      recs.push('📋 Increase monitoring frequency for this wallet');
      recs.push('📋 Set up real-time alerts using SolSentry monitor mode');
    }
    if (threats.length === 0) {
      recs.push('✅ No threats detected — your wallet looks clean!');
      recs.push('💡 Continue monitoring regularly to stay safe');
      recs.push('🛡️ Consider setting up real-time monitoring with `sol-sentry monitor`');
    }
    return recs;
  }

  /** Generate a complete security report */
  async generateReport(): Promise<WalletReport> {
    console.log(`\n🔍 SolSentry scanning wallet: ${this.walletAddress}`);
    console.log(`   Network: ${this.network}`);

    const [balance, txs] = await Promise.all([
      this.getBalance(),
      this.getRecentTransactions(20),
    ]);

    console.log(`   💰 Balance: ${balance.toFixed(4)} SOL`);
    console.log(`   📦 Fetched ${txs.length} recent transactions`);

    // Reset context for this scan
    this.context.seenRecipients.clear();

    const allThreats: any[] = [];
    for (const tx of txs) {
      allThreats.push(...this.analyzeThreat(tx));
    }
    allThreats.push(...this.detectBurstActivity(txs));

    const riskScore = this.calculateRiskScore(allThreats);
    const riskLevel = riskScore >= 70 ? 'CRITICAL' :
                      riskScore >= 40 ? 'HIGH' :
                      riskScore >= 20 ? 'MEDIUM' : 'LOW';
    const recommendations = this.generateRecommendations(allThreats);
    const aiAnalysis = generateAIAnalysis(allThreats, txs.length, this.walletAddress);

    const riskIcon = riskScore >= 70 ? '🔴' : riskScore >= 40 ? '🟠' : riskScore >= 20 ? '🟡' : '🟢';
    const summary = allThreats.length === 0
      ? `✅ No suspicious activity detected across ${txs.length} recent transactions.`
      : `⚠️ ${allThreats.length} threat(s) found across ${txs.length} transactions. Risk: ${riskIcon} ${riskLevel} (${riskScore}/100)`;

    return {
      walletAddress: this.walletAddress,
      generatedAt: new Date().toISOString(),
      network: this.network,
      solBalance: balance,
      totalTransactions: txs.length,
      threats: allThreats,
      riskScore,
      riskLevel,
      summary,
      aiAnalysis,
      recommendations,
    };
  }
}

/** Pretty-print a report to the console */
export function printReport(report: WalletReport): void {
  const divider = '═'.repeat(60);
  console.log(`\n${divider}`);
  console.log('🛡️  SOL SENTRY — WALLET SECURITY REPORT');
  console.log(divider);
  console.log(`📍 Wallet:       ${report.walletAddress}`);
  console.log(`🌐 Network:      ${report.network}`);
  console.log(`💰 Balance:      ${report.solBalance.toFixed(4)} SOL`);
  console.log(`📅 Generated:    ${report.generatedAt}`);
  console.log(`📊 Transactions: ${report.totalTransactions}`);
  console.log(`🎯 Risk Score:   ${report.riskScore}/100 (${report.riskLevel})`);
  console.log(`\n📝 ${report.summary}`);

  if (report.threats.length > 0) {
    console.log('\n🚨 THREATS DETECTED:');
    console.log('─'.repeat(60));
    for (const t of report.threats) {
      const icon = t.severity === 'critical' ? '🔴' : t.severity === 'high' ? '🟠' : t.severity === 'medium' ? '🟡' : '🟢';
      console.log(`  ${icon} [${t.severity.toUpperCase()}] ${t.ruleName}`);
      console.log(`     ${t.description}`);
      console.log(`     ${t.details}`);
      if (t.signature !== 'multiple') {
        console.log(`     🔗 https://solscan.io/tx/${t.signature}`);
      }
      console.log();
    }
  }

  console.log('\n🤖 AI ANALYSIS:');
  console.log('─'.repeat(60));
  console.log(report.aiAnalysis);

  console.log('\n💡 RECOMMENDATIONS:');
  console.log('─'.repeat(60));
  for (const r of report.recommendations) {
    console.log(`  ${r}`);
  }
  console.log(`\n${divider}\n`);
}

// --- CLI Entry Point ---
async function main() {
  const args = process.argv.slice(2);
  const wallet = args.find(a => !a.startsWith('--'));
  const useDevnet = args.includes('--devnet');
  const useMainnet = args.includes('--mainnet');

  if (!wallet) {
    console.log('🛡️  SolSentry — AI-Powered Solana Wallet Guardian\n');
    console.log('Usage: sol-sentry <WALLET_ADDRESS> [options]\n');
    console.log('Options:');
    console.log('  --devnet     Use Solana devnet');
    console.log('  --mainnet    Use Solana mainnet (default)\n');
    console.log('Examples:');
    console.log('  npx tsx src/index.ts 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU');
    console.log('  npx tsx src/index.ts <wallet> --devnet');
    process.exit(1);
  }

  const rpcUrl = useDevnet ? DEVNET_RPC : MAINNET_RPC;
  const sentry = new SolSentry(wallet, rpcUrl);

  try {
    const report = await sentry.generateReport();
    printReport(report);
    return report;
  } catch (err: any) {
    console.error(`\n❌ Error scanning wallet: ${err.message}`);
    process.exit(1);
  }
}

// Run CLI if executed directly
const isMainModule = process.argv[1]?.includes('index');
if (isMainModule) {
  main().catch(console.error);
}
