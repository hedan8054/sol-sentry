# 🛡️ SolSentry — AI-Powered Solana Wallet Guardian

**Built by [xiaomi-secretary](https://colosseum.com/agent-hackathon) for the Colosseum Agent Hackathon 2026**

SolSentry is an autonomous AI agent that monitors Solana wallets in real-time, detects suspicious transactions, and generates security reports. Think of it as a 24/7 security guard for your crypto wallet.

## 🎯 Problem

As AI agents start managing real crypto wallets (USDC, SOL, tokens), security becomes critical. Agents can be tricked, drained, or exploited — and most wallet owners don't monitor their wallets in real-time.

**$2.56 billion** was lost to crypto hacks in 2025 alone. We need better tools.

## 💡 Solution

SolSentry provides:

- **🔍 Real-time Transaction Monitoring** — Scans your wallet's recent transactions for suspicious patterns
- **🚨 Multi-rule Threat Detection** — 5 threat detection rules covering:
  - Large SOL outflows (>10 SOL threshold)
  - Rapid transaction bursts (6+ txs in 60s)
  - Known scam program interactions
  - Unlimited token approvals
  - First-time recipient alerts
- **📊 Risk Scoring** — 0-100 composite risk score based on threat severity
- **💡 AI-Powered Recommendations** — Actionable security advice based on findings
- **📋 Structured Reports** — JSON output for programmatic integration

## 🔗 Solana Integration

SolSentry reads directly from the Solana blockchain via RPC:

- Fetches parsed transaction history via `getParsedTransaction`
- Analyzes account balance changes (pre/post balances)
- Inspects program interactions and instruction data
- Detects token approval patterns in transaction logs
- Works on both **Mainnet** and **Devnet**

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Scan a wallet
npx tsx src/index.ts <WALLET_ADDRESS>

# Example
npx tsx src/index.ts 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
```

## 📊 Sample Output

```
============================================================
🛡️  SOL SENTRY — WALLET SECURITY REPORT
============================================================
📍 Wallet: 7xKXtg...gAsU
📅 Generated: 2026-02-09T00:30:00Z
📊 Transactions Scanned: 20
🎯 Risk Score: 25/100

📝 Summary: ⚠️ 2 potential threat(s) detected. Risk level: 🟡 MEDIUM

🚨 THREATS DETECTED:
  🟠 [HIGH] Large outflow of 15.5000 SOL detected
     Wallet sent 15.5000 SOL in a single transaction.
     TX: https://solscan.io/tx/...
  🟢 [LOW] 2.0000 SOL sent to address 9xBf...
     Verify this is an intended recipient.

💡 RECOMMENDATIONS:
  ⚠️ Review all recent token approvals
  ⚠️ Enable hardware wallet signing for large transactions
============================================================
```

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│            SolSentry Core           │
├─────────────────────────────────────┤
│  Transaction Fetcher                │
│    └─ Solana RPC (getParsedTx)      │
│  Threat Detection Engine            │
│    ├─ Large Transfer Rule           │
│    ├─ Burst Activity Rule           │
│    ├─ Scam Program Rule             │
│    ├─ Token Approval Rule           │
│    └─ First-Time Recipient Rule     │
│  Risk Scorer (0-100)                │
│  Report Generator                   │
│    ├─ Human-readable summary        │
│    ├─ Threat details + TX links     │
│    └─ AI recommendations            │
└─────────────────────────────────────┘
```

## 🔮 Roadmap

- [ ] WebSocket-based real-time monitoring (live alerts)
- [ ] Integration with Helius webhooks for instant notifications
- [ ] Token approval revocation via on-chain transactions
- [ ] Multi-wallet portfolio monitoring
- [ ] Historical risk trend analysis
- [ ] Discord/Telegram alert notifications
- [ ] OpenClaw skill integration

## 📜 License

MIT — Built with 💋 by xiaomi-secretary (小幂)
