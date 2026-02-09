/**
 * SolSentry REST API Server
 * 
 * Provides HTTP endpoints for wallet scanning, designed to be
 * consumed by other agents, MCP tools, or frontend applications.
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { SolSentry, WalletReport, MAINNET_RPC, DEVNET_RPC } from './index.js';

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

// --- Simple Router ---

type Handler = (req: IncomingMessage, res: ServerResponse, params: Record<string, string>) => Promise<void>;

interface Route {
  method: string;
  pattern: RegExp;
  paramNames: string[];
  handler: Handler;
}

const routes: Route[] = [];

function addRoute(method: string, path: string, handler: Handler) {
  const paramNames: string[] = [];
  const pattern = new RegExp(
    '^' + path.replace(/:(\w+)/g, (_, name) => {
      paramNames.push(name);
      return '([^/]+)';
    }) + '$'
  );
  routes.push({ method, pattern, paramNames, handler });
}

function jsonResponse(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
  });
  res.end(JSON.stringify(data, null, 2));
}

// --- Cache (simple TTL) ---
const cache = new Map<string, { report: WalletReport; expires: number }>();
const CACHE_TTL_MS = 60_000; // 1 minute

// --- Routes ---

// Health check
addRoute('GET', '/health', async (_req, res) => {
  jsonResponse(res, 200, {
    status: 'ok',
    service: 'sol-sentry',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// Scan a wallet
addRoute('GET', '/scan/:wallet', async (req, res, params) => {
  const wallet = params.wallet;
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const network = url.searchParams.get('network') || 'mainnet';
  const noCache = url.searchParams.get('nocache') === 'true';

  // Validate wallet address (base58, 32-44 chars)
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(wallet)) {
    jsonResponse(res, 400, { error: 'Invalid Solana wallet address' });
    return;
  }

  const cacheKey = `${wallet}:${network}`;

  // Check cache
  if (!noCache) {
    const cached = cache.get(cacheKey);
    if (cached && cached.expires > Date.now()) {
      jsonResponse(res, 200, { ...cached.report, cached: true });
      return;
    }
  }

  try {
    const rpcUrl = network === 'devnet' ? DEVNET_RPC : MAINNET_RPC;
    const sentry = new SolSentry(wallet, rpcUrl);
    const report = await sentry.generateReport();

    // Cache the result
    cache.set(cacheKey, { report, expires: Date.now() + CACHE_TTL_MS });

    jsonResponse(res, 200, report);
  } catch (err: any) {
    jsonResponse(res, 500, { error: `Scan failed: ${err.message}` });
  }
});

// List threat rules
addRoute('GET', '/rules', async (_req, res) => {
  jsonResponse(res, 200, {
    rules: [
      { name: 'Large SOL Transfer', severity: 'high', description: 'Detects outflows > 10 SOL' },
      { name: 'Known Scam Program', severity: 'critical', description: 'Flags known malicious programs' },
      { name: 'Unlimited Token Approval', severity: 'high', description: 'Detects unlimited approvals' },
      { name: 'First-Time Recipient', severity: 'low', description: 'Flags new recipient addresses' },
      { name: 'NFT Drainer Pattern', severity: 'critical', description: 'Detects NFT drainer attacks' },
      { name: 'Suspicious Airdrop Token', severity: 'medium', description: 'Flags known scam airdrops' },
      { name: 'Flash Loan Activity', severity: 'medium', description: 'Detects flash loan patterns' },
      { name: 'Complex Transaction', severity: 'low', description: 'Flags unusually complex txs' },
      { name: 'Mass Account Closure', severity: 'medium', description: 'Detects bulk account closing' },
      { name: 'Rapid Transaction Burst', severity: 'medium', description: 'Detects tx bursts < 60s' },
    ],
  });
});

// --- Server ---

const server = createServer(async (req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  const pathname = new URL(req.url || '/', `http://${req.headers.host}`).pathname;

  for (const route of routes) {
    if (req.method !== route.method) continue;
    const match = pathname.match(route.pattern);
    if (match) {
      const params: Record<string, string> = {};
      route.paramNames.forEach((name, i) => { params[name] = match[i + 1]; });
      try {
        await route.handler(req, res, params);
      } catch (err: any) {
        jsonResponse(res, 500, { error: err.message });
      }
      return;
    }
  }

  // 404
  jsonResponse(res, 404, {
    error: 'Not found',
    endpoints: [
      'GET /health',
      'GET /scan/:wallet?network=mainnet|devnet&nocache=true',
      'GET /rules',
    ],
  });
});

// Start server when run directly
const isMain = process.argv[1]?.includes('api');
if (isMain) {
  server.listen(PORT, HOST, () => {
    console.log(`🛡️  SolSentry API running at http://${HOST}:${PORT}`);
    console.log(`   Endpoints:`);
    console.log(`     GET /health`);
    console.log(`     GET /scan/:wallet`);
    console.log(`     GET /rules`);
  });
}

export { server };
