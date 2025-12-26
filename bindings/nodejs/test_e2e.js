/**
 * End-to-End tests for Node.js bindings using mock FRPS server.
 *
 * This test:
 * 1. Starts a mock FRPS server (demo_stcp_frps)
 * 2. Creates STCP server and visitor tunnels
 * 3. Verifies tunnel creation and basic data flow
 * 4. Cleans up all resources
 *
 * Usage:
 *   node test_e2e.js [--frps-path /path/to/demo_stcp_frps]
 */

const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');

const { FRPCClient, TunnelType, cleanup } = require('./frpc_node');

/**
 * Find a free port on localhost
 */
function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

/**
 * Wait for a port to become available
 */
function waitForPort(host, port, timeout = 10000) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeout;
    
    function tryConnect() {
      if (Date.now() > deadline) {
        resolve(false);
        return;
      }
      
      const socket = new net.Socket();
      socket.setTimeout(500);
      
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on('error', () => {
        socket.destroy();
        setTimeout(tryConnect, 100);
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        setTimeout(tryConnect, 100);
      });
      
      socket.connect(port, host);
    }
    
    tryConnect();
  });
}

/**
 * Mock FRPS Server manager (demo_stcp_frps)
 */
class FRPSServer {
  constructor(frpsPath, bindPort) {
    this.frpsPath = frpsPath;
    this.bindPort = bindPort;
    this.process = null;
  }

  async start() {
    this.process = spawn(this.frpsPath, [
      '--listen-addr', '127.0.0.1',
      '--listen-port', String(this.bindPort),
      '--run-id', 'e2e_test_run',
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    this.process.stdout.on('data', (data) => {
      if (process.env.VERBOSE === '1') {
        console.log(`[FRPS] ${data.toString().trim()}`);
      }
    });

    this.process.stderr.on('data', (data) => {
      if (process.env.VERBOSE === '1') {
        console.error(`[FRPS ERR] ${data.toString().trim()}`);
      }
    });

    const ready = await waitForPort('127.0.0.1', this.bindPort, 10000);
    if (!ready) {
      await this.stop();
      return false;
    }

    console.log(`Mock FRPS started on port ${this.bindPort}`);
    return true;
  }

  async stop() {
    if (this.process) {
      this.process.kill('SIGTERM');
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (!this.process.killed) {
        this.process.kill('SIGKILL');
      }
      this.process = null;
    }
  }
}

/**
 * Sleep helper
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Assert helper
 */
function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

/**
 * Test STCP E2E
 * 
 * Verifies:
 * 1. Connection to FRPS
 * 2. STCP server tunnel creation and registration
 * 3. STCP visitor tunnel creation and registration
 * 4. Data sending (bytes_sent increases)
 * 5. Proper cleanup
 */
async function testStcpE2E(frps) {
  console.log('\n=== Testing STCP E2E ===');

  let serverClient = null;
  let visitorClient = null;
  let serverTunnel = null;
  let visitorTunnel = null;

  try {
    // === Create STCP Server ===
    console.log('Creating STCP server tunnel...');
    // useEncryption: false for mock frps (mock frps doesn't support encryption)
    serverClient = new FRPCClient('127.0.0.1', frps.bindPort, null, { useEncryption: false });

    serverTunnel = serverClient.createTunnel(TunnelType.STCP_SERVER, 'e2e_stcp_server', {
      secretKey: 'e2e_secret',
      localAddr: '127.0.0.1',
      localPort: 8080,
    });

    console.log('Connecting server to FRPS...');
    serverClient.connect();
    assert(serverClient.isConnected(), 'Server should be connected');
    console.log('✓ Server connected to FRPS');

    console.log('Starting server tunnel...');
    serverTunnel.start();
    await sleep(300);
    assert(serverTunnel.isActive(), 'Server tunnel should be active');
    console.log('✓ Server tunnel started and registered');

    // === Create STCP Visitor ===
    console.log('\nCreating STCP visitor tunnel...');
    visitorClient = new FRPCClient('127.0.0.1', frps.bindPort, null, { useEncryption: false });

    const visitorBindPort = await findFreePort();
    visitorTunnel = visitorClient.createTunnel(TunnelType.STCP_VISITOR, 'e2e_stcp_visitor', {
      secretKey: 'e2e_secret',
      remoteName: 'e2e_stcp_server',
      bindAddr: '127.0.0.1',
      bindPort: visitorBindPort,
    });

    console.log('Connecting visitor to FRPS...');
    visitorClient.connect();
    assert(visitorClient.isConnected(), 'Visitor should be connected');
    console.log('✓ Visitor connected to FRPS');

    console.log('Starting visitor tunnel...');
    visitorTunnel.start();
    await sleep(300);
    assert(visitorTunnel.isActive(), 'Visitor tunnel should be active');
    console.log('✓ Visitor tunnel started');

    // === Test Data Send ===
    console.log('\nTesting data send...');
    const testMessage = Buffer.from('Hello from E2E test!');
    const sent = visitorTunnel.sendData(testMessage);
    console.log(`Sent ${sent} bytes via sendData`);

    await sleep(500);

    // Verify stats
    const visitorStats = visitorTunnel.getStats();
    console.log('Visitor stats:', visitorStats);

    assert(visitorStats.bytesSent > 0n, 'Visitor should have sent bytes');
    console.log(`✓ Data sent successfully (${visitorStats.bytesSent} bytes)`);

    // === Verify connection counts ===
    const serverStats = serverTunnel.getStats();
    console.log('Server stats:', serverStats);

    assert(serverStats.connectionsTotal >= 1, 'Server should have at least 1 connection');
    assert(visitorStats.connectionsTotal >= 1, 'Visitor should have at least 1 connection');
    console.log('✓ Connection counts verified');

    console.log('\n=== STCP E2E test PASSED! ===');
    return true;
  } catch (e) {
    console.error(`\n✗ STCP E2E test FAILED: ${e.message}`);
    return false;
  } finally {
    // Cleanup
    for (const tunnel of [visitorTunnel, serverTunnel]) {
      if (tunnel) {
        try {
          tunnel.stop();
          tunnel.close();
        } catch (e) {}
      }
    }
    for (const client of [visitorClient, serverClient]) {
      if (client) {
        try {
          client.close();
        } catch (e) {}
      }
    }
  }
}

async function main() {
  let frpsPath = path.join(__dirname, '..', '..', 'build', 'demo_stcp_frps');

  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--frps-path' && args[i + 1]) {
      frpsPath = args[i + 1];
      i++;
    }
  }

  frpsPath = path.resolve(frpsPath);

  if (!fs.existsSync(frpsPath)) {
    console.error(`ERROR: demo_stcp_frps binary not found at ${frpsPath}`);
    console.error('Build it with: make demo-stcp');
    process.exit(1);
  }

  console.log(`Using mock frps: ${frpsPath}`);

  const frpsPort = await findFreePort();
  const frps = new FRPSServer(frpsPath, frpsPort);

  try {
    if (!(await frps.start())) {
      console.error('ERROR: Failed to start mock FRPS');
      process.exit(1);
    }

    const success = await testStcpE2E(frps);

    process.exit(success ? 0 : 1);
  } finally {
    cleanup();
    await frps.stop();
    console.log('Cleanup completed');
  }
}

main().catch((e) => {
  console.error('E2E test error:', e);
  process.exit(1);
});
