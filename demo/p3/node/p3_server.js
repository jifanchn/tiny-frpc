const readline = require('readline');
const path = require('path');
const { FRPCClient, TunnelType } = require('../../../bindings/nodejs/frpc_node');

if (process.argv.length < 4) {
    console.log(`Usage: node ${path.basename(__filename)} <server_addr> <server_port>`);
    process.exit(1);
}

const host = process.argv[2];
const port = parseInt(process.argv[3]);

console.log(`Starting Node.js STCP Server connecting to ${host}:${port}...`);

const client = new FRPCClient(host, port, "test_token", { useEncryption: true });

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: '> '
});

const tunnel = client.createTunnel(TunnelType.STCP_SERVER, "p3_test_stcp", {
    secretKey: "p3_test_secret",
    localAddr: "127.0.0.1",
    localPort: 0,
    onData: (data) => {
        const msg = data.toString('utf8').trim();
        // Clear current line to avoid mess with prompt
        if (process.stdout.clearLine && process.stdout.cursorTo) {
            process.stdout.clearLine(0);
            process.stdout.cursorTo(0);
        }
        console.log(`[Received] ${msg}`);
        rl.prompt(true);
    },
    onConnection: (connected, error) => {
        if (process.stdout.clearLine && process.stdout.cursorTo) {
            process.stdout.clearLine(0);
            process.stdout.cursorTo(0);
        }
        const status = connected ? "Connected" : "Disconnected";
        console.log(`[Status] ${status} (error: ${error})`);
        rl.prompt(true);
    }
});

client.connect();
tunnel.start();

console.log("Server started. Waiting for visitors...");
rl.prompt();

rl.on('line', (line) => {
    line = line.trim();
    if (line === 'quit') {
        client.disconnect();
        process.exit(0);
    }
    if (line) {
        try {
            tunnel.sendData(`[Server] ${line}`);
        } catch (e) {
            console.error(`Send failed: ${e.message}`);
        }
    }
    rl.prompt();
});
