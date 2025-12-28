const readline = require('readline');
const path = require('path');
const { FRPCClient, TunnelType } = require('../../../bindings/nodejs/frpc_node');

if (process.argv.length < 5) {
    console.log(`Usage: node ${path.basename(__filename)} <server_addr> <server_port> <visitor_name>`);
    process.exit(1);
}

const host = process.argv[2];
const port = parseInt(process.argv[3]);
const name = process.argv[4];

console.log(`Starting Node.js STCP Visitor '${name}' connecting to ${host}:${port}...`);

const client = new FRPCClient(host, port, "test_token", { useEncryption: true });

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: '> '
});

const tunnel = client.createTunnel(TunnelType.STCP_VISITOR, `visitor_${name}`, {
    secretKey: "p3_test_secret",
    remoteName: "p3_test_stcp",
    onData: (data) => {
        const msg = data.toString('utf8').trim();
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

console.log("Visitor started.");
rl.prompt();

rl.on('line', (line) => {
    line = line.trim();
    if (line === 'quit') {
        client.disconnect();
        process.exit(0);
    }
    if (line) {
        try {
            tunnel.sendData(`[${name}] ${line}`);
        } catch (e) {
            console.error(`Send failed: ${e.message}`);
        }
    }
    rl.prompt();
});
