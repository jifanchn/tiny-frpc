/**
 * Example: STCP Visitor using Node.js FRPC bindings
 * This example creates an STCP visitor that connects to a remote STCP server.
 */

const { FRPCClient, TunnelType, cleanup } = require('./frpc_node');
const net = require('net');

// Configuration
const config = {
    serverAddr: '127.0.0.1',
    serverPort: 7000,
    token: 'test_token',
    tunnelName: 'nodejs_stcp_visitor',
    secretKey: 'nodejs_secret',
    remoteName: 'python_stcp_server', // Connect to the Python server example
    bindAddr: '127.0.0.1',
    bindPort: 9090
};

console.log('Node.js FRPC STCP Visitor Example');
console.log(`Connecting to FRP server: ${config.serverAddr}:${config.serverPort}`);
console.log(`Tunnel: ${config.tunnelName}`);
console.log(`Remote server: ${config.remoteName}`);
console.log(`Local bind: ${config.bindAddr}:${config.bindPort}`);
console.log('Press Ctrl+C to exit\n');

let client = null;
let tunnel = null;
let localServer = null;

async function startLocalServer() {
    return new Promise((resolve, reject) => {
        localServer = net.createServer((socket) => {
            console.log(`Local client connected: ${socket.remoteAddress}:${socket.remotePort}`);
            
            socket.on('data', (data) => {
                console.log(`Forwarding data to tunnel: ${data.toString()}`);
                try {
                    tunnel.sendData(data);
                } catch (error) {
                    console.error('Error sending data through tunnel:', error);
                }
            });
            
            socket.on('close', () => {
                console.log('Local client disconnected');
            });
            
            socket.on('error', (error) => {
                console.error('Local socket error:', error);
            });
        });
        
        localServer.listen(config.bindPort, config.bindAddr, () => {
            console.log(`Local server listening on ${config.bindAddr}:${config.bindPort}`);
            resolve();
        });
        
        localServer.on('error', reject);
    });
}

async function main() {
    try {
        // Start local server first
        await startLocalServer();
        
        // Create FRPC client
        client = new FRPCClient(config.serverAddr, config.serverPort, config.token);
        
        // Create STCP visitor tunnel
        tunnel = client.createTunnel(TunnelType.STCP_VISITOR, config.tunnelName, {
            secretKey: config.secretKey,
            remoteName: config.remoteName,
            bindAddr: config.bindAddr,
            bindPort: config.bindPort,
            onData: (data) => {
                console.log(`Received data from tunnel: ${data.toString()}`);
                // In a real implementation, you'd forward this to the appropriate local connection
            },
            onConnection: (connected, errorCode) => {
                if (connected) {
                    console.log('Visitor tunnel connected successfully');
                } else {
                    console.log(`Visitor tunnel disconnected (error: ${errorCode})`);
                }
            }
        });
        
        // Set up event handlers
        client.on('connected', () => {
            console.log('Client connected to FRP server');
            tunnel.start();
        });
        
        client.on('disconnected', () => {
            console.log('Client disconnected from FRP server');
        });
        
        client.on('error', (error) => {
            console.error('Client error:', error);
        });
        
        tunnel.on('started', () => {
            console.log('STCP visitor tunnel started');
            console.log('You can now connect to the local server to test the tunnel');
        });
        
        tunnel.on('error', (error) => {
            console.error('Tunnel error:', error);
        });
        
        // Connect to FRP server
        console.log('Connecting to FRP server...');
        client.connect();
        
        // Show stats periodically
        const statsInterval = setInterval(() => {
            if (client.isConnected() && tunnel.isActive()) {
                const stats = tunnel.getStats();
                console.log(`Stats - Sent: ${stats.bytesSent} bytes, ` +
                           `Received: ${stats.bytesReceived} bytes, ` +
                           `Active connections: ${stats.connectionsActive}`);
            } else {
                console.log('Warning: Client disconnected or tunnel inactive');
            }
        }, 10000); // Every 10 seconds
        
        // Graceful shutdown
        process.on('SIGINT', () => {
            console.log('\nShutting down...');
            clearInterval(statsInterval);
            
            if (localServer) {
                localServer.close();
            }
            if (client) {
                client.close();
            }
            cleanup();
            
            console.log('Cleanup completed');
            process.exit(0);
        });
        
        // Keep the process running
        console.log('STCP visitor is running. Waiting for connections...');
        
    } catch (error) {
        console.error('Error:', error);
        
        // Cleanup on error
        if (localServer) {
            localServer.close();
        }
        if (client) {
            client.close();
        }
        cleanup();
        
        process.exit(1);
    }
}

// Test function to send data through the tunnel
function testTunnel() {
    if (!tunnel || !tunnel.isActive()) {
        console.log('Tunnel not active, cannot send test data');
        return;
    }
    
    const testData = `Hello from Node.js visitor at ${new Date().toISOString()}`;
    console.log(`Sending test data: ${testData}`);
    
    try {
        tunnel.sendData(testData);
    } catch (error) {
        console.error('Error sending test data:', error);
    }
}

// Export test function for external use
module.exports = { testTunnel };

// Run if this is the main module
if (require.main === module) {
    main();
}