/**
 * Node.js bindings smoke/unit tests (cover critical paths as much as possible).
 *
 * Notes:
 * - Does NOT require a real FRPS (uses a minimal mock server for Login/LoginResp only).
 * - Coverage: connect success, auth failure, protocol error, tunnel start/stop, stats, inject Yamux frame -> onData.
 */

const assert = require('assert');
const { Worker } = require('worker_threads');

const { FRPCClient, TunnelType, ErrorCode, cleanup } = require('./frpc_node');

function startMockFrps(mode) {
  // mode: 'ok' | 'auth_fail' | 'wrong_type' | 'missing_run_id'
  //
  // IMPORTANT: FRPCClient.connect() is a synchronous native call and will block the JS main thread.
  // Run the mock server in a Worker thread, otherwise it cannot respond.
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      `
        const net = require('net');
        const { parentPort, workerData } = require('worker_threads');

        function writeLoginRespAndClose(socket, payloadObj) {
          const respBytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
          const header = Buffer.alloc(9);
          const t = workerData.mode === 'wrong_type' ? 'X' : '1';
          header.writeUInt8(t.charCodeAt(0), 0);
          header.writeBigInt64BE(BigInt(respBytes.length), 1);
          // Write response and close the connection to allow the server to shutdown cleanly.
          socket.end(Buffer.concat([header, respBytes]));
        }

        const sockets = new Set();

        const server = net.createServer((socket) => {
          sockets.add(socket);
          socket.on('close', () => sockets.delete(socket));
          let buf = Buffer.alloc(0);
          socket.on('data', (chunk) => {
            buf = Buffer.concat([buf, chunk]);
            while (buf.length >= 9) {
              const len = Number(buf.readBigInt64BE(1));
              if (len < 0 || len > 1024 * 1024) {
                socket.destroy();
                return;
              }
              if (buf.length < 9 + len) return;
              buf = buf.slice(9 + len); // consume Login

              let resp;
              if (workerData.mode === 'auth_fail') {
                resp = { version: '0.62.1', error: 'bad token' };
              } else if (workerData.mode === 'missing_run_id') {
                resp = { version: '0.62.1' };
              } else {
                resp = { version: '0.62.1', run_id: 'node_test_run_id' };
              }
              writeLoginRespAndClose(socket, resp);
            }
          });
        });

        server.listen(0, '127.0.0.1', () => {
          parentPort.postMessage({ port: server.address().port });
        });

        parentPort.on('message', (msg) => {
          if (msg && msg.cmd === 'close') {
            for (const s of sockets) {
              try { s.destroy(); } catch (_) {}
            }
            server.close(() => process.exit(0));
          }
        });
      `,
      { eval: true, workerData: { mode } }
    );

    worker.on('message', (m) => {
      if (m && m.port) {
        resolve({
          port: m.port,
          close: () => {
            return new Promise((res) => {
              worker.once('exit', () => res());
              worker.postMessage({ cmd: 'close' });
            });
          }
        });
      }
    });
    worker.on('error', reject);
  });
}

async function main() {
  // Positive: connect success + create/start/stop tunnels + send/stats + inject Yamux frame -> onData.
  {
    const { port, close } = await startMockFrps('ok');
    const client = new FRPCClient('127.0.0.1', port, 'test_token');
    try {
      client.connect();

      const t1 = client.createTunnel(TunnelType.STCP_SERVER, 'node_stcp_server', {
        secretKey: 'node_secret',
        localAddr: '127.0.0.1',
        localPort: 8080
      });
      t1.start();
      t1.stop();
      t1.close();

      let got = null;
      const t2 = client.createTunnel(TunnelType.STCP_VISITOR, 'node_stcp_visitor', {
        secretKey: 'node_secret',
        remoteName: 'remote_server',
        bindAddr: '127.0.0.1',
        bindPort: 9090,
        onData: (buf) => {
          got = Buffer.from(buf);
        }
      });
      t2.start();
      const n = t2.sendData(Buffer.from('hello-from-nodejs'));
      assert(n > 0, 'expected sendData > 0');

      // Inject a Yamux DATA frame: version=0, type=DATA(0), flags=0, stream_id=1, length=payload
      const payload = Buffer.from('inbound-from-nodejs', 'utf8');
      const hdr = Buffer.alloc(12);
      hdr.writeUInt8(0, 0);
      hdr.writeUInt8(0, 1);
      hdr.writeUInt16BE(0, 2);
      hdr.writeUInt32BE(1, 4);
      hdr.writeUInt32BE(payload.length, 8);
      const frame = Buffer.concat([hdr, payload]);
      const consumed = t2.injectYamuxFrame(frame);
      assert(consumed > 0, 'expected injectYamuxFrame > 0');
      assert(got && got.equals(payload), 'expected onData to receive injected payload');

      const st = t2.getStats();
      assert(st && typeof st.bytesReceived === 'bigint', 'expected stats.bytesReceived to be BigInt');
      assert(st.bytesReceived > 0n, 'expected bytesReceived > 0');

      t2.stop();
      t2.close();
    } finally {
      client.close();
      await close();
    }
  }

  // Negative: auth failure should surface as ErrorCode.AUTH (-4).
  {
    const { port, close } = await startMockFrps('auth_fail');
    const client = new FRPCClient('127.0.0.1', port, 'bad_token');
    try {
      let ok = false;
      try {
        client.connect();
      } catch (e) {
        ok = e && e.errorCode === ErrorCode.AUTH;
      }
      assert(ok, 'expected auth failure with ErrorCode.AUTH');
    } finally {
      client.close();
      await close();
    }
  }

  // Negative: protocol errors (wrong response type / missing run_id) should surface as ErrorCode.PROTO (-6).
  {
    const { port, close } = await startMockFrps('wrong_type');
    const client = new FRPCClient('127.0.0.1', port, 'test_token');
    try {
      let ok = false;
      try {
        client.connect();
      } catch (e) {
        ok = e && e.errorCode === ErrorCode.PROTO;
      }
      assert(ok, 'expected proto failure with ErrorCode.PROTO on wrong response type');
    } finally {
      client.close();
      await close();
    }
  }

  {
    const { port, close } = await startMockFrps('missing_run_id');
    const client = new FRPCClient('127.0.0.1', port, 'test_token');
    try {
      let ok = false;
      try {
        client.connect();
      } catch (e) {
        ok = e && e.errorCode === ErrorCode.PROTO;
      }
      assert(ok, 'expected proto failure with ErrorCode.PROTO on missing run_id');
    } finally {
      client.close();
      await close();
    }
  }

  cleanup();
  console.log('nodejs bindings smoke test: OK');
}

main().catch((e) => {
  console.error('nodejs bindings smoke test: FAILED', e);
  process.exit(1);
});


