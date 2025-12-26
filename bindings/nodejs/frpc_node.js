/**
 * Node.js bindings for TINY-FRPC (native N-API addon).
 *
 * Notes:
 * - Avoids ffi-napi (often fails to build / incompatible with newer Node versions).
 * - Uses node-gyp to build a small N-API addon and links to the shared library in `../../build`.
 */

const path = require('path');
const EventEmitter = require('events');

const native = require(path.join(__dirname, 'build', 'Release', 'frpc_native.node'));

// Constants (keep in sync with frpc-bindings.h / frpc.h).
const LogLevel = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3
};

const TunnelType = {
  STCP_SERVER: 0,
  STCP_VISITOR: 1,
  TCP: 2,
  UDP: 3,
  HTTP: 4,
  HTTPS: 5
};

const ErrorCode = {
  SUCCESS: 0,
  INVALID_PARAM: -1,
  MEMORY: -2,
  NETWORK: -3,
  AUTH: -4,
  TIMEOUT: -5,
  PROTO: -6,
  INTERNAL: -7,
  CONNECTION_CLOSED: -8,
  CONNECTION_CLOSED_BY_REMOTE: -9,
  STREAM_NOT_WRITABLE: -10
};

class FRPCError extends Error {
  constructor(errorCode, message) {
    const msg = message || native.getErrorMessage(errorCode);
    super(`FRPC Error ${errorCode}: ${msg}`);
    this.errorCode = errorCode;
  }
}

class FRPCClient extends EventEmitter {
  constructor(serverAddr, serverPort, token = null, options = {}) {
    super();
    this._handle = native.createClient(serverAddr, serverPort, token);
    this._tunnels = new Map();
    this._eventTimer = null;
    
    // Set encryption (default true for real FRPS, set false for mock FRPS)
    const useEncryption = options.useEncryption !== undefined ? options.useEncryption : true;
    native.clientSetEncryption(this._handle, useEncryption);
  }

  connect() {
    const ret = native.clientConnect(this._handle);
    if (ret !== 0) {
      throw new FRPCError(ret);
    }
    this._startEventLoop();
    this.emit('connected');
  }

  disconnect() {
    this._stopEventLoop();
    const ret = native.clientDisconnect(this._handle);
    if (ret !== 0) {
      throw new FRPCError(ret);
    }
    this.emit('disconnected');
  }

  close() {
    try {
      // Best-effort shutdown.
      this.disconnect();
    } catch (_) {
      // ignore
    }
    for (const t of this._tunnels.values()) {
      try {
        t.close();
      } catch (_) {
        // ignore
      }
    }
    this._tunnels.clear();
    native.destroyClient(this._handle);
  }

  isConnected() {
    return native.clientIsConnected(this._handle);
  }

  createTunnel(tunnelType, tunnelName, options = {}) {
    const tunnel = new FRPCTunnel(this, tunnelType, tunnelName, options);
    this._tunnels.set(tunnelName, tunnel);
    return tunnel;
  }

  _startEventLoop() {
    if (this._eventTimer) return;
    this._eventTimer = setInterval(() => {
      try {
        native.processEvents(this._handle);
      } catch (e) {
        this.emit('error', e);
      }
    }, 10);
  }

  _stopEventLoop() {
    if (!this._eventTimer) return;
    clearInterval(this._eventTimer);
    this._eventTimer = null;
  }
}

class FRPCTunnel extends EventEmitter {
  constructor(client, tunnelType, tunnelName, options = {}) {
    super();
    this.client = client;
    this.tunnelType = tunnelType;
    this.tunnelName = tunnelName;

    // The native addon reads these fields from options:
    // secretKey/localAddr/localPort/remoteName/bindAddr/bindPort
    // and optional callbacks: onData/onConnection
    this._handle = native.createTunnel(client._handle, tunnelType, tunnelName, options);
  }

  start() {
    const ret = native.tunnelStart(this._handle);
    if (ret !== 0) {
      throw new FRPCError(ret);
    }
    this.emit('started');
  }

  stop() {
    const ret = native.tunnelStop(this._handle);
    if (ret !== 0) {
      throw new FRPCError(ret);
    }
    this.emit('stopped');
  }

  sendData(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    const ret = native.tunnelSend(this._handle, buf);
    if (ret < 0) {
      throw new FRPCError(ret);
    }
    return ret;
  }

  /**
   * Inject a "raw Yamux frame" (12-byte header + payload) into the tunnel.
   * Mainly used for tests: trigger onData callback, cover stats fields, etc.
   */
  injectYamuxFrame(frame) {
    const buf = Buffer.isBuffer(frame) ? frame : Buffer.from(frame);
    const ret = native.tunnelInjectYamuxFrame(this._handle, buf);
    if (ret < 0) {
      throw new FRPCError(ret);
    }
    return ret;
  }

  getStats() {
    return native.tunnelGetStats(this._handle);
  }

  isActive() {
    return native.tunnelIsActive(this._handle);
  }

  close() {
    native.destroyTunnel(this._handle);
    this.emit('closed');
  }
}

function cleanup() {
  native.cleanup();
}

module.exports = {
  FRPCClient,
  FRPCTunnel,
  FRPCError,
  LogLevel,
  TunnelType,
  ErrorCode,
  cleanup
};


