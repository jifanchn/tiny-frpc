#include <node_api.h>
#include <stdlib.h>
#include <string.h>

#include "frpc-bindings.h"

// Minimal N-API addon for TINY-FRPC.
// Goal: avoid ffi-napi (often fails to build / incompatible with newer Node versions).

#define NAPI_CALL(env, call)                                                   \
    do {                                                                       \
        napi_status _status = (call);                                          \
        if (_status != napi_ok) {                                              \
            const napi_extended_error_info* _info = NULL;                      \
            napi_get_last_error_info((env), &_info);                           \
            const char* _msg = (_info && _info->error_message) ? _info->error_message : "napi error"; \
            napi_throw_error((env), NULL, _msg);                               \
            return NULL;                                                       \
        }                                                                      \
    } while (0)

static napi_value napi_int32(napi_env env, int32_t v) {
    napi_value n;
    NAPI_CALL(env, napi_create_int32(env, v, &n));
    return n;
}

static napi_value napi_bool(napi_env env, bool v) {
    napi_value b;
    NAPI_CALL(env, napi_get_boolean(env, v, &b));
    return b;
}

static napi_value js_undefined(napi_env env) {
    napi_value u;
    NAPI_CALL(env, napi_get_undefined(env, &u));
    return u;
}

static bool is_nullish(napi_env env, napi_value v) {
    napi_valuetype t;
    if (napi_typeof(env, v, &t) != napi_ok) return true;
    return (t == napi_null || t == napi_undefined);
}

static char* get_string_utf8_alloc(napi_env env, napi_value v) {
    if (is_nullish(env, v)) return NULL;
    size_t len = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, v, NULL, 0, &len));
    char* buf = (char*)malloc(len + 1);
    if (!buf) return NULL;
    size_t out = 0;
    if (napi_get_value_string_utf8(env, v, buf, len + 1, &out) != napi_ok) {
        free(buf);
        return NULL;
    }
    buf[out] = '\0';
    return buf;
}

static bool get_named_property(napi_env env, napi_value obj, const char* name, napi_value* out) {
    bool has = false;
    if (napi_has_named_property(env, obj, name, &has) != napi_ok || !has) {
        return false;
    }
    return (napi_get_named_property(env, obj, name, out) == napi_ok);
}

typedef struct {
    frpc_handle_t handle;
    bool destroyed;
} client_wrap_t;

typedef struct {
    napi_env env;
    napi_ref on_data_ref;
    napi_ref on_conn_ref;
} tunnel_cb_ctx_t;

typedef struct {
    frpc_tunnel_handle_t tunnel;
    tunnel_cb_ctx_t* cb;
    bool destroyed;
} tunnel_wrap_t;

static tunnel_wrap_t* unwrap_tunnel(napi_env env, napi_value v) {
    tunnel_wrap_t* w = NULL;
    NAPI_CALL(env, napi_get_value_external(env, v, (void**)&w));
    return w;
}

static client_wrap_t* unwrap_client(napi_env env, napi_value v) {
    client_wrap_t* w = NULL;
    NAPI_CALL(env, napi_get_value_external(env, v, (void**)&w));
    return w;
}

static void tunnel_cb_on_data(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len, void* user_data) {
    (void)tunnel;
    tunnel_cb_ctx_t* ctx = (tunnel_cb_ctx_t*)user_data;
    if (!ctx || !ctx->env || !ctx->on_data_ref) return;

    napi_handle_scope scope;
    if (napi_open_handle_scope(ctx->env, &scope) != napi_ok) return;

    napi_value cb;
    if (napi_get_reference_value(ctx->env, ctx->on_data_ref, &cb) != napi_ok) {
        napi_close_handle_scope(ctx->env, scope);
        return;
    }

    napi_value global;
    if (napi_get_global(ctx->env, &global) != napi_ok) {
        napi_close_handle_scope(ctx->env, scope);
        return;
    }

    void* out_data = NULL;
    napi_value buf;
    if (napi_create_buffer_copy(ctx->env, len, data, &out_data, &buf) != napi_ok) {
        napi_close_handle_scope(ctx->env, scope);
        return;
    }

    napi_value argv[1] = { buf };
    napi_value result;
    (void)napi_call_function(ctx->env, global, cb, 1, argv, &result);

    napi_close_handle_scope(ctx->env, scope);
}

static void tunnel_cb_on_conn(frpc_tunnel_handle_t tunnel, int connected, int error_code, void* user_data) {
    (void)tunnel;
    tunnel_cb_ctx_t* ctx = (tunnel_cb_ctx_t*)user_data;
    if (!ctx || !ctx->env || !ctx->on_conn_ref) return;

    napi_handle_scope scope;
    if (napi_open_handle_scope(ctx->env, &scope) != napi_ok) return;

    napi_value cb;
    if (napi_get_reference_value(ctx->env, ctx->on_conn_ref, &cb) != napi_ok) {
        napi_close_handle_scope(ctx->env, scope);
        return;
    }

    napi_value global;
    if (napi_get_global(ctx->env, &global) != napi_ok) {
        napi_close_handle_scope(ctx->env, scope);
        return;
    }

    napi_value argv[2] = { napi_bool(ctx->env, connected != 0), napi_int32(ctx->env, (int32_t)error_code) };
    napi_value result;
    (void)napi_call_function(ctx->env, global, cb, 2, argv, &result);

    napi_close_handle_scope(ctx->env, scope);
}

static void finalize_client(napi_env env, void* data, void* hint) {
    (void)env; (void)hint;
    client_wrap_t* w = (client_wrap_t*)data;
    if (!w) return;
    if (!w->destroyed && w->handle) {
        frpc_destroy(w->handle);
    }
    free(w);
}

static void finalize_tunnel(napi_env env, void* data, void* hint) {
    (void)hint;
    tunnel_wrap_t* w = (tunnel_wrap_t*)data;
    if (!w) return;
    if (!w->destroyed && w->tunnel) {
        frpc_destroy_tunnel(w->tunnel);
    }
    if (w->cb) {
        if (w->cb->on_data_ref) {
            napi_delete_reference(env, w->cb->on_data_ref);
        }
        if (w->cb->on_conn_ref) {
            napi_delete_reference(env, w->cb->on_conn_ref);
        }
        free(w->cb);
    }
    free(w);
}

static napi_value js_create_client(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) {
        napi_throw_error(env, NULL, "createClient(serverAddr, serverPort, token?)");
        return NULL;
    }

    char* server_addr = get_string_utf8_alloc(env, argv[0]);
    if (!server_addr) {
        napi_throw_error(env, NULL, "invalid serverAddr");
        return NULL;
    }

    uint32_t port = 0;
    NAPI_CALL(env, napi_get_value_uint32(env, argv[1], &port));

    char* token = NULL;
    if (argc >= 3) {
        token = get_string_utf8_alloc(env, argv[2]);
    }

    frpc_handle_t h = frpc_create(server_addr, (uint16_t)port, token);
    free(server_addr);
    if (token) free(token);

    if (!h) {
        napi_throw_error(env, NULL, "frpc_create failed");
        return NULL;
    }

    client_wrap_t* w = (client_wrap_t*)calloc(1, sizeof(client_wrap_t));
    if (!w) {
        frpc_destroy(h);
        napi_throw_error(env, NULL, "out of memory");
        return NULL;
    }
    w->handle = h;
    w->destroyed = false;

    napi_value ext;
    NAPI_CALL(env, napi_create_external(env, w, finalize_client, NULL, &ext));
    return ext;
}

static napi_value js_destroy_client(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return js_undefined(env);
    client_wrap_t* w = unwrap_client(env, argv[0]);
    if (w && !w->destroyed && w->handle) {
        frpc_destroy(w->handle);
        w->destroyed = true;
        w->handle = NULL;
    }
    return js_undefined(env);
}

static napi_value js_client_connect(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    client_wrap_t* w = unwrap_client(env, argv[0]);
    if (!w || w->destroyed || !w->handle) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    int ret = frpc_connect(w->handle);
    return napi_int32(env, (int32_t)ret);
}

static napi_value js_client_disconnect(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    client_wrap_t* w = unwrap_client(env, argv[0]);
    if (!w || w->destroyed || !w->handle) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    int ret = frpc_disconnect(w->handle);
    return napi_int32(env, (int32_t)ret);
}

static napi_value js_client_is_connected(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_bool(env, false);
    client_wrap_t* w = unwrap_client(env, argv[0]);
    if (!w || w->destroyed || !w->handle) return napi_bool(env, false);
    return napi_bool(env, frpc_is_connected(w->handle));
}

static napi_value js_process_events(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    client_wrap_t* w = unwrap_client(env, argv[0]);
    if (!w || w->destroyed || !w->handle) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    int ret = frpc_process_events(w->handle);
    return napi_int32(env, (int32_t)ret);
}

static napi_value js_create_tunnel(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value argv[4];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 3) {
        napi_throw_error(env, NULL, "createTunnel(client, tunnelType, tunnelName, options?)");
        return NULL;
    }

    client_wrap_t* cw = unwrap_client(env, argv[0]);
    if (!cw || cw->destroyed || !cw->handle) {
        napi_throw_error(env, NULL, "invalid client handle");
        return NULL;
    }

    int32_t tunnel_type = 0;
    NAPI_CALL(env, napi_get_value_int32(env, argv[1], &tunnel_type));
    char* tunnel_name = get_string_utf8_alloc(env, argv[2]);
    if (!tunnel_name) {
        napi_throw_error(env, NULL, "invalid tunnelName");
        return NULL;
    }

    napi_value options = (argc >= 4) ? argv[3] : NULL;
    bool has_options = false;
    if (options) {
        napi_valuetype t;
        if (napi_typeof(env, options, &t) == napi_ok && t == napi_object) {
            has_options = true;
        }
    }

    char* secret_key = NULL;
    char* local_addr = NULL;
    uint32_t local_port = 0;
    char* remote_name = NULL;
    char* bind_addr = NULL;
    uint32_t bind_port = 0;

    tunnel_cb_ctx_t* cb = NULL;

    frpc_tunnel_config_t cfg;
    frpc_tunnel_config_init(&cfg);
    cfg.tunnel_type = tunnel_type;
    cfg.tunnel_name = tunnel_name;

    if (has_options) {
        napi_value v;
        if (get_named_property(env, options, "secretKey", &v)) secret_key = get_string_utf8_alloc(env, v);
        if (get_named_property(env, options, "localAddr", &v)) local_addr = get_string_utf8_alloc(env, v);
        if (get_named_property(env, options, "localPort", &v)) (void)napi_get_value_uint32(env, v, &local_port);
        if (get_named_property(env, options, "remoteName", &v)) remote_name = get_string_utf8_alloc(env, v);
        if (get_named_property(env, options, "bindAddr", &v)) bind_addr = get_string_utf8_alloc(env, v);
        if (get_named_property(env, options, "bindPort", &v)) (void)napi_get_value_uint32(env, v, &bind_port);

        napi_value on_data;
        napi_value on_conn;
        bool has_on_data = get_named_property(env, options, "onData", &on_data);
        bool has_on_conn = get_named_property(env, options, "onConnection", &on_conn);

        if (has_on_data || has_on_conn) {
            cb = (tunnel_cb_ctx_t*)calloc(1, sizeof(tunnel_cb_ctx_t));
            if (!cb) {
                free(tunnel_name);
                if (secret_key) free(secret_key);
                if (local_addr) free(local_addr);
                if (remote_name) free(remote_name);
                if (bind_addr) free(bind_addr);
                napi_throw_error(env, NULL, "out of memory");
                return NULL;
            }
            cb->env = env;
            cb->on_data_ref = NULL;
            cb->on_conn_ref = NULL;

            if (has_on_data) {
                napi_valuetype tt;
                if (napi_typeof(env, on_data, &tt) == napi_ok && tt == napi_function) {
                    napi_create_reference(env, on_data, 1, &cb->on_data_ref);
                    cfg.data_callback = tunnel_cb_on_data;
                }
            }
            if (has_on_conn) {
                napi_valuetype tt;
                if (napi_typeof(env, on_conn, &tt) == napi_ok && tt == napi_function) {
                    napi_create_reference(env, on_conn, 1, &cb->on_conn_ref);
                    cfg.connection_callback = tunnel_cb_on_conn;
                }
            }

            if (cb->on_data_ref || cb->on_conn_ref) {
                cfg.user_data = cb;
            }
        }
    }

    cfg.secret_key = secret_key;
    cfg.local_addr = local_addr;
    cfg.local_port = (uint16_t)local_port;
    cfg.remote_name = remote_name;
    cfg.bind_addr = bind_addr;
    cfg.bind_port = (uint16_t)bind_port;

    frpc_tunnel_handle_t th = frpc_create_tunnel(cw->handle, &cfg);

    free(tunnel_name);
    if (secret_key) free(secret_key);
    if (local_addr) free(local_addr);
    if (remote_name) free(remote_name);
    if (bind_addr) free(bind_addr);

    if (!th) {
        if (cb) {
            if (cb->on_data_ref) napi_delete_reference(env, cb->on_data_ref);
            if (cb->on_conn_ref) napi_delete_reference(env, cb->on_conn_ref);
            free(cb);
        }
        napi_throw_error(env, NULL, "frpc_create_tunnel failed");
        return NULL;
    }

    tunnel_wrap_t* tw = (tunnel_wrap_t*)calloc(1, sizeof(tunnel_wrap_t));
    if (!tw) {
        frpc_destroy_tunnel(th);
        if (cb) {
            if (cb->on_data_ref) napi_delete_reference(env, cb->on_data_ref);
            if (cb->on_conn_ref) napi_delete_reference(env, cb->on_conn_ref);
            free(cb);
        }
        napi_throw_error(env, NULL, "out of memory");
        return NULL;
    }
    tw->tunnel = th;
    tw->cb = cb;
    tw->destroyed = false;

    napi_value ext;
    NAPI_CALL(env, napi_create_external(env, tw, finalize_tunnel, NULL, &ext));
    return ext;
}

static napi_value js_destroy_tunnel(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return js_undefined(env);
    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (w && !w->destroyed && w->tunnel) {
        frpc_destroy_tunnel(w->tunnel);
        w->destroyed = true;
        w->tunnel = NULL;
    }
    return js_undefined(env);
}

static napi_value js_tunnel_start(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (!w || w->destroyed || !w->tunnel) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    int ret = frpc_start_tunnel(w->tunnel);
    return napi_int32(env, (int32_t)ret);
}

static napi_value js_tunnel_stop(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (!w || w->destroyed || !w->tunnel) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    int ret = frpc_stop_tunnel(w->tunnel);
    return napi_int32(env, (int32_t)ret);
}

static napi_value js_tunnel_send(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);
    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (!w || w->destroyed || !w->tunnel) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);

    bool is_buf = false;
    NAPI_CALL(env, napi_is_buffer(env, argv[1], &is_buf));
    if (!is_buf) {
        napi_throw_type_error(env, NULL, "sendData expects a Buffer");
        return NULL;
    }
    void* data = NULL;
    size_t len = 0;
    NAPI_CALL(env, napi_get_buffer_info(env, argv[1], &data, &len));
    int ret = frpc_send_data(w->tunnel, (const uint8_t*)data, len);
    return napi_int32(env, (int32_t)ret);
}

// Inject a "raw Yamux frame" into a tunnel (for tests or advanced use cases).
// Args: tunnelHandle, frameBuffer (12-byte header + payload)
static napi_value js_tunnel_inject_yamux_frame(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);

    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (!w || w->destroyed || !w->tunnel) return napi_int32(env, FRPC_ERROR_INVALID_PARAM);

    bool is_buf = false;
    NAPI_CALL(env, napi_is_buffer(env, argv[1], &is_buf));
    if (!is_buf) {
        napi_throw_type_error(env, NULL, "tunnelInjectYamuxFrame expects a Buffer");
        return NULL;
    }

    void* data = NULL;
    size_t len = 0;
    NAPI_CALL(env, napi_get_buffer_info(env, argv[1], &data, &len));
    int ret = frpc_tunnel_inject_yamux_frame(w->tunnel, (const uint8_t*)data, len);
    return napi_int32(env, (int32_t)ret);
}

static napi_value js_tunnel_is_active(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return napi_bool(env, false);
    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (!w || w->destroyed || !w->tunnel) return napi_bool(env, false);
    return napi_bool(env, frpc_is_tunnel_active(w->tunnel));
}

static napi_value js_tunnel_get_stats(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return NULL;
    tunnel_wrap_t* w = unwrap_tunnel(env, argv[0]);
    if (!w || w->destroyed || !w->tunnel) return NULL;

    frpc_tunnel_stats_t s;
    memset(&s, 0, sizeof(s));
    int ret = frpc_get_tunnel_stats(w->tunnel, &s);
    if (ret != 0) return NULL;

    napi_value obj;
    NAPI_CALL(env, napi_create_object(env, &obj));
    napi_value v;

    NAPI_CALL(env, napi_create_uint32(env, s.connections_active, &v));
    NAPI_CALL(env, napi_set_named_property(env, obj, "connectionsActive", v));
    NAPI_CALL(env, napi_create_uint32(env, s.connections_total, &v));
    NAPI_CALL(env, napi_set_named_property(env, obj, "connectionsTotal", v));

    // uint64 fields as BigInt
    NAPI_CALL(env, napi_create_bigint_uint64(env, s.bytes_sent, &v));
    NAPI_CALL(env, napi_set_named_property(env, obj, "bytesSent", v));
    NAPI_CALL(env, napi_create_bigint_uint64(env, s.bytes_received, &v));
    NAPI_CALL(env, napi_set_named_property(env, obj, "bytesReceived", v));
    NAPI_CALL(env, napi_create_bigint_uint64(env, s.last_activity_time, &v));
    NAPI_CALL(env, napi_set_named_property(env, obj, "lastActivityTime", v));

    return obj;
}

static napi_value js_get_error_message(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return NULL;
    int32_t code = 0;
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));
    const char* msg = frpc_get_error_message(code);
    napi_value s;
    NAPI_CALL(env, napi_create_string_utf8(env, msg ? msg : "Unknown error", NAPI_AUTO_LENGTH, &s));
    return s;
}

static napi_value js_cleanup(napi_env env, napi_callback_info info) {
    (void)info;
    frpc_cleanup();
    return js_undefined(env);
}

static napi_value init(napi_env env, napi_value exports) {
    // Initialize core once.
    (void)frpc_init();

    napi_property_descriptor props[] = {
        { "createClient", 0, js_create_client, 0, 0, 0, napi_default, 0 },
        { "destroyClient", 0, js_destroy_client, 0, 0, 0, napi_default, 0 },
        { "clientConnect", 0, js_client_connect, 0, 0, 0, napi_default, 0 },
        { "clientDisconnect", 0, js_client_disconnect, 0, 0, 0, napi_default, 0 },
        { "clientIsConnected", 0, js_client_is_connected, 0, 0, 0, napi_default, 0 },
        { "processEvents", 0, js_process_events, 0, 0, 0, napi_default, 0 },
        { "createTunnel", 0, js_create_tunnel, 0, 0, 0, napi_default, 0 },
        { "destroyTunnel", 0, js_destroy_tunnel, 0, 0, 0, napi_default, 0 },
        { "tunnelStart", 0, js_tunnel_start, 0, 0, 0, napi_default, 0 },
        { "tunnelStop", 0, js_tunnel_stop, 0, 0, 0, napi_default, 0 },
        { "tunnelSend", 0, js_tunnel_send, 0, 0, 0, napi_default, 0 },
        { "tunnelInjectYamuxFrame", 0, js_tunnel_inject_yamux_frame, 0, 0, 0, napi_default, 0 },
        { "tunnelIsActive", 0, js_tunnel_is_active, 0, 0, 0, napi_default, 0 },
        { "tunnelGetStats", 0, js_tunnel_get_stats, 0, 0, 0, napi_default, 0 },
        { "getErrorMessage", 0, js_get_error_message, 0, 0, 0, napi_default, 0 },
        { "cleanup", 0, js_cleanup, 0, 0, 0, napi_default, 0 },
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props));
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)


