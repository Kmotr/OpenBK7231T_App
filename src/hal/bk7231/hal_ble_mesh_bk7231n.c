/*
 * Experimental OpenBeken-only BLE 5.1 advertisement relay.
 * This is not Bluetooth SIG Mesh and is not interoperable with SIG Mesh.
 */
#include "../../new_common.h"
#include "../../new_pins.h"
#include "../../new_cfg.h"
#include "../../cmnds/cmd_public.h"
#include "../../logging/logging.h"
#include "../../driver/drv_deviceclock.h"
#include "../hal_bt_proxy.h"
#include "../../httpserver/new_http.h"
#include "hal_ble_mesh_bk7231n.h"

#if PLATFORM_BEKEN_NEW && PLATFORM_BK7231N && ENABLE_BLE_MESH_CUSTOM
#include "include.h"
#include "ble_api.h"
#include "app_ble.h"
#include "app_ble_task.h"
#include "ble_ui.h"
#include <stdlib.h>
#include <string.h>

#define MESH_NODE_INDEX 0
#define MESH_KEY_INDEX 1
#define MESH_SEQ_INDEX 17
#define MESH_SERVICE_UUID 0xF0A1u
#define MESH_FRAME_SIZE 27
#define MESH_DATA_SIZE 31
#define MESH_NODE_MAX 254
#define MESH_TTL_MAX 254
#define MESH_DEFAULT_TTL 254
#define MESH_REPLAY_WINDOW 32
#define MESH_TIMESTAMP_OFFSET 13
#define MESH_TAG_OFFSET 19
#define MESH_MQTT_UNSYNCED_HOLD_SECONDS 5
#define MESH_RELAY_DEDUPE_SECONDS 3
#define MESH_ADV_DURATION_10MS 30

enum { MESH_POWER = 1, MESH_DIMMER = 2, MESH_RGBCW = 3, MESH_RGB = 4, MESH_TEMPERATURE = 5, MESH_OP_MAX = 5 };

typedef struct {
    uint32_t timestamp;
    uint32_t sequence;
    uint8_t source;
    uint8_t valid;
} mesh_version_t;

static uint32_t g_seen_highest[MESH_NODE_MAX + 1];
static uint32_t g_seen_window[MESH_NODE_MAX + 1];
static uint8_t g_seen_valid[MESH_NODE_MAX + 1];
static uint8_t g_mesh_sequence[3];
static bool g_sequence_loaded;
static uint32_t g_sequence_next;
static uint32_t g_sequence_reserved_until;
static uint8_t g_mesh_adv_idx = 0xFF;
static bool g_mesh_adv_creating;
static bool g_mesh_adv_pending;
static bool g_mesh_event_hooked;
static uint8_t g_mesh_pending_frame[MESH_FRAME_SIZE];
static bool g_mesh_stack_started;
static mesh_version_t g_latest_version[MESH_OP_MAX + 1];
static uint8_t g_latest_payload[MESH_OP_MAX + 1][5];
static uint32_t g_latest_mqtt_timestamp[MESH_OP_MAX + 1];
static uint32_t g_latest_mqtt_uptime[MESH_OP_MAX + 1];
static uint8_t g_latest_mqtt_valid[MESH_OP_MAX + 1];
static uint8_t g_recent_relay_payload[MESH_OP_MAX + 1][5];
static uint8_t g_recent_relay_target[MESH_OP_MAX + 1];
static uint32_t g_recent_relay_uptime[MESH_OP_MAX + 1];
static uint8_t g_recent_relay_valid[MESH_OP_MAX + 1];

static void mesh_adv_frame(const uint8_t frame[MESH_FRAME_SIZE]);

static void mesh_ble_event(ble_event_t event, void *param) {
    if (event != BLE_ACTIVITY_CREATED_IND || !param) return;
    struct ble_activity_created_ind *created = (struct ble_activity_created_ind *)param;
    if (created->actv_type == BLE_ACTV_TYPE_SCAN) {
        if (get_app_ble_scan_state() == APP_SCAN_STATE_CREATED) appm_scan_fsm_next();
        return;
    }
    if (created->actv_type != BLE_ACTV_TYPE_ADV) return;
    g_mesh_adv_idx = created->actv_idx;
    g_mesh_adv_creating = false;
    if (g_mesh_adv_pending) {
        g_mesh_adv_pending = false;
        mesh_adv_frame(g_mesh_pending_frame);
    }
}

static void mesh_install_event_hook(void) {
    if (!g_mesh_event_hooked) {
        ble_app_set_event_cb(mesh_ble_event);
        g_mesh_event_hooked = true;
    }
}

#if !ENABLE_BT_PROXY
static void mesh_scan_callback(recv_adv_t *info) {
    HAL_BLEMeshBK7231N_OnAdvertisement(info);
}
#endif

static void mesh_start_radio(void) {
#if ENABLE_BT_PROXY
    if (!g_mesh_stack_started) {
        HAL_BTProxy_Init();
        HAL_BTProxy_StartScan();
        g_mesh_stack_started = true;
    }
    mesh_install_event_hook();
#else
    if (!g_mesh_stack_started) {
        extern void ble_entry(void);
        ble_entry();
        g_mesh_stack_started = true;
        delay_ms(50);
    }
    mesh_install_event_hook();
    ble_set_recv_adv_cb(mesh_scan_callback);
    int scan_state = get_app_ble_scan_state();
    if (scan_state == APP_SCAN_STATE_IDLE || scan_state == APP_SCAN_STATE_CREATED)
        appm_scan_fsm_next();
#endif
}

/* SipHash-2-4, used here as a compact 64-bit authentication tag. */
static uint64_t rotl64(uint64_t x, unsigned n) { return (x << n) | (x >> (64 - n)); }
#define SIPROUND do { \
    v0 += v1; v1 = rotl64(v1,13); v1 ^= v0; v0 = rotl64(v0,32); \
    v2 += v3; v3 = rotl64(v3,16); v3 ^= v2; \
    v0 += v3; v3 = rotl64(v3,21); v3 ^= v0; \
    v2 += v1; v1 = rotl64(v1,17); v1 ^= v2; v2 = rotl64(v2,32); \
} while (0)

static uint64_t load64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

static uint64_t siphash24(const uint8_t key[16], const uint8_t *data, unsigned len) {
    uint64_t k0 = load64le(key), k1 = load64le(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    unsigned i = 0;
    while (i + 8 <= len) {
        uint64_t m = load64le(data + i); v3 ^= m; SIPROUND; SIPROUND; v0 ^= m; i += 8;
    }
    uint64_t b = ((uint64_t)len) << 56;
    for (unsigned j = 0; i + j < len; ++j) b |= ((uint64_t)data[i + j]) << (8 * j);
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b; v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint8_t *mesh_key(void) { return (uint8_t *)&g_cfg.unused[MESH_KEY_INDEX]; }
static uint8_t mesh_node(void) { return (uint8_t)g_cfg.unused[MESH_NODE_INDEX]; }
static int mesh_is_provisioned(void) {
    uint8_t any = 0;
    for (int i = 0; i < 16; ++i) any |= mesh_key()[i];
    return mesh_node() >= 1 && mesh_node() <= MESH_NODE_MAX && any != 0;
}

static uint32_t mesh_now(void) {
    return TIME_IsTimeSynced() ? TIME_GetCurrentTimeWithoutOffset() : 0;
}

static uint32_t mesh_frame_timestamp(const uint8_t *frame) {
    return (uint32_t)frame[MESH_TIMESTAMP_OFFSET] |
        ((uint32_t)frame[MESH_TIMESTAMP_OFFSET + 1] << 8) |
        ((uint32_t)frame[MESH_TIMESTAMP_OFFSET + 2] << 16) |
        ((uint32_t)frame[MESH_TIMESTAMP_OFFSET + 3] << 24);
}

static void mesh_set_frame_timestamp(uint8_t *frame, uint32_t timestamp) {
    frame[MESH_TIMESTAMP_OFFSET] = timestamp & 0xFF;
    frame[MESH_TIMESTAMP_OFFSET + 1] = (timestamp >> 8) & 0xFF;
    frame[MESH_TIMESTAMP_OFFSET + 2] = (timestamp >> 16) & 0xFF;
    frame[MESH_TIMESTAMP_OFFSET + 3] = (timestamp >> 24) & 0xFF;
}

static uint32_t mesh_frame_sequence(const uint8_t *frame) {
    return (uint32_t)frame[3] | ((uint32_t)frame[4] << 8) | ((uint32_t)frame[5] << 16);
}

static int mesh_version_newer(uint32_t timestamp, uint8_t source, uint32_t sequence, const mesh_version_t *current) {
    if (!current->valid) return 1;
    if (timestamp != current->timestamp) return timestamp > current->timestamp;
    if (source != current->source) return source > current->source;
    return sequence > current->sequence;
}

static unsigned mesh_payload_size(uint8_t op) {
    if (op == MESH_POWER || op == MESH_DIMMER) return 1;
    if (op == MESH_RGB) return 3;
    if (op == MESH_TEMPERATURE) return 2;
    return op == MESH_RGBCW ? 5 : 0;
}

static void mesh_version_store_frame(const uint8_t *frame, int force) {
    uint8_t op = frame[7];
    if (op == 0 || op > MESH_OP_MAX) return;
    mesh_version_t *v = &g_latest_version[op];
    if (!force && !mesh_version_newer(mesh_frame_timestamp(frame), frame[1], mesh_frame_sequence(frame), v)) return;
    v->timestamp = mesh_frame_timestamp(frame);
    v->source = frame[1];
    v->sequence = mesh_frame_sequence(frame);
    v->valid = 1;
    memcpy(g_latest_payload[op], frame + 8, mesh_payload_size(op));
}

static int mesh_accept_for_local_state(const uint8_t *frame) {
    uint8_t op = frame[7];
    if (op == 0 || op > MESH_OP_MAX) return 0;
    uint32_t timestamp = mesh_frame_timestamp(frame);
    uint32_t now_uptime = (uint32_t)g_secondsElapsed;
    if (g_latest_mqtt_valid[op]) {
        if (timestamp && g_latest_mqtt_timestamp[op] && timestamp <= g_latest_mqtt_timestamp[op]) return 0;
        if ((!timestamp || !g_latest_mqtt_timestamp[op]) &&
            (uint32_t)(now_uptime - g_latest_mqtt_uptime[op]) < MESH_MQTT_UNSYNCED_HOLD_SECONDS) return 0;
    }
    uint32_t sequence = mesh_frame_sequence(frame);
    if (!mesh_version_newer(timestamp, frame[1], sequence, &g_latest_version[op])) return 0;
    unsigned payload_size = mesh_payload_size(op);
    int changed = !g_latest_version[op].valid || memcmp(g_latest_payload[op], frame + 8, payload_size) != 0;
    mesh_version_store_frame(frame, 0);
    return changed ? 2 : 1;
}

/* Suppress the same group state arriving from several WiFi-connected spots. */
static int mesh_should_relay(const uint8_t *frame) {
    uint8_t op = frame[7];
    if (op == 0 || op > MESH_OP_MAX) return 0;
    uint32_t now = (uint32_t)g_secondsElapsed;
    unsigned payload_size = mesh_payload_size(op);
    if (g_recent_relay_valid[op] &&
        g_recent_relay_target[op] == frame[2] &&
        memcmp(g_recent_relay_payload[op], frame + 8, payload_size) == 0 &&
        (uint32_t)(now - g_recent_relay_uptime[op]) < MESH_RELAY_DEDUPE_SECONDS)
        return 0;
    memcpy(g_recent_relay_payload[op], frame + 8, payload_size);
    g_recent_relay_target[op] = frame[2];
    g_recent_relay_uptime[op] = now;
    g_recent_relay_valid[op] = 1;
    return 1;
}

static uint32_t mesh_sequence_next(void) {
    if (!g_sequence_loaded) {
        memcpy(g_mesh_sequence, &g_cfg.unused[MESH_SEQ_INDEX], sizeof(g_mesh_sequence));
        g_sequence_next = (uint32_t)g_mesh_sequence[0] | ((uint32_t)g_mesh_sequence[1] << 8) | ((uint32_t)g_mesh_sequence[2] << 16);
        g_sequence_reserved_until = g_sequence_next;
        g_sequence_loaded = true;
    }
    if (g_sequence_next >= g_sequence_reserved_until) {
        if (g_sequence_next >= 0xFFFF00u) return 0;
        g_sequence_reserved_until = g_sequence_next + 256;
        g_mesh_sequence[0] = g_sequence_reserved_until & 0xFF;
        g_mesh_sequence[1] = (g_sequence_reserved_until >> 8) & 0xFF;
        g_mesh_sequence[2] = (g_sequence_reserved_until >> 16) & 0xFF;
        memcpy(&g_cfg.unused[MESH_SEQ_INDEX], g_mesh_sequence, sizeof(g_mesh_sequence));
        CFG_MarkAsDirty();
        CFG_Save_IfThereArePendingChanges();
    }
    return ++g_sequence_next;
}

static void mesh_tag(uint8_t frame[MESH_FRAME_SIZE]) {
    uint64_t tag = siphash24(mesh_key(), frame, MESH_TAG_OFFSET);
    for (int i = 0; i < 8; ++i) frame[MESH_TAG_OFFSET + i] = (uint8_t)(tag >> (i * 8));
}

static int mesh_tag_valid(const uint8_t frame[MESH_FRAME_SIZE]) {
    uint8_t expected[8];
    uint64_t tag = siphash24(mesh_key(), frame, MESH_TAG_OFFSET);
    for (int i = 0; i < 8; ++i) expected[i] = (uint8_t)(tag >> (i * 8));
    uint8_t diff = 0;
    for (int i = 0; i < 8; ++i) diff |= expected[i] ^ frame[MESH_TAG_OFFSET + i];
    return diff == 0;
}

static int mesh_seen(uint8_t source, uint32_t sequence) {
    if (source == 0 || source > MESH_NODE_MAX || sequence == 0 || sequence > 0xFFFFFFu) return 1;
    if (!g_seen_valid[source]) {
        g_seen_valid[source] = 1;
        g_seen_highest[source] = sequence;
        g_seen_window[source] = 1;
        return 0;
    }
    if (sequence > g_seen_highest[source]) {
        uint32_t shift = sequence - g_seen_highest[source];
        g_seen_window[source] = shift >= MESH_REPLAY_WINDOW ? 1u : (g_seen_window[source] << shift) | 1u;
        g_seen_highest[source] = sequence;
        return 0;
    }
    uint32_t behind = g_seen_highest[source] - sequence;
    if (behind >= MESH_REPLAY_WINDOW) return 1;
    uint32_t mask = 1u << behind;
    if (g_seen_window[source] & mask) return 1;
    g_seen_window[source] |= mask;
    return 0;
}

static int mesh_extract(const uint8_t *adv, unsigned len, uint8_t frame[MESH_FRAME_SIZE]) {
    unsigned pos = 0;
    while (pos + 1 < len) {
        unsigned n = adv[pos];
        if (n == 0 || pos + n >= len) return 0;
        if (adv[pos + 1] == 0x16 && n == MESH_FRAME_SIZE + 3 &&
            adv[pos + 2] == (MESH_SERVICE_UUID & 0xFF) && adv[pos + 3] == (MESH_SERVICE_UUID >> 8)) {
            memcpy(frame, adv + pos + 4, MESH_FRAME_SIZE);
            return 1;
        }
        pos += n + 1;
    }
    return 0;
}

static void mesh_adv_frame(const uint8_t frame[MESH_FRAME_SIZE]) {
    uint8_t adv[MESH_DATA_SIZE] = { MESH_FRAME_SIZE + 3, 0x16,
        (uint8_t)(MESH_SERVICE_UUID & 0xFF), (uint8_t)(MESH_SERVICE_UUID >> 8) };
    memcpy(adv + 4, frame, MESH_FRAME_SIZE);
    mesh_install_event_hook();
    if (g_mesh_adv_idx == 0xFF) {
        memcpy(g_mesh_pending_frame, frame, sizeof(g_mesh_pending_frame));
        g_mesh_adv_pending = true;
        if (!g_mesh_adv_creating) {
            g_mesh_adv_creating = true;
            ble_appm_create_advertising(7, 160, 160);
        }
        return;
    }
    ble_appm_update_adv_data(g_mesh_adv_idx, adv, sizeof(adv));
    /* GAPM duration is in 10 ms units; 300 ms keeps each relay burst bounded. */
    ble_appm_start_advertising(g_mesh_adv_idx, MESH_ADV_DURATION_10MS);
}

static void mesh_apply(const uint8_t *f) {
    char command[64];
    if (f[7] == MESH_POWER) {
        snprintf(command, sizeof(command), "led_enableAll %u", f[8] ? 1 : 0);
        CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_SCRIPT);
    } else if (f[7] == MESH_DIMMER) {
        snprintf(command, sizeof(command), "led_dimmer %u", f[8]);
        CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_SCRIPT);
    } else if (f[7] == MESH_RGBCW) {
        snprintf(command, sizeof(command), "led_basecolor_rgbcw #%02X%02X%02X%02X%02X", f[8], f[9], f[10], f[11], f[12]);
        CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_SCRIPT);
    } else if (f[7] == MESH_RGB) {
        snprintf(command, sizeof(command), "led_basecolor_rgb #%02X%02X%02X", f[8], f[9], f[10]);
        CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_SCRIPT);
    } else if (f[7] == MESH_TEMPERATURE) {
        unsigned temperature = (unsigned)f[8] | ((unsigned)f[9] << 8);
        if (temperature < HASS_TEMPERATURE_MIN || temperature > HASS_TEMPERATURE_MAX) return;
        snprintf(command, sizeof(command), "led_temperature %u", temperature);
        CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_SCRIPT);
    }
}

void HAL_BLEMeshBK7231N_OnAdvertisement(const void *received) {
    const recv_adv_t *info = (const recv_adv_t *)received;
    if (!info || !mesh_is_provisioned()) return;
    uint8_t f[MESH_FRAME_SIZE];
    if (!mesh_extract(info->data, info->data_len, f) || f[0] != 1 || !mesh_tag_valid(f)) return;
    if (f[1] == 0 || f[1] > MESH_NODE_MAX || f[2] > MESH_NODE_MAX ||
        f[6] == 0 || f[6] > MESH_TTL_MAX || f[7] == 0 || f[7] > MESH_OP_MAX) return;
    if ((f[7] == MESH_POWER && f[8] > 1) ||
        (f[7] == MESH_DIMMER && f[8] > 100) ||
        (f[7] == MESH_TEMPERATURE &&
            (((unsigned)f[8] | ((unsigned)f[9] << 8)) < HASS_TEMPERATURE_MIN ||
             ((unsigned)f[8] | ((unsigned)f[9] << 8)) > HASS_TEMPERATURE_MAX))) return;
    uint32_t seq = mesh_frame_sequence(f);
    if (mesh_seen(f[1], seq)) return;
    int state_result = 1;
    if (f[2] == 0 || f[2] == mesh_node()) {
        state_result = mesh_accept_for_local_state(f);
        if (state_result == 2) mesh_apply(f);
    }
    if (f[6] > 1 && f[6] <= MESH_TTL_MAX && state_result != 0 && mesh_should_relay(f)) {
        --f[6]; mesh_tag(f); mesh_adv_frame(f);
    }
}

void HAL_BLEMeshBK7231N_OnMqttCommand(const char *command, const char *args) {
    if (!command || !args || !mesh_is_provisioned()) return;
    uint8_t op = 0;
    uint8_t payload[5] = { 0 };
    if (!strcmp(command, "led_enableAll")) {
        op = MESH_POWER;
        payload[0] = LED_GetEnableAll() ? 1 : 0;
    } else if (!strcmp(command, "led_dimmer")) {
        op = MESH_DIMMER;
        float dimmer = LED_GetDimmer();
        if (dimmer < 0 || dimmer > 100) return;
        payload[0] = (uint8_t)(dimmer + 0.5f);
    } else if (!strcmp(command, "led_basecolor_rgb")) {
        op = MESH_RGB;
        for (int i = 0; i < 3; ++i) payload[i] = (uint8_t)led_baseColors[i];
    } else if (!strcmp(command, "led_basecolor_rgbcw")) {
        op = MESH_RGBCW;
        for (int i = 0; i < 5; ++i) payload[i] = (uint8_t)led_baseColors[i];
    } else if (!strcmp(command, "led_temperature")) {
        op = MESH_TEMPERATURE;
        float temperature = LED_GetTemperature();
        if (temperature < HASS_TEMPERATURE_MIN || temperature > HASS_TEMPERATURE_MAX) return;
        unsigned value = (unsigned)(temperature + 0.5f);
        payload[0] = value & 0xFF;
        payload[1] = (value >> 8) & 0xFF;
    } else {
        return;
    }

    uint8_t relay_check[MESH_FRAME_SIZE] = { 1, mesh_node(), 0, 0, 0, 0, MESH_DEFAULT_TTL, op,
        payload[0], payload[1], payload[2], payload[3], payload[4] };
    if (!mesh_should_relay(relay_check)) return;

    uint32_t sequence = mesh_sequence_next();
    if (!sequence) return;
    uint8_t frame[MESH_FRAME_SIZE] = { 1, mesh_node(), 0, 0, 0, 0, MESH_DEFAULT_TTL, op,
        payload[0], payload[1], payload[2], payload[3], payload[4] };
    frame[3] = sequence & 0xFF;
    frame[4] = (sequence >> 8) & 0xFF;
    frame[5] = (sequence >> 16) & 0xFF;
    uint32_t timestamp = mesh_now();
    mesh_set_frame_timestamp(frame, timestamp);
    mesh_seen(frame[1], sequence);
    mesh_version_store_frame(frame, 1);
    g_latest_mqtt_timestamp[op] = timestamp;
    g_latest_mqtt_uptime[op] = (uint32_t)g_secondsElapsed;
    g_latest_mqtt_valid[op] = 1;
    mesh_start_radio();
    mesh_tag(frame);
    mesh_adv_frame(frame);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int HAL_BLEMeshBK7231N_WebConfig(http_request_t *request) {
    char body[128] = { 0 };
    char key[40] = { 0 };
    char node_text[8] = { 0 };
    int saved = 0;
    if (!request) return 0;

    if (request->method == HTTP_POST) {
        if (!request->bodystart || request->bodylen <= 0 || request->bodylen >= (int)sizeof(body)) {
            http_setup(request, httpMimeTypeHTML);
            poststr(request, "Invalid BLE mesh form data.");
            poststr(request, NULL);
            return 0;
        }
        memcpy(body, request->bodystart, request->bodylen);
        body[request->bodylen] = 0;
        http_getRawArg(body, "key", key, sizeof(key));
        http_getRawArg(body, "node", node_text, sizeof(node_text));
        int node = atoi(node_text);
        if (node < 1 || node > MESH_NODE_MAX ||
            (key[0] != 0 && strlen(key) != 32)) {
            http_setup(request, httpMimeTypeHTML);
            poststr(request, "Invalid node ID or key. Use node 1-254 and an optional 32-character hexadecimal key.");
            poststr(request, NULL);
            return 0;
        }
        if (key[0]) {
            char command[56];
            snprintf(command, sizeof(command), "BLEMesh key %s", key);
            if (CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_HTTP) != CMD_RES_OK) {
                http_setup(request, httpMimeTypeHTML);
                poststr(request, "The BLE mesh key could not be saved.");
                poststr(request, NULL);
                return 0;
            }
        }
        char command[24];
        snprintf(command, sizeof(command), "BLEMesh node %d", node);
        if (CMD_ExecuteCommand(command, COMMAND_FLAG_SOURCE_HTTP) != CMD_RES_OK) {
            http_setup(request, httpMimeTypeHTML);
            poststr(request, "The BLE mesh node ID could not be saved.");
            poststr(request, NULL);
            return 0;
        }
        saved = 1;
        if (mesh_is_provisioned()) mesh_start_radio();
    }

    http_setup(request, httpMimeTypeHTML);
    http_html_start(request, "BLE Mesh");
    poststr(request, "<p>Set a node ID from 1 to 254. Use the same 128-bit key on every spot in this mesh. Leave the key field blank to keep the current key.</p>");
    if (saved) poststr(request, "<p>BLE mesh settings saved.</p>");
    poststr(request, "<form action='/blemesh' method='post'>");
    hprintf255(request, "<label for='node'>Node ID (1-254)</label><input id='node' name='node' type='number' min='1' max='254' value='%u' required>", mesh_node());
    poststr(request, "<label for='key'>Mesh key (128-bit hexadecimal)</label><input id='key' name='key' type='password' minlength='32' maxlength='32' pattern='[0-9A-Fa-f]{32}' autocomplete='new-password' placeholder='Leave blank to keep the current key'>");
    poststr(request, "<input type='submit' value='Save BLE Mesh settings'></form>");
    poststr(request, htmlFooterReturnToCfgOrMainPage);
    http_html_end(request);
    poststr(request, NULL);
    return 0;
}

static commandResult_t CMD_BLEMesh(const void *context, const char *cmd, const char *args, int cmdFlags) {
    Tokenizer_TokenizeString(args, 0);
    const char *sub = Tokenizer_GetArg(0);
    if (!sub) return CMD_RES_NOT_ENOUGH_ARGUMENTS;
    if (!strcmp(sub, "key")) {
        if ((cmdFlags & (COMMAND_FLAG_SOURCE_CONSOLE | COMMAND_FLAG_SOURCE_HTTP)) == 0) return CMD_RES_BAD_ARGUMENT;
        const char *hex = Tokenizer_GetArg(1);
        if (!hex || strlen(hex) != 32) return CMD_RES_BAD_ARGUMENT;
        uint8_t key[16];
        uint8_t any = 0;
        for (int i = 0; i < 16; ++i) {
            int hi = hex_value(hex[2 * i]), lo = hex_value(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) return CMD_RES_BAD_ARGUMENT;
            key[i] = (uint8_t)((hi << 4) | lo);
            any |= key[i];
        }
        if (!any) return CMD_RES_BAD_ARGUMENT;
        memcpy(mesh_key(), key, sizeof(key));
        memset(g_seen_valid, 0, sizeof(g_seen_valid));
        memset(g_recent_relay_valid, 0, sizeof(g_recent_relay_valid));
        CFG_MarkAsDirty();
        CFG_Save_IfThereArePendingChanges();
        return CMD_RES_OK;
    }
    if (!strcmp(sub, "node")) {
        if ((cmdFlags & (COMMAND_FLAG_SOURCE_CONSOLE | COMMAND_FLAG_SOURCE_HTTP)) == 0) return CMD_RES_BAD_ARGUMENT;
        int node = Tokenizer_GetArgIntegerDefault(1, 0);
        if (node < 1 || node > MESH_NODE_MAX) return CMD_RES_BAD_ARGUMENT;
        g_cfg.unused[MESH_NODE_INDEX] = (char)node;
        CFG_MarkAsDirty();
        CFG_Save_IfThereArePendingChanges();
        return CMD_RES_OK;
    }
    if (!strcmp(sub, "start")) {
        if (!mesh_is_provisioned()) return CMD_RES_BAD_ARGUMENT;
        mesh_start_radio();
        return CMD_RES_OK;
    }
    if (!strcmp(sub, "send")) {
        if (!mesh_is_provisioned()) return CMD_RES_BAD_ARGUMENT;
        int target = Tokenizer_GetArgIntegerDefault(1, -1);
        const char *op = Tokenizer_GetArg(2);
        if (target < 0 || target > MESH_NODE_MAX || !op) return CMD_RES_BAD_ARGUMENT;
        uint8_t f[MESH_FRAME_SIZE] = { 1, mesh_node(), (uint8_t)target, 0, 0, 0, MESH_DEFAULT_TTL, 0, 0, 0, 0, 0, 0 };
        uint32_t seq = mesh_sequence_next(); if (seq == 0) return CMD_RES_BAD_ARGUMENT;
        f[3] = seq & 0xFF; f[4] = (seq >> 8) & 0xFF; f[5] = (seq >> 16) & 0xFF;
        if (!strcmp(op, "power")) {
            f[7] = MESH_POWER; int v = Tokenizer_GetArgIntegerDefault(3, -1); if (v < 0 || v > 1) return CMD_RES_BAD_ARGUMENT; f[8] = v;
        } else if (!strcmp(op, "dimmer")) {
            f[7] = MESH_DIMMER; int v = Tokenizer_GetArgIntegerDefault(3, -1); if (v < 0 || v > 100) return CMD_RES_BAD_ARGUMENT; f[8] = v;
        } else if (!strcmp(op, "rgbcw")) {
            f[7] = MESH_RGBCW;
            for (int i = 0; i < 5; ++i) { int v = Tokenizer_GetArgIntegerDefault(i + 3, -1); if (v < 0 || v > 255) return CMD_RES_BAD_ARGUMENT; f[8 + i] = (uint8_t)v; }
        } else if (!strcmp(op, "rgb")) {
            f[7] = MESH_RGB;
            for (int i = 0; i < 3; ++i) { int v = Tokenizer_GetArgIntegerDefault(i + 3, -1); if (v < 0 || v > 255) return CMD_RES_BAD_ARGUMENT; f[8 + i] = (uint8_t)v; }
        } else if (!strcmp(op, "temperature")) {
            f[7] = MESH_TEMPERATURE;
            int v = Tokenizer_GetArgIntegerDefault(3, -1); if (v < HASS_TEMPERATURE_MIN || v > HASS_TEMPERATURE_MAX) return CMD_RES_BAD_ARGUMENT;
            f[8] = v & 0xFF; f[9] = (v >> 8) & 0xFF;
        } else return CMD_RES_BAD_ARGUMENT;
        mesh_set_frame_timestamp(f, mesh_now());
        mesh_seen(f[1], seq);
        if (target == 0 || target == mesh_node()) {
            mesh_version_store_frame(f, 1);
            mesh_apply(f);
        }
        mesh_start_radio();
        mesh_tag(f); mesh_adv_frame(f);
        return CMD_RES_OK;
    }
    return CMD_RES_BAD_ARGUMENT;
}

void HAL_BLEMeshBK7231N_RegisterCommands(void) {
    CMD_RegisterCommand("BLEMesh", CMD_BLEMesh, NULL);
    HTTP_RegisterCallback("/blemesh", HTTP_GET, HAL_BLEMeshBK7231N_WebConfig, 1);
    HTTP_RegisterCallback("/blemesh", HTTP_POST, HAL_BLEMeshBK7231N_WebConfig, 1);
    if (mesh_is_provisioned()) mesh_start_radio();
}
#else
void HAL_BLEMeshBK7231N_OnAdvertisement(const void *info) { (void)info; }
void HAL_BLEMeshBK7231N_RegisterCommands(void) { }
void HAL_BLEMeshBK7231N_OnMqttCommand(const char *command, const char *args) { (void)command; (void)args; }
int HAL_BLEMeshBK7231N_WebConfig(http_request_t *request) { (void)request; return 0; }
#endif
