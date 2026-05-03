#include "fido2_scanner.h"
#include <string.h>

// ── CBOR types ───────────────────────────────────────────────────────────────
#define CBOR_UINT       0x00
#define CBOR_NEGINT     0x20
#define CBOR_BYTES      0x40
#define CBOR_TEXT       0x60
#define CBOR_ARRAY      0x80
#define CBOR_MAP        0xA0
#define CBOR_SIMPLE     0xE0

#define CBOR_TRUE       0xF5
#define CBOR_FALSE      0xF4

// ── Cursor ───────────────────────────────────────────────────────────────────
typedef struct {
    const uint8_t* data;
    uint16_t       pos;
    uint16_t       len;
} CborCursor;


static bool cbor_read_byte(CborCursor* c, uint8_t* out) {
    if(c->pos >= c->len) return false;
    *out = c->data[c->pos++];
    return true;
}

// Lê o argumento de comprimento (adicional info do byte inicial)
static bool cbor_read_uint(CborCursor* c, uint8_t info, uint64_t* out) {
    if(info <= 23) { *out = info; return true; }
    if(info == 24) {
        uint8_t v; if(!cbor_read_byte(c, &v)) return false;
        *out = v; return true;
    }
    if(info == 25) {
        uint8_t hi, lo;
        if(!cbor_read_byte(c, &hi) || !cbor_read_byte(c, &lo)) return false;
        *out = ((uint16_t)hi << 8) | lo; return true;
    }
    if(info == 26) {
        uint8_t b[4];
        for(int i=0;i<4;i++) if(!cbor_read_byte(c, &b[i])) return false;
        *out = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
        return true;
    }
    return false; // info >= 27 não suportado aqui
}

// Salta um valor CBOR completo (recursivo, limitado)
static bool cbor_skip(CborCursor* c, int depth);

static bool cbor_skip(CborCursor* c, int depth) {
    if(depth > 8) return false;
    uint8_t b; if(!cbor_read_byte(c, &b)) return false;
    uint8_t major = b & 0xE0;
    uint8_t info  = b & 0x1F;

    uint64_t n = 0;
    if(!cbor_read_uint(c, info, &n)) return false;

    if(major == CBOR_UINT || major == CBOR_NEGINT) return true;
    if(major == CBOR_SIMPLE) return true;
    if(major == CBOR_BYTES || major == CBOR_TEXT) {
        c->pos += (uint16_t)n;
        return c->pos <= c->len;
    }
    if(major == CBOR_ARRAY) {
        for(uint64_t i = 0; i < n; i++) if(!cbor_skip(c, depth+1)) return false;
        return true;
    }
    if(major == CBOR_MAP) {
        for(uint64_t i = 0; i < n*2; i++) if(!cbor_skip(c, depth+1)) return false;
        return true;
    }
    return false;
}

// Lê string de texto CBOR → buffer (null-terminated)
static bool cbor_read_text(CborCursor* c, char* buf, size_t buflen) {
    uint8_t b; if(!cbor_read_byte(c, &b)) return false;
    if((b & 0xE0) != CBOR_TEXT) return false;
    uint64_t n; if(!cbor_read_uint(c, b & 0x1F, &n)) return false;
    if(n >= buflen || c->pos + n > c->len) return false;
    memcpy(buf, c->data + c->pos, n);
    buf[n] = '\0';
    c->pos += (uint16_t)n;
    return true;
}

// Lê bytes CBOR → buffer
static bool cbor_read_bytes(CborCursor* c, uint8_t* buf, size_t buflen, uint16_t* out_len) {
    uint8_t b; if(!cbor_read_byte(c, &b)) return false;
    if((b & 0xE0) != CBOR_BYTES) return false;
    uint64_t n; if(!cbor_read_uint(c, b & 0x1F, &n)) return false;
    if(n > buflen || c->pos + n > c->len) return false;
    memcpy(buf, c->data + c->pos, n);
    *out_len = (uint16_t)n;
    c->pos += (uint16_t)n;
    return true;
}

// ── Parse de array de strings ─────────────────────────────────────────────────
static void parse_string_array(CborCursor* c, char out[][24], uint8_t maxcount, uint8_t* count) {
    uint8_t b; if(!cbor_read_byte(c, &b)) return;
    if((b & 0xE0) != CBOR_ARRAY) return;
    uint64_t n; if(!cbor_read_uint(c, b & 0x1F, &n)) return;
    *count = 0;
    for(uint64_t i = 0; i < n; i++) {
        if(*count < maxcount) {
            char tmp[24] = {0};
            if(cbor_read_text(c, tmp, sizeof(tmp))) {
                memcpy(out[*count], tmp, sizeof(tmp));
                (*count)++;
            }
        } else {
            cbor_skip(c, 0);
        }
    }
}

// ── Parse do options map ──────────────────────────────────────────────────────
static void parse_options_map(CborCursor* c, Fido2Fingerprint* fp) {
    uint8_t b; if(!cbor_read_byte(c, &b)) return;
    if((b & 0xE0) != CBOR_MAP) return;
    uint64_t n; if(!cbor_read_uint(c, b & 0x1F, &n)) return;

    for(uint64_t i = 0; i < n; i++) {
        char key[24] = {0};
        if(!cbor_read_text(c, key, sizeof(key))) { cbor_skip(c,0); cbor_skip(c,0); continue; }

        if(c->pos >= c->len) break;
        uint8_t peek_b = c->data[c->pos];
        if(peek_b == CBOR_TRUE || peek_b == CBOR_FALSE) {
            c->pos++;
            bool bval = (peek_b == CBOR_TRUE);
	    if(strcmp(key, "rk") == 0)              fp->rk         = bval;
            else if(strcmp(key, "clientPin") == 0)  fp->client_pin = bval;
            else if(strcmp(key, "largeBlobs") == 0) fp->large_blobs = bval;
            else if(strcmp(key, "alwaysUv") == 0)   fp->always_uv  = bval;
            else if(strcmp(key, "plat") == 0)        fp->plat       = bval;
        } else {
            cbor_skip(c, 0);
            continue;
        }
    }
}

// ── Parser principal: GetInfo CBOR ───────────────────────────────────────────
// Estrutura: map { 0x01: versions[], 0x02: extensions[], 0x03: aaguid,
//                  0x04: options{}, 0x05: maxMsgSize, 0x06: pinUvAuthProtocols[],
//                  0x07..., 0x09: transports[], 0x0E: firmwareVersion, ... }
bool fido2_cbor_parse_getinfo(const uint8_t* data, uint16_t len, Fido2Fingerprint* fp) {
    CborCursor c = { .data = data, .pos = 0, .len = len };

    // Byte inicial deve ser map
    uint8_t b; if(!cbor_read_byte(&c, &b)) return false;
    if((b & 0xE0) != CBOR_MAP) return false;
    uint64_t map_count; if(!cbor_read_uint(&c, b & 0x1F, &map_count)) return false;

    for(uint64_t i = 0; i < map_count && c.pos < c.len; i++) {
        // Chave é uint
        uint8_t kb; if(!cbor_read_byte(&c, &kb)) break;
        uint64_t key; if(!cbor_read_uint(&c, kb & 0x1F, &key)) break;

        switch(key) {
        case 0x01: // versions: array de strings
            parse_string_array(&c, fp->versions, 4, &fp->version_count);
            break;

        case 0x02: // extensions: array de strings
            parse_string_array(&c, fp->extensions, 8, &fp->extension_count);
            break;

        case 0x03: { // aaguid: bytes(16)
            uint16_t alen = 0;
            if(cbor_read_bytes(&c, fp->aaguid, FIDO2_AAGUID_LEN, &alen))
                fp->has_aaguid = (alen == FIDO2_AAGUID_LEN);
            break;
        }

        case 0x04: // options: map
            parse_options_map(&c, fp);
            break;

        case 0x05: { // maxMsgSize: uint
            uint8_t vb; cbor_read_byte(&c, &vb);
            uint64_t v; cbor_read_uint(&c, vb & 0x1F, &v);
            fp->max_msg_size = (uint16_t)v;
            break;
        }

        case 0x09: // transports: array de strings
            parse_string_array(&c, fp->transports, 4, &fp->transport_count);
            break;

        case 0x0D: { // minPINLength: uint
            uint8_t vb; cbor_read_byte(&c, &vb);
            uint64_t v; cbor_read_uint(&c, vb & 0x1F, &v);
            fp->min_pin_length = (uint8_t)v;
            break;
        }

        case 0x0E: { // firmwareVersion: uint
            uint8_t vb; cbor_read_byte(&c, &vb);
            uint64_t v; cbor_read_uint(&c, vb & 0x1F, &v);
            fp->firmware_version     = (uint32_t)v;
            fp->has_firmware_version = true;
            break;
        }

        default:
            cbor_skip(&c, 0);
            break;
        }
    }
    return true;
}
