#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/widget.h>
#include <gui/modules/submenu.h>
#include <gui/modules/popup.h>
#include <gui/modules/text_box.h>
#include <storage/storage.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_poller.h>
#include <bit_lib/bit_lib.h>
#include <toolbox/hex.h>

// ── APDUs hardcoded ──────────────────────────────────────────────────────────
// SELECT AID FIDO/U2F: A0 00 00 06 47 2F 00 01
#define FIDO_SELECT_AID \
    { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00 }
#define FIDO_SELECT_AID_LEN 14

// CTAP2 GetInfo: comando 0x04
#define CTAP2_GET_INFO \
    { 0x80, 0x10, 0x00, 0x00, 0x01, 0x04, 0x00 }
#define CTAP2_GET_INFO_LEN 7

#define FIDO2_SCANNER_SD_PATH    "/ext/apps_data/fido2_scanner"
#define FIDO2_SCANNER_EXT        ".fido2"
#define FIDO2_MAX_RESPONSE       512
#define FIDO2_AAGUID_LEN         16

// ── Fingerprint estruturado ──────────────────────────────────────────────────
typedef struct {
    // ATS layer
    bool     has_yubikey_string;         // "YubiKey" nos historical bytes
    uint8_t  historical_bytes[16];
    uint8_t  historical_bytes_len;

    // CTAP2 GetInfo (campos extraídos do CBOR)
    char     versions[4][24];            // ex: "FIDO_2_1"
    uint8_t  version_count;

    char     extensions[8][24];          // ex: "hmac-secret"
    uint8_t  extension_count;

    uint8_t  aaguid[FIDO2_AAGUID_LEN];  // 16 bytes — fingerprint de modelo
    bool     has_aaguid;

    // Options map
    bool     rk;                         // resident keys
    bool     client_pin;                 // PIN configurado?
    bool     large_blobs;
    bool     always_uv;
    bool     plat;                       // platform authenticator?

    // Campos escalares
    uint16_t max_msg_size;
    uint8_t  min_pin_length;
    uint32_t firmware_version;           // ex: 0x00050704 → 5.7.4
    bool     has_firmware_version;

    char     transports[4][24];           // ex: "nfc", "usb"
    uint8_t  transport_count;

    // Raw para salvar no arquivo
    uint8_t  raw_getinfo[FIDO2_MAX_RESPONSE];
    uint16_t raw_getinfo_len;
} Fido2Fingerprint;

// ── Worker ───────────────────────────────────────────────────────────────────
typedef enum {
    Fido2WorkerEventSuccess,
    Fido2WorkerEventFail,
    Fido2WorkerEventTimeout,
    Fido2WorkerEventAborted,
} Fido2WorkerEvent;

typedef void (*Fido2WorkerCallback)(Fido2WorkerEvent event, void* context);

typedef struct Fido2Worker Fido2Worker;

Fido2Worker* fido2_worker_alloc(Nfc* nfc);
void         fido2_worker_free(Fido2Worker* worker);
void         fido2_worker_start(Fido2Worker* worker, Fido2WorkerCallback cb, void* ctx);
void         fido2_worker_stop(Fido2Worker* worker);
Fido2Fingerprint* fido2_worker_get_fingerprint(Fido2Worker* worker);

// ── CBOR parser (mínimo para GetInfo) ───────────────────────────────────────
bool fido2_cbor_parse_getinfo(
    const uint8_t* data,
    uint16_t       len,
    Fido2Fingerprint* fp);

// ── App state ────────────────────────────────────────────────────────────────
typedef enum {
    Fido2ScannerViewSubmenu,
    Fido2ScannerViewPopup,
    Fido2ScannerViewTextBox,
} Fido2ScannerView;

typedef struct {
    Gui*             gui;
    ViewDispatcher*  view_dispatcher;
    SceneManager*    scene_manager;
    Submenu*         submenu;
    Popup*           popup;
    TextBox*         text_box;
    FuriString*      text_box_store;
    Storage*         storage;

    Nfc*             nfc;
    Fido2Worker*     worker;
    Fido2Fingerprint fingerprint;

    bool             scan_done;
} Fido2Scanner;

int32_t fido2_scanner_app(void* p);
