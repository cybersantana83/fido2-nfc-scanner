#include "fido2_scanner.h"
#include <storage/storage.h>

#define TAG "Fido2Scanner"

// ── Scene IDs ────────────────────────────────────────────────────────────────
typedef enum {
    Fido2SceneStart,
    Fido2SceneScanning,
    Fido2SceneResult,
    Fido2SceneCount,
} Fido2Scene;

// ── Forward declarations ──────────────────────────────────────────────────────
static void scene_start_on_enter(void* ctx);
static bool scene_start_on_event(void* ctx, SceneManagerEvent event);
static void scene_start_on_exit(void* ctx);

static void scene_scanning_on_enter(void* ctx);
static bool scene_scanning_on_event(void* ctx, SceneManagerEvent event);
static void scene_scanning_on_exit(void* ctx);

static void scene_result_on_enter(void* ctx);
static bool scene_result_on_event(void* ctx, SceneManagerEvent event);
static void scene_result_on_exit(void* ctx);

static void fido2_scanner_save(Fido2Scanner* app);

// ── Scene handlers table ──────────────────────────────────────────────────────
static void (*const on_enter[])(void*) = {
    scene_start_on_enter,
    scene_scanning_on_enter,
    scene_result_on_enter,
};
static bool (*const on_event[])(void*, SceneManagerEvent) = {
    scene_start_on_event,
    scene_scanning_on_event,
    scene_result_on_event,
};
static void (*const scene_on_exit[])(void*) = {
    scene_start_on_exit,
    scene_scanning_on_exit,
    scene_result_on_exit,
};
static const SceneManagerHandlers scene_handlers = {
    .on_enter_handlers = on_enter,
    .on_event_handlers = on_event,
    .on_exit_handlers  = scene_on_exit,
    .scene_num         = Fido2SceneCount,
};

// ── Worker callback ───────────────────────────────────────────────────────────
#define FIDO2_CUSTOM_SCAN_OK   (0)
#define FIDO2_CUSTOM_SCAN_FAIL (1)

static void worker_callback(Fido2WorkerEvent event, void* ctx) {
    Fido2Scanner* app = ctx;
    uint32_t custom = (event == Fido2WorkerEventSuccess)
                        ? FIDO2_CUSTOM_SCAN_OK
                        : FIDO2_CUSTOM_SCAN_FAIL;
    view_dispatcher_send_custom_event(app->view_dispatcher, custom);
}

// ── Scene: Start (tela "Aproxime o token NFC") ────────────────────────────────
static void scene_start_on_enter(void* ctx) {
    Fido2Scanner* app = ctx;
    popup_reset(app->popup);
    popup_set_header(app->popup, "FIDO2 NFC Scanner", 64, 10, AlignCenter, AlignCenter);
    popup_set_text(app->popup, "Aproxime o\nauthenticator NFC", 64, 36, AlignCenter, AlignCenter);
    popup_set_icon(app->popup, 0, 0, NULL);
    view_dispatcher_switch_to_view(app->view_dispatcher, Fido2ScannerViewPopup);

    // Inicia o worker
    fido2_worker_start(app->worker, worker_callback, app);
    scene_manager_next_scene(app->scene_manager, Fido2SceneScanning);
}

static bool scene_start_on_event(void* ctx, SceneManagerEvent event) {
    UNUSED(ctx); UNUSED(event);
    return false;
}

static void scene_start_on_exit(void* ctx) { UNUSED(ctx); }

// ── Scene: Scanning ───────────────────────────────────────────────────────────
static void scene_scanning_on_enter(void* ctx) {
    Fido2Scanner* app = ctx;
    popup_reset(app->popup);
    popup_set_header(app->popup, "Lendo FIDO2...", 64, 10, AlignCenter, AlignCenter);
    popup_set_text(app->popup, "Aguarde...\nNao mova o token", 64, 36, AlignCenter, AlignCenter);
    view_dispatcher_switch_to_view(app->view_dispatcher, Fido2ScannerViewPopup);
}

static bool scene_scanning_on_event(void* ctx, SceneManagerEvent event) {
    Fido2Scanner* app = ctx;
    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == FIDO2_CUSTOM_SCAN_OK) {
            // Copia fingerprint do worker para o app
            Fido2Fingerprint* fp = fido2_worker_get_fingerprint(app->worker);
            memcpy(&app->fingerprint, fp, sizeof(Fido2Fingerprint));
            app->scan_done = true;
            scene_manager_next_scene(app->scene_manager, Fido2SceneResult);
            return true;
        }
        if(event.event == FIDO2_CUSTOM_SCAN_FAIL) {
            popup_set_header(app->popup, "Falhou!", 64, 10, AlignCenter, AlignCenter);
            popup_set_text(app->popup, "Nao foi possivel\nler o token", 64, 36, AlignCenter, AlignCenter);
            return true;
        }
    }
    return false;
}

static void scene_scanning_on_exit(void* ctx) { UNUSED(ctx); }

// ── Formata fingerprint para exibição ─────────────────────────────────────────
static void format_fingerprint(Fido2Scanner* app) {
    Fido2Fingerprint* fp = &app->fingerprint;
    FuriString* s = app->text_box_store;
    furi_string_reset(s);

    // YubiKey ATS detection
    if(fp->has_yubikey_string)
        furi_string_cat_printf(s, "! YubiKey ATS: DETECTADO\n\n");

    // AAGUID
    if(fp->has_aaguid) {
        furi_string_cat_printf(s, "AAGUID:\n");
        for(int i = 0; i < 16; i++)
            furi_string_cat_printf(s, "%02X%s", fp->aaguid[i], (i==3||i==5||i==7||i==9)?"-":"");
        furi_string_cat_printf(s, "\n\n");
    }

    // Firmware version
    if(fp->has_firmware_version) {
        uint8_t maj = (fp->firmware_version >> 16) & 0xFF;
        uint8_t min = (fp->firmware_version >>  8) & 0xFF;
        uint8_t rev =  fp->firmware_version        & 0xFF;
        furi_string_cat_printf(s, "FW: %d.%d.%d\n", maj, min, rev);
    }

    // PIN status
    furi_string_cat_printf(s, "PIN: %s\n", fp->client_pin ? "CONFIGURADO" : "nao definido");

    // Transports
    if(fp->transport_count > 0) {
        furi_string_cat_printf(s, "Transport:");
        for(int i = 0; i < fp->transport_count; i++)
            furi_string_cat_printf(s, " %s", fp->transports[i]);
        furi_string_cat_printf(s, "\n");
    }

    // Versions
    if(fp->version_count > 0) {
        furi_string_cat_printf(s, "Versions:");
        for(int i = 0; i < fp->version_count; i++)
            furi_string_cat_printf(s, " %s", fp->versions[i]);
        furi_string_cat_printf(s, "\n");
    }

    // Extensions
    if(fp->extension_count > 0) {
        furi_string_cat_printf(s, "Ext:");
        for(int i = 0; i < fp->extension_count; i++)
            furi_string_cat_printf(s, "\n  %s", fp->extensions[i]);
        furi_string_cat_printf(s, "\n");
    }

    // maxMsgSize / minPIN
    furi_string_cat_printf(s, "MaxMsg: %u  MinPIN: %u\n",
        fp->max_msg_size, fp->min_pin_length);
}

static void fido2_scanner_save(Fido2Scanner* app) {
    Fido2Fingerprint* fp = &app->fingerprint;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, FIDO2_SCANNER_SD_PATH);
    FuriString* path = furi_string_alloc_printf(
        "%s/scan_%08lX%s", FIDO2_SCANNER_SD_PATH,
        (uint32_t)furi_get_tick(), FIDO2_SCANNER_EXT);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        FuriString* buf = furi_string_alloc();
        furi_string_cat_printf(buf, "FIDO2 NFC Scanner\n==================\n\n");
        if(fp->has_yubikey_string) furi_string_cat_printf(buf, "ATS: YubiKey DETECTADO\n");
        if(fp->has_aaguid) {
            furi_string_cat_printf(buf, "AAGUID: ");
            for(int i = 0; i < 16; i++)
                furi_string_cat_printf(buf, "%02X%s", fp->aaguid[i], (i==3||i==5||i==7||i==9)?"-":"");
            furi_string_cat_printf(buf, "\n");
        }
        furi_string_cat_printf(buf, "PIN: %s\n", fp->client_pin ? "CONFIGURADO" : "nao definido");
        furi_string_cat_printf(buf, "Versions:");
        for(int i = 0; i < fp->version_count; i++) furi_string_cat_printf(buf, " %s", fp->versions[i]);
        furi_string_cat_printf(buf, "\nExtensions:\n");
        for(int i = 0; i < fp->extension_count; i++) furi_string_cat_printf(buf, "  %s\n", fp->extensions[i]);
        furi_string_cat_printf(buf, "Transports:");
        for(int i = 0; i < fp->transport_count; i++) furi_string_cat_printf(buf, " %s", fp->transports[i]);
        furi_string_cat_printf(buf, "\nRAW (%u bytes):\n", fp->raw_getinfo_len);
        for(uint16_t i = 0; i < fp->raw_getinfo_len; i++) {
            furi_string_cat_printf(buf, "%02X", fp->raw_getinfo[i]);
            if((i+1) % 16 == 0) furi_string_cat_printf(buf, "\n");
            else furi_string_cat_printf(buf, " ");
        }
        furi_string_cat_printf(buf, "\n");
        storage_file_write(file, furi_string_get_cstr(buf), furi_string_size(buf));
        furi_string_free(buf);
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_string_free(path);
    furi_record_close(RECORD_STORAGE);
}
// ── Scene: Result ─────────────────────────────────────────────────────────────
static void scene_result_on_enter(void* ctx) {
    Fido2Scanner* app = ctx;
    format_fingerprint(app);
    fido2_scanner_save(app);
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_store));
    view_dispatcher_switch_to_view(app->view_dispatcher, Fido2ScannerViewTextBox);
}

static bool scene_result_on_event(void* ctx, SceneManagerEvent event) {
    Fido2Scanner* app = ctx;
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_stop(app->scene_manager);
        view_dispatcher_stop(app->view_dispatcher);
        return true;
    }
    return false;
}

static void scene_result_on_exit(void* ctx) { UNUSED(ctx); }

// ── View dispatcher callback ──────────────────────────────────────────────────
static bool nav_callback(void* ctx) {
    Fido2Scanner* app = ctx;
    return scene_manager_handle_back_event(app->scene_manager);
}

static bool custom_callback(void* ctx, uint32_t event) {
    Fido2Scanner* app = ctx;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

// ── Entry point ───────────────────────────────────────────────────────────────
int32_t fido2_scanner_app(void* p) {
    UNUSED(p);
    Fido2Scanner* app = malloc(sizeof(Fido2Scanner));
    memset(app, 0, sizeof(Fido2Scanner));

    // GUI
    app->gui             = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    app->scene_manager   = scene_manager_alloc(&scene_handlers, app);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, nav_callback);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, custom_callback);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // Views
    app->popup = popup_alloc();
    view_dispatcher_add_view(app->view_dispatcher, Fido2ScannerViewPopup, popup_get_view(app->popup));

    app->text_box       = text_box_alloc();
    app->text_box_store = furi_string_alloc();
    view_dispatcher_add_view(app->view_dispatcher, Fido2ScannerViewTextBox, text_box_get_view(app->text_box));

    // NFC + worker
    app->nfc    = nfc_alloc();
    app->worker = fido2_worker_alloc(app->nfc);

    // Inicia
    scene_manager_next_scene(app->scene_manager, Fido2SceneStart);
    view_dispatcher_run(app->view_dispatcher);

    // Cleanup
    fido2_worker_stop(app->worker);
    fido2_worker_free(app->worker);
    nfc_free(app->nfc);

    view_dispatcher_remove_view(app->view_dispatcher, Fido2ScannerViewPopup);
    view_dispatcher_remove_view(app->view_dispatcher, Fido2ScannerViewTextBox);
    popup_free(app->popup);
    text_box_free(app->text_box);
    furi_string_free(app->text_box_store);

    scene_manager_free(app->scene_manager);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    free(app);
    return 0;
}
