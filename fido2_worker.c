#include "fido2_scanner.h"
#include <furi.h>
// Acesso ao struct interno do poller — necessário para chaining
#include <nfc/protocols/iso14443_4a/iso14443_4a_poller_i.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_i.h>

#define TAG "Fido2Worker"
#define WORKER_DONE (1 << 0)
#define WORKER_ERR  (1 << 1)

// PCB byte defines para I-block chaining
#define PCB_I_BLOCK_MASK  0xC0  // bits 7-6 = 00 → I-block
#define PCB_I_BLOCK_VAL   0x00
#define PCB_CHAIN_BIT     0x10  // bit 4 setado = mais frames vindo
#define PCB_BLOCK_NUM     0x01  // bit 0 = block number (toggle)
#define PCB_R_ACK(bn)     (0xA2 | ((bn) & PCB_BLOCK_NUM))

static bool pcb_is_chained_i_block(uint8_t pcb) {
    return ((pcb & PCB_I_BLOCK_MASK) == PCB_I_BLOCK_VAL) && (pcb & PCB_CHAIN_BIT);
}

struct Fido2Worker {
    FuriThread*         thread;
    FuriThreadId        thread_id;
    Nfc*                nfc;
    NfcPoller*          poller;
    Fido2WorkerCallback callback;
    void*               context;
    bool                running;
    Fido2Fingerprint    fingerprint;
    BitBuffer*          tx;
    BitBuffer*          rx;
    BitBuffer*          acc;  // acumulador para frames chainados
};

// ── Envia APDU e faz reassembly de I-block chaining ─────────────────────────
// Retorna true se recebeu resposta completa em worker->acc
static bool fido2_send_apdu_chained(
    Iso14443_4aPoller* poller,
    Fido2Worker*       worker,
    const uint8_t*     apdu,
    size_t             apdu_len)
{
    bit_buffer_reset(worker->acc);

    // Envia o APDU via send_block
    bit_buffer_reset(worker->tx);
    bit_buffer_reset(worker->rx);
    bit_buffer_copy_bytes(worker->tx, apdu, apdu_len);

    Iso14443_4aError err = iso14443_4a_poller_send_block(
        poller, worker->tx, worker->rx);

    // Se não falhou → resposta cabe num frame, copia e retorna
    if(err == Iso14443_4aErrorNone) {
        size_t rlen = bit_buffer_get_size_bytes(worker->rx);
        for(size_t i = 0; i < rlen; i++)
            bit_buffer_append_byte(worker->acc, bit_buffer_get_byte(worker->rx, i));
        return true;
    }

    // Se falhou com Protocol → pode ser chaining — olha o rx_buffer interno
    if(err != Iso14443_4aErrorProtocol) {
        FURI_LOG_E(TAG, "send_block err=%d (nao protocol)", err);
        return false;
    }

    // Verifica PCB byte no rx_buffer interno do poller
    size_t raw_len = bit_buffer_get_size_bytes(poller->rx_buffer);
    if(raw_len < 2) {
        FURI_LOG_E(TAG, "rx_buffer interno vazio");
        return false;
    }

    uint8_t first_pcb = bit_buffer_get_byte(poller->rx_buffer, 0);
    if(!pcb_is_chained_i_block(first_pcb)) {
        FURI_LOG_E(TAG, "PCB=%02X nao e chained I-block", first_pcb);
        return false;
    }

    FURI_LOG_I(TAG, "Chaining detectado! PCB=%02X, iniciando reassembly", first_pcb);

    // Copia payload do primeiro frame (pula PCB byte)
    for(size_t i = 1; i < raw_len; i++)
        bit_buffer_append_byte(worker->acc, bit_buffer_get_byte(poller->rx_buffer, i));

    // Loop: envia R(ACK) e recebe próximos frames até chain bit = 0
    uint8_t block_num = first_pcb & PCB_BLOCK_NUM;
    uint8_t max_chunks = 16; // safety limit

    while(max_chunks-- > 0) {
        // Alterna block number para o próximo R(ACK)
        block_num ^= 1;
        uint8_t rack = PCB_R_ACK(block_num);

        FURI_LOG_I(TAG, "Enviando R(ACK)=%02X block_num=%d", rack, block_num);

        // Envia R(ACK) diretamente via send_receive_ready_block
        BitBuffer* empty = bit_buffer_alloc(1);
        err = iso14443_4a_poller_send_receive_ready_block(
            poller, true, empty, worker->rx);
        bit_buffer_free(empty);

        if(err != Iso14443_4aErrorNone) {
            // R(ACK) também pode acionar chaining — lê o raw_buffer
            raw_len = bit_buffer_get_size_bytes(poller->rx_buffer);
            if(raw_len < 2) {
                FURI_LOG_E(TAG, "R(ACK) sem resposta");
                return false;
            }
            uint8_t pcb = bit_buffer_get_byte(poller->rx_buffer, 0);
            FURI_LOG_I(TAG, "Chunk PCB=%02X raw_len=%d", pcb, (int)raw_len);

            // Copia payload
            for(size_t i = 1; i < raw_len; i++)
                bit_buffer_append_byte(worker->acc, bit_buffer_get_byte(poller->rx_buffer, i));

            // Verifica se ainda tem mais
            if(!pcb_is_chained_i_block(pcb)) {
                FURI_LOG_I(TAG, "Chaining completo via raw_buffer");
                return true;
            }
        } else {
            // send_receive_ready_block decodificou ok — pega de worker->rx
            size_t rlen = bit_buffer_get_size_bytes(worker->rx);
            FURI_LOG_I(TAG, "Chunk OK: %d bytes", (int)rlen);
            for(size_t i = 0; i < rlen; i++)
                bit_buffer_append_byte(worker->acc, bit_buffer_get_byte(worker->rx, i));
            FURI_LOG_I(TAG, "Chaining completo");
            return true;
        }
    }

    FURI_LOG_E(TAG, "Safety limit atingido no chaining");
    return false;
}

// ── Callback do poller ───────────────────────────────────────────────────────
static NfcCommand fido2_poller_callback(NfcGenericEvent event, void* ctx) {
    Fido2Worker* worker = ctx;
    Iso14443_4aPollerEvent* ev = event.event_data;

    if(ev->type != Iso14443_4aPollerEventTypeReady)
        return NfcCommandContinue;

    Iso14443_4aPoller* poller = event.instance;

    // ── Detecta "YubiKey" nos ATS historical bytes ───────────────────────────
    const NfcDeviceData* dev_data = nfc_poller_get_data(worker->poller);
    if(dev_data) {
       const Iso14443_4aData* nfc_4a = (const Iso14443_4aData*)dev_data;
       uint32_t hist_len = 0;
       const uint8_t* hist = iso14443_4a_get_historical_bytes(nfc_4a, &hist_len);
       if(hist && hist_len > 0) {
           if(hist_len > 16) hist_len = 16;
           memcpy(worker->fingerprint.historical_bytes, hist, hist_len);
           worker->fingerprint.historical_bytes_len = (uint8_t)hist_len;
           const uint8_t yubikey[] = {0x57,0x59,0x75,0x62,0x69,0x4B,0x65,0x79};
           for(uint32_t i = 0; i + 8 <= hist_len; i++) {
               if(memcmp(hist + i, yubikey, 8) == 0) {
                   worker->fingerprint.has_yubikey_string = true;
                   break;
            }
        }
    }
}


    // ── Step 1: SELECT AID ───────────────────────────────────────────────────
    uint8_t select_aid[] = FIDO_SELECT_AID;
    FURI_LOG_I(TAG, "SELECT AID...");

    if(!fido2_send_apdu_chained(poller, worker, select_aid, FIDO_SELECT_AID_LEN)) {
        FURI_LOG_E(TAG, "SELECT AID falhou");
        furi_thread_flags_set(worker->thread_id, WORKER_ERR);
        return NfcCommandStop;
    }

    size_t rlen = bit_buffer_get_size_bytes(worker->acc);
    if(rlen < 2) { furi_thread_flags_set(worker->thread_id, WORKER_ERR); return NfcCommandStop; }

    uint8_t sw1 = bit_buffer_get_byte(worker->acc, rlen - 2);
    uint8_t sw2 = bit_buffer_get_byte(worker->acc, rlen - 1);
    FURI_LOG_I(TAG, "SELECT SW: %02X %02X", sw1, sw2);

    if(sw1 != 0x90 || sw2 != 0x00) {
        furi_thread_flags_set(worker->thread_id, WORKER_ERR);
        return NfcCommandStop;
    }

    // ── Step 2: CTAP2 GetInfo ────────────────────────────────────────────────
    uint8_t get_info[] = CTAP2_GET_INFO;
    FURI_LOG_I(TAG, "GetInfo...");

    if(!fido2_send_apdu_chained(poller, worker, get_info, CTAP2_GET_INFO_LEN)) {
        FURI_LOG_E(TAG, "GetInfo falhou");
        furi_thread_flags_set(worker->thread_id, WORKER_ERR);
        return NfcCommandStop;
    }

    rlen = bit_buffer_get_size_bytes(worker->acc);
    FURI_LOG_I(TAG, "GetInfo total: %d bytes", (int)rlen);

    // Remove SW 90 00 final se presente
    uint16_t cbor_len = (rlen >= 2) ? (uint16_t)(rlen - 2) : (uint16_t)rlen;
    if(cbor_len > FIDO2_MAX_RESPONSE) cbor_len = FIDO2_MAX_RESPONSE;

    for(uint16_t i = 0; i < cbor_len; i++)
        worker->fingerprint.raw_getinfo[i] = bit_buffer_get_byte(worker->acc, i);
    worker->fingerprint.raw_getinfo_len = cbor_len;

    // Pula status byte CTAP2 (0x00)
    if(cbor_len > 1 && worker->fingerprint.raw_getinfo[0] == 0x00)
        fido2_cbor_parse_getinfo(
            worker->fingerprint.raw_getinfo + 1,
            cbor_len - 1,
            &worker->fingerprint);

    furi_thread_flags_set(worker->thread_id, WORKER_DONE);
    return NfcCommandStop;
}

// ── Thread ───────────────────────────────────────────────────────────────────
static int32_t fido2_worker_thread(void* ctx) {
    Fido2Worker* worker = ctx;
    worker->thread_id = furi_thread_get_current_id();
    memset(&worker->fingerprint, 0, sizeof(Fido2Fingerprint));

    worker->poller = nfc_poller_alloc(worker->nfc, NfcProtocolIso14443_4a);
    nfc_poller_start(worker->poller, fido2_poller_callback, worker);

    uint32_t flags = furi_thread_flags_wait(
        WORKER_DONE | WORKER_ERR, FuriFlagWaitAny, 15000);

    nfc_poller_stop(worker->poller);
    nfc_poller_free(worker->poller);
    worker->poller = NULL;

    Fido2WorkerEvent result = (flags & WORKER_DONE)
        ? Fido2WorkerEventSuccess : Fido2WorkerEventFail;

    if(worker->callback) worker->callback(result, worker->context);
    return 0;
}

// ── API pública ───────────────────────────────────────────────────────────────
Fido2Worker* fido2_worker_alloc(Nfc* nfc) {
    Fido2Worker* w = malloc(sizeof(Fido2Worker));
    memset(w, 0, sizeof(Fido2Worker));
    w->nfc = nfc;
    w->tx  = bit_buffer_alloc(64);
    w->rx  = bit_buffer_alloc(FIDO2_MAX_RESPONSE);
    w->acc = bit_buffer_alloc(FIDO2_MAX_RESPONSE * 2);
    return w;
}

void fido2_worker_free(Fido2Worker* w) {
    furi_assert(w);
    fido2_worker_stop(w);
    bit_buffer_free(w->tx);
    bit_buffer_free(w->rx);
    bit_buffer_free(w->acc);
    free(w);
}

void fido2_worker_start(Fido2Worker* w, Fido2WorkerCallback cb, void* ctx) {
    furi_assert(w);
    w->callback = cb;
    w->context  = ctx;
    w->running  = true;
    w->thread   = furi_thread_alloc_ex("Fido2Worker", 4096, fido2_worker_thread, w);
    furi_thread_start(w->thread);
}

void fido2_worker_stop(Fido2Worker* w) {
    furi_assert(w);
    if(!w->running) return;
    w->running = false;
    if(w->thread) {
        furi_thread_join(w->thread);
        furi_thread_free(w->thread);
        w->thread = NULL;
    }
}

Fido2Fingerprint* fido2_worker_get_fingerprint(Fido2Worker* w) {
    return &w->fingerprint;
}
