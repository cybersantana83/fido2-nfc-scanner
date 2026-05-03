# FIDO2 NFC Scanner

FAP para Flipper Zero (Momentum firmware) que extrai e exibe metadados de
autenticadores FIDO2 via NFC sem qualquer autenticação.

## Contexto

O FIDO2 foi projetado para garantir unlinkability entre serviços — um
authenticator não deve ser rastreável entre relying parties. Esta pesquisa
documenta que tokens como o YubiKey 5 NFC expõem um fingerprint completo
antes de qualquer autenticação, violando essa propriedade de privacidade.

## O que o app captura

- **ATS Historical Bytes** — string "YubiKey" em texto claro antes de qualquer
  autenticação (tag COMPACT-TLV proprietária da Yubico)
- **AAGUID** — identificador único de modelo de hardware, cruzável com FIDO MDS
- **Versões CTAP2** — U2F_V2, FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1
- **Extensions** — credProtect, hmac-secret, largeBlobKey, credBlob, minPinLength
- **PIN status** — clientPin configurado ou não
- **RAW CBOR** — resposta bruta do CTAP2 GetInfo salva no SD card

## Hardware testado

| Dispositivo | Resultado |
|-------------|-----------|
| YubiKey 5 NFC (FW 5.7.4) | ✅ Fingerprint completo |
| Flipper Zero (Momentum) | ✅ Captura independente |
| Proxmark3 | ✅ Dump de referência |

## Como usar

1. Instale o `.fap` em `/ext/apps/NFC/` no SD card do Flipper
2. Abra o app em **Apps → NFC → FIDO2 NFC Scanner**
3. Aproxime o autenticador NFC
4. O fingerprint é exibido na tela e salvo em `/ext/apps_data/fido2_scanner/`

## Download

O `.fap` compilado está disponível em `releases/fido2_scanner_v0.1.fap`.

Compatível com Momentum firmware. Copie para `/ext/apps/NFC/` no SD card.

## Build

```bash
cd Momentum-Firmware
cp -r fido2-nfc-scanner applications/external/fido2_scanner
./fbt fap_fido2_scanner
```

## Notas técnicas

- Implementa reassembly de I-block chaining manualmente (TODO na lib do Momentum)
- Parser CBOR mínimo sem dependências externas
- Usa `iso14443_4a_get_historical_bytes` da API pública do Momentum

## Status da pesquisa

- [x] Captura com Proxmark3
- [x] Captura independente com Flipper Zero
- [x] FAP funcional com parser CBOR
- [x] Detecção de YubiKey nos ATS historical bytes
- [x] Salvar fingerprint em SD card
- [ ] Fix do segundo chunk (FWT — MaxMsg, Transports, FW version)
- [ ] Responsible disclosure (Yubico + FIDO Alliance)
- [ ] Paper + H2HC 2026

## Disclaimer

Esta ferramenta foi desenvolvida para fins de pesquisa de segurança.
O processo de responsible disclosure está em andamento.
Não utilize para fins maliciosos.

## Autor

CyberSantana — Café com Solda
