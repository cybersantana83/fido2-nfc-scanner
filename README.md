# FIDO2 NFC Scanner

FAP para Flipper Zero (Momentum firmware) que extrai e exibe metadados de
autenticadores FIDO2 via NFC sem qualquer autenticação.

Desenvolvido como ferramenta de pesquisa de segurança por
**Cristiano Santana dos Santos** (Café com Solda @cafecomsoldalab).

## Contexto

O FIDO2 foi projetado para garantir unlinkability entre serviços. Esta
pesquisa documenta que tokens FIDO2 NFC expõem class-level fingerprinting
antes de qualquer autenticação, incluindo vendor strings nos ATS historical
bytes e metadados completos via CTAP2 GetInfo sem PIN ou toque.

Responsible disclosure realizado para Yubico, Identiv/Hirsch e FIDO Alliance.
CVE submetido ao MITRE CNA-LR (CAN-2026-2038918, aguardando revisão).

## Tokens testados

| Token | Fabricante | ATS String | GetInfo sem auth |
|-------|-----------|------------|-----------------|
| YubiKey 5C NFC (FW 5.7.4) | Yubico (CH) | "YubiKey" | AAGUID + FW + PIN + Passkeys |
| uTrust FIDO2 NFC+ | Identiv (US) | "uTrust" | AAGUID + PIN |

## O que o app captura e exibe

**[DEVICE]**
- ATS Historical Bytes com vendor string detectada
- AAGUID (identificador de modelo, cruzável com FIDO MDS)
- Firmware version (ex: 5.7.4)
- Transports (nfc, usb)

**[SECURITY]**
- PIN status (SET / NOT SET)
- PIN minimum length
- Passkeys armazenadas e slots livres (via remainingDiscoverableCredentials)
- MaxMsg size

**[CAPABILITIES]**
- Versões CTAP2 suportadas

**[EXTENSIONS]**
- Extensions disponíveis (credProtect, hmac-secret, etc)

Tudo salvo em `/ext/apps_data/fido2_scanner/scan_XXXXXXXX.fido2`.

## Como usar

1. Instale o `.fap` em `/ext/apps/NFC/` no SD card do Flipper
2. Abra o app em **Apps → NFC → FIDO2 NFC Scanner**
3. Aproxime o autenticador FIDO2 NFC
4. Navegue pelas seções com o d-pad
5. O fingerprint é salvo automaticamente no SD card

## Download

Releases disponíveis em `releases/`:

| Versão | Mudanças |
|--------|---------|
| v0.4 | Display reestruturado, passkeys count, FW version, GET RESPONSE |
| v0.3 | Suporte multi-token (YubiKey + Identiv), ícone |
| v0.2 | Back button fix, detecção ATS |
| v0.1 | Release inicial |

Compatível com Momentum firmware. Copie para `/ext/apps/NFC/`.

## Build

```bash
cd Momentum-Firmware
cp -r fido2-nfc-scanner applications/external/fido2_scanner
./fbt fap_fido2_scanner
```

## Ferramentas relacionadas

- [fido2-token-probe](https://github.com/cybersantana83/fido2-token-probe)
  Demo web Flask que captura AAGUID via WebAuthn browser API

## Disclosure

| Destinatário | Status |
|---|---|
| Yubico | Won't fix — "conformant with specifications" |
| Identiv/Hirsch | Caso #00467298 aberto |
| FIDO Alliance | "Informational privacy-hardening issue" |
| MITRE CNA-LR | CAN-2026-2038918 aguardando revisão |

## Disclaimer

Ferramenta desenvolvida para fins de pesquisa de segurança.
Use com responsabilidade e apenas em dispositivos próprios.

## Autor

**Cristiano Santana dos Santos**
Café com Solda — [@cafecomsoldalab](https://instagram.com/cafecomsoldalab)
GitHub: [@cybersantana83](https://github.com/cybersantana83)
