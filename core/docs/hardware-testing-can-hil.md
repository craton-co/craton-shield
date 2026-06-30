# CAN Hardware-in-the-Loop — NUCLEO-F767ZI + MCP2515 ×2

**Version**: 1.0.0 (draft) | **Status**: firmware + MCP2515 `vs_hal::CanBus`
driver cross-compile, link, and emit a valid boot image; awaiting on-bus run
**Firmware**: [tools/stm32f767-canhil](../../tools/stm32f767-canhil)

This is **Tier 2** — the piece that fully closes the "no real hardware testing"
gap for the flagship CAN path. Real CAN frames travel over a physical
twisted-pair bus between two transceivers and are inspected **on the Cortex-M7**
by the certified `vs-can-monitor`, through a new bare-metal
[`vs_hal::CanBus`](../hal/src/lib.rs) implementation for the MCP2515.

```
   Node B (traffic gen)            Node A (IDS interface)
   MCP2515 #2  ── CANH/CANL ───────  MCP2515 #1
      │ SPI2                            │ SPI1
      └──────────  STM32F767  ─────────┘
                      │ USART3 -> ST-LINK VCP -> laptop
```

> The MCP2515 is an **SPI** CAN controller — it cannot connect to a PC directly.
> The STM32 is the SPI host for *both* modules; the modules' TJA1050
> transceivers form a genuine CAN bus between them.

---

## 1 What it proves

- The IDS ingests frames from a **real CAN transceiver**, not a simulated
  buffer (the missing half of Tier 1, which ran compute on-chip but fed
  in-memory frames).
- A new, reusable `vs_hal::CanBus` driver
  ([src/mcp2515.rs](../../tools/stm32f767-canhil/src/mcp2515.rs)) — the
  bare-metal analogue of the Linux SocketCAN HAL.
- **Flood detection firing from live bus traffic**: node B injects a frame
  burst faster than the configured 2 ms threshold; the on-chip IDS flags it.

---

## 2 Bill of Materials

| Used | Item |
|:---:|:---|
| ✅ | NUCLEO-F767ZI |
| ✅ | MCP2515 + TJA1050 module ×2 |
| ✅ | Dupont jumpers (M-F) — ~13 wires |
| ❌ | CH343G RS485 adapters (that's the separate Modbus bench) |
| ❌ | MPU6050 |

---

## 3 Wiring

### 3.1 SPI — STM32 to each MCP2515

| MCP2515 pin | Node A (IDS) → STM32 | Node B (gen) → STM32 |
|:---|:---|:---|
| VCC | **3V3** (see note) | **3V3** |
| GND | GND | GND |
| SCK | PA5  | PB13 |
| SO (MISO) | PA6 | PB14 |
| SI (MOSI) | PA7 | PB15 |
| CS | PD14 | PB12 |
| INT | *(not connected — firmware polls)* | *(not connected)* |

On the NUCLEO-144 these are on the CN7/CN8/CN9/CN10 morpho/Arduino headers;
any 3V3 and any GND pin will do for power.

> **Power-level note (important).** These modules carry a 5 V TJA1050.
> Powering VCC at **3V3** keeps all SPI levels clean for the STM32 and is the
> reliable choice for bring-up — both modules run at the same 3V3, so their
> transceivers still interoperate over the short bench bus. If you power them at
> 5 V instead, the MCP2515's logic-high input threshold (~3.5 V) may not
> recognise the STM32's 3.3 V SPI outputs, and the 5 V MISO line feeds back into
> the MCU. Start at 3V3.

### 3.2 CAN bus — the two modules to each other

| Node A | Node B |
|:---|:---|
| CANH | CANH |
| CANL | CANL |

Just two wires joining the transceivers. Each module has an onboard 120 Ω
terminator, which gives the correct ~60 Ω across a 2-node bench bus — no extra
resistors needed.

---

## 4 Match the bit timing to your crystal

**This is the most common reason a CAN bus stays silent.** Look at the silver
crystal can on each MCP2515 module:
- marked **8.000** → 8 MHz (the usual default) — no change needed.
- marked **16.000** → 16 MHz → edit [src/main.rs](../../tools/stm32f767-canhil/src/main.rs):
  ```rust
  const TIMING: BitTiming = BitTiming::KBPS500_XTAL16;
  ```
Both modules must use the same setting. Rebuild after any change.

---

## 5 Build & flash

```powershell
cd C:\craton\shield-hw-test\tools\stm32f767-canhil
.\make-bin.ps1
```
Drag `target\thumbv7em-none-eabihf\release\stm32f767-canhil.bin` onto the
**`NODE_F767ZI`** USB drive (same drag-and-drop flow as Tier 1). Open the
**STLink Virtual COM Port** at **115200 8N1** and press RESET.

---

## 6 Expected output (shape)

```
==== Craton Shield CAN HIL (Tier 2) ====
board : NUCLEO-F767ZI, two MCP2515 on one CAN bus
bitrate: 500000 bit/s (crystal-dependent timing)
both MCP2515 controllers initialised OK

Phase 1: baseline traffic on ID 0x100 (10 ms spacing)
  ok    baseline           id=0x100 dlc=8
  ... (no alerts — spacing above threshold)

Phase 2: flood on ID 0x100 (~0.3 ms spacing)
  ALERT flood              id=0x100 sev=High src=0x100
  ... (flood detected on the live bus)

Phase 3: traffic on unmonitored ID 0x200
  ok    other-id           id=0x200 dlc=8

──────────── SUMMARY ────────────
frames sent (node B)     : 20
frames received (node A) : 20
IDS alerts raised        : <n>
RESULT: PASS — real CAN frames inspected on-chip, flood detected
```

`frames received > 0` is the headline: it means frames physically crossed the
CAN bus and reached the IDS. `RESULT: NO BUS TRAFFIC` points at wiring,
termination, or a crystal/timing mismatch (§4, §9).

---

## 7 Capturing results

Paste the serial output back. It feeds:
- [hardware-compatibility.md](hardware-compatibility.md) — MCP2515 added as a
  validated CAN controller; STM32F767 CAN path marked HIL-validated.
- [test-plan.md](test-plan.md) — the "vCAN / HILS" rows gain a real bare-metal
  entry.
- [performance-results.md](performance-results.md) — on-bus round behaviour
  alongside the Tier 1 WCET numbers.

---

## 8 Honesty notes

- The MCP2515 driver and firmware are verified to **compile, link, and produce
  a valid boot image** on the host. Register-level logic follows the MCP2515
  datasheet, but **on-bus behaviour is confirmed only once you run it** — bit
  timing, SPI levels, and termination are physical variables I can't test from
  here. Nothing goes into the certification docs until your output confirms it.
- Both modules are driven by one MCU. That is a real two-controller CAN bus with
  real arbitration and transceivers — but a single-host bench, not two
  independent ECUs. A fully independent attacker node would use the second
  MCP2515 on a separate board; noted as a future step.

---

## 9 Troubleshooting

| Symptom | Likely cause / fix |
|:---|:---|
| `FATAL: ... MCP2515 init failed` | SPI wiring or power. Check VCC/GND to that module and its CS pin. Init verifies mode-switch over SPI, so this is an SPI-link problem, not the CAN bus. |
| `RESULT: NO BUS TRAFFIC` | CANH/CANL swapped or open; crystal/timing mismatch (§4); both terminators missing. |
| Frames flow but no flood alert | Flood threshold vs. actual spacing — lower `min_interval_us` in the rule or shorten the Phase 2 gap. |
| Garbled serial | Not 115200 8N1. |
| Intermittent receive | Lower SPI speed (already 1 MHz) or shorten jumper wires; ensure common GND between both modules and the board. |
