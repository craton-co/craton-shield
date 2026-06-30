# Hardware-in-the-Loop Testing — RS485 / Modbus RTU Bench

**Version**: 1.0.0 (draft) | **Status**: procedure validated offline; awaiting physical run
**Applies to**: `vs-modbus-monitor-ind` (industrial Modbus RTU IDS)
**Author**: Craton Shield Team

This guide walks a first-time tester through exercising the Craton Shield
Modbus RTU intrusion-detection monitor against a **real RS485 wire**, using two
USB-RS485 adapters and a laptop. No Linux, Raspberry Pi, or soldering required.

> **Why this bench and not CAN?**
> Craton Shield Core is a `#![no_std]` inspection library; it does not capture
> traffic itself. The only physical-bus HAL in the repo is Linux **SocketCAN**
> ([core/hal-linux](../hal-linux)), which needs Linux and a CAN controller on an
> SPI host (e.g. an MCP2515 on a Raspberry Pi). With a Windows laptop and
> USB-RS485 adapters, the **Modbus RTU monitor** is the subsystem we can drive
> end-to-end over a genuine wire today. The CAN path is documented separately as
> a future bench (needs a Linux SBC).

---

## 1 Bill of Materials

| Used | Item | Role on this bench |
|:---:|:---|:---|
| ✅ | USB-RS485 adapter (CH343G) ×2 | One transmits Modbus RTU, one is the IDS tap |
| ✅ | Dupont jumper wires (F-F) ×3 | Wire the two adapters together (A, B, GND) |
| ✅ | Windows laptop | Runs both the replayer and the monitor |
| ❌ | MCP2515 + TJA1050 (CAN) | Not used here — needs an SPI host (Pi/Arduino) for the CAN bench |
| ❌ | STM32F767ZI | Not used here — would need custom firmware |
| ❌ | MPU6050 | Not used here — emits I²C motion data, not bus frames |

---

## 2 Wiring

The two adapters share one differential pair. RS485 is half-duplex multidrop,
so the tap simply listens to whatever the other adapter transmits.

```
   Adapter 1 (REPLAYER)              Adapter 2 (MONITOR / TAP)
   ┌──────────────┐                 ┌──────────────┐
   │   A / D+  ●───┼───── wire ──────┼───● A / D+   │
   │   B / D-  ●───┼───── wire ──────┼───● B / D-   │
   │   GND     ●───┼───── wire ──────┼───● GND      │
   └──────┬───────┘                 └──────┬───────┘
          │ USB                            │ USB
        laptop  ←────── same laptop ──────→ laptop
```

**Rules:**
- **A↔A** (sometimes labelled `D+` or `T/R+`), **B↔B** (`D-` / `T/R-`), **GND↔GND**.
- **Do not** cross A and B. If you see no traffic, swapping A/B is the first thing to try — it is the most common wiring mistake and harmless to test.
- At ≤19200 baud over a few cm of jumper wire you do **not** need 120 Ω termination resistors.
- Plug **both** adapters into the laptop's USB ports.

---

## 3 Driver & COM Port Setup (Windows)

1. **Install the CH343 driver** if Windows hasn't already: download the WCH
   `CH343SER` driver from the manufacturer, run the installer, replug the
   adapters. Each adapter should appear under *Device Manager → Ports (COM & LPT)*
   as `USB-Enhanced-SERIAL CH343 (COMx)`.
2. **List the two COM ports** in PowerShell:
   ```powershell
   [System.IO.Ports.SerialPort]::getportnames()
   ```
   You should see two new ports, e.g. `COM5` and `COM6`. To tell which is which,
   unplug one and re-run — the port that disappears is that adapter.
3. Decide a role: e.g. **COM6 = replayer**, **COM5 = monitor**. (Either assignment works.)

---

## 4 Build the Harness

The bench tooling lives in [tools/modbus-rs485-harness](../../tools/modbus-rs485-harness).
It is a standalone `std` crate (its own workspace) that depends on the certified
`vs-modbus-monitor-ind` and `vs-types-ind` crates by path — so the IDS logic
under test is **the real production code**, only the serial I/O glue is new.

```powershell
cd C:\craton\shield-hw-test\tools\modbus-rs485-harness
cargo build --release
```

This produces two binaries under `target\release\`:
- `vs-modbus-monitor.exe` — the IDS tap
- `vs-modbus-replay.exe` — the traffic generator

**Sanity check (no hardware needed):**
```powershell
cargo test -- --nocapture
```
This runs the offline validation and prints the *expected verdict table* — the
hardware run should reproduce it exactly.

---

## 5 Run the Test

Open **two terminals**.

**Terminal A — start the monitor first** (so it's listening before traffic):
```powershell
cd C:\craton\shield-hw-test\tools\modbus-rs485-harness
.\target\release\vs-modbus-monitor.exe COM5 19200
```
It prints `listening on COM5 @ 19200 ...` and waits. It exits automatically ~4 s
after the last frame and prints a summary.

**Terminal B — send the scripted traffic:**
```powershell
cd C:\craton\shield-hw-test\tools\modbus-rs485-harness
.\target\release\vs-modbus-replay.exe COM6 19200 1
```

The replayer sends 8 frames (3 legitimate reads + 5 attacks). Watch Terminal A
classify each one.

> **Profiles:** the monitor defaults to the **strict** read-only profile. Add
> `--permissive` to see the contrast (most attacks become `ALLOW`), which is a
> good way to demonstrate that the policy — not the parser — is what blocks them.

---

## 6 Expected Result

Under the **strict** profile, Terminal A should show (verbatim verdicts,
validated offline in [tests/offline.rs](../../tools/modbus-rs485-harness/tests/offline.rs)):

| # | Frame | Verdict |
|:-:|:---|:---|
| 1 | ReadHoldingRegisters (FC 0x03) | `ALLOW` |
| 2 | ReadInputRegisters (FC 0x04) | `ALLOW` |
| 3 | ReadCoils (FC 0x01) | `ALLOW` |
| 4 | WriteSingleRegister (FC 0x06) | `DENY [UnknownFunctionCode]` |
| 5 | WriteMultipleRegisters (FC 0x10) | `DENY [UnknownFunctionCode]` |
| 6 | Diagnostics Restart (FC 0x08) | `DENY [UnknownFunctionCode]` |
| 7 | Unknown function 0x41 | `DENY [UnknownFunctionCode]` |
| 8 | Corrupted CRC | `DENY [CrcFailure]` |

> Under read-only policy, every non-read function code is rejected as
> `UnknownFunctionCode` (it is not on the allowlist) *before* the dedicated
> diagnostic-sub-function path runs. To exercise that path and the address-range
> rules with distinct alert codes, configure the safety profile — see §8.

The summary block reports counts and a **per-frame inspection-latency**
histogram (mean / p50 / p99 / max), measured on your actual machine.

---

## 7 Capturing Results

Save both terminals' output. Paste them back so the measured numbers and
verdicts can be written into:
- [docs/performance-results.md](performance-results.md) — real per-frame latency on this host
- [docs/hardware-compatibility.md](hardware-compatibility.md) — CH343G adapter added as a validated RS485 interface
- [docs/test-plan.md](test-plan.md) — RS485/Modbus HIL added to the test environment matrix

A copy/paste template is in [results-template.md](results-template.md).

---

## 8 Going Further

- **Safety profile** — to trigger the dedicated `DangerousDiagnostic`,
  `IllegalAddress`, and rate-limit alert codes (instead of everything collapsing
  to `UnknownFunctionCode`), extend the monitor binary to configure
  `set_function_code_allowlist(FC_PROFILE_SAFETY)`,
  `set_block_dangerous_diagnostics(true)`, and `add_address_rule(...)`.
- **Sensor-driven traffic** — wire the MPU6050 to the STM32 (or any MCU), have
  it publish accelerometer values into Modbus holding registers, and inject
  out-of-range writes as the attack. This turns the "irrelevant" motion sensor
  into a realistic data source the IDS protects.
- **CAN bench** — on a Raspberry Pi, attach an MCP2515 over SPI (`mcp251x`
  kernel driver → `can0`) and drive [core/hal-linux](../hal-linux) directly.

---

## 9 Troubleshooting

| Symptom | Likely cause / fix |
|:---|:---|
| Monitor prints nothing | A/B swapped — swap the two data wires. Also confirm both COM ports and matching baud. |
| `could not open COMx` | Port in use (close other terminal/serial tool) or wrong port name. |
| All frames `PARSE ERROR` | Baud mismatch between the two terminals, or missing GND wire. |
| Garbled / partial frames | Increase the replayer inter-frame gap, or lower baud to 9600 on both sides. |
| Verdicts differ from §6 | Check you're on the strict profile (no `--permissive`) and rebuilt after any edits. |
