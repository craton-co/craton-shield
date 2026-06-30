# On-Target Self-Test & WCET — NUCLEO-F767ZI

**Version**: 1.0.0 (draft) | **Status**: firmware cross-compiles + links; vector
table validated; awaiting on-silicon run
**Board**: NUCLEO-F767ZI (STM32F767ZI, Cortex-M7F @ up to 216 MHz)
**Firmware**: [tools/stm32f767-selftest](../../tools/stm32f767-selftest)

This is the **on-silicon** counterpart to [performance-results.md](performance-results.md).
That document reports x86 criterion benchmarks plus *estimated* target latency
(scaling factors such as "~8–12× slower"). This firmware **measures the real
thing**: it cross-compiles the certified `vs-can-monitor` and
`vs-modbus-monitor-ind` crates to the Cortex-M7 and times them with the **DWT
cycle counter**, the hardware instrument used for WCET work.

> **Why this matters for the review.** The "weakest point = no real hardware
> testing" critique is answered here: the production IDS code executes on the
> actual target MCU, and we get *measured* cycle counts instead of estimates.

---

## 1 What the firmware does

On boot it:
1. Configures the core clock to its **216 MHz** maximum (worst-case-fastest path).
2. Enables the DWT cycle counter.
3. Runs the real IDS operations `ITERS` times each, timing every single call:
   - `CanMonitor::process_frame` — allowlisted ID (hot path) and unknown ID
   - `ModbusMonitor::inspect_rtu` — an allowed read and a denied write
4. Prints **min / mean / max cycles** (and ns at 216 MHz) per operation over the
   USB serial port, then a PASS/REVIEW line against the CAN bus timing budget.

`max` cycles is the observed WCET. Cycles are the primary metric because they
are clock-independent; ns is derived.

---

## 2 Build the firmware

```powershell
cd C:\craton\shield-hw-test\tools\stm32f767-selftest
.\make-bin.ps1
```

This produces (validated to compile + link, with a correct Cortex-M vector
table — initial SP `0x20080000`, reset vector in flash):

```
target\thumbv7em-none-eabihf\release\stm32f767-selftest.bin
```

> First build pins two transitive crates for Cargo 1.82 compatibility
> (`time` 0.3.36, `time-core` 0.1.2); this is already captured in `Cargo.lock`.

---

## 3 Flash it (drag-and-drop — no debugger needed)

1. Connect the Nucleo's **ST-LINK USB** port (the one near the mini/micro-USB
   end labelled `CN1 / ST-LINK`) to the laptop.
2. A USB drive named **`NODE_F767ZI`** appears in Explorer.
3. **Drag `stm32f767-selftest.bin` onto that drive.** The ST-LINK flashes it and
   the board resets automatically. The drive re-mounts when done.

(Alternative: STM32CubeProgrammer, or `probe-rs run` if you install probe-rs.)

---

## 4 Read the results

The same ST-LINK USB connection also provides a **virtual COM port**
(`STMicroelectronics STLink Virtual COM Port (COMx)` in Device Manager).

Open it at **115200 8N1** with any serial terminal — including the RS485
harness's monitor is *not* needed; use PuTTY, `tio`, or this one-liner that
reuses tooling you already have:

```powershell
# minimal reader using the same serialport stack:
# (or just use PuTTY / Tera Term at 115200 8N1)
```

Press the black **RESET** button on the board to re-run and re-print.

Expected output (shape — real numbers come from your run):

```
==== Craton Shield on-target self-test ====
board   : NUCLEO-F767ZI (Cortex-M7F)
sysclk  : 216000000 Hz
iters   : 2000 per op (single-shot timed)

CAN process_frame (allowlisted ID)     min=...  cyc (... ns)  mean=... cyc  max=... cyc (... ns)
CAN process_frame (unknown ID)         min=...  cyc (... ns)  mean=... cyc  max=... cyc (... ns)
Modbus inspect_rtu (allow)             min=...  cyc (... ns)  mean=... cyc  max=... cyc (... ns)
Modbus inspect_rtu (deny)              min=...  cyc (... ns)  mean=... cyc  max=... cyc (... ns)

CAN WCET (allowlisted) = ... ns at 216 MHz
RESULT: PASS (within CAN 10us bus budget)

==== self-test complete ====
```

---

## 5 Capturing results

Paste the serial output back. It will be written into:
- [performance-results.md](performance-results.md) — a new **measured on-target
  WCET** table alongside the existing estimates (so the estimate vs. measurement
  comparison is explicit).
- [hardware-compatibility.md](hardware-compatibility.md) — STM32F767ZI promoted
  from "Tier 2 / bare-metal with custom HAL" to **on-target validated**.
- [test-plan.md](test-plan.md) — the "HILS (planned)" row becomes a real entry.

---

## 6 Troubleshooting

| Symptom | Likely cause / fix |
|:---|:---|
| No `NODE_F767ZI` drive | Use the ST-LINK USB port (not the user USB), and a data-capable cable. |
| Drive shows `FAIL.TXT` after copy | Old ST-LINK firmware — update via STM32CubeProgrammer/ST-LINK upgrade tool, or flash with probe-rs. |
| No serial output | Confirm 115200 8N1 and the **STLink Virtual COM Port**. Press RESET. If still nothing, the 216 MHz clock config may not converge on your board revision — drop `SYSCLK_HZ` to `120_000_000` in `src/main.rs`, rebuild, reflash. |
| Garbled text | Wrong baud — must be 115200. |

---

## 7 Scope & honesty notes

- This measures the IDS **compute** path on real silicon. It does **not** yet
  ingest frames from a physical CAN transceiver — that is Tier 2 (a `vs-hal`
  `CanBus` implementation driving the MCP2515 over SPI).
- The firmware was verified to **cross-compile, link, and produce a
  well-formed boot image** on the development host. On-silicon execution and the
  numbers themselves are confirmed only once you run it and paste the output —
  no results are written into the certification docs before then.
