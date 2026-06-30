# RS485 / Modbus RTU Bench — Results Capture Template

Fill this in during the physical run and paste it back. Nothing here is
published until it reflects a real run on real hardware.

## Setup

- Date: ____________________
- Laptop CPU / OS: ____________________
- Adapters: 2× CH343G USB-RS485
- Baud: ____________ (default 19200, 8N1)
- Replayer COM port: ________  Monitor COM port: ________
- Monitor profile: [ ] strict  [ ] permissive

## Monitor terminal output (paste verbatim)

```
<paste the full vs-modbus-monitor output here, including the SUMMARY block>
```

## Replayer terminal output (paste verbatim)

```
<paste the full vs-modbus-replay output here>
```

## Verdict check

| # | Frame | Expected | Observed | Pass? |
|:-:|:---|:---|:---|:---:|
| 1 | ReadHoldingRegisters 0x03 | ALLOW | | |
| 2 | ReadInputRegisters 0x04 | ALLOW | | |
| 3 | ReadCoils 0x01 | ALLOW | | |
| 4 | WriteSingleRegister 0x06 | DENY UnknownFunctionCode | | |
| 5 | WriteMultipleRegisters 0x10 | DENY UnknownFunctionCode | | |
| 6 | Diagnostics Restart 0x08 | DENY UnknownFunctionCode | | |
| 7 | Unknown FC 0x41 | DENY UnknownFunctionCode | | |
| 8 | Corrupted CRC | DENY CrcFailure | | |

## Measured inspection latency (from SUMMARY)

- mean: ______ ns   p50: ______ ns   p99: ______ ns   max: ______ ns   (n=____)

## Notes / anomalies

____________________________________________________________
