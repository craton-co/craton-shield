# Build the firmware and emit a flashable .bin (+ .hex) next to the ELF.
# Usage:  .\make-bin.ps1
#
# cargo-binutils does not install on Cargo 1.82 (an edition2024 transitive dep),
# so this script calls llvm-objcopy from the installed `llvm-tools` component
# directly. Requires: rustup component add llvm-tools

$ErrorActionPreference = "Stop"

cargo build --release

$sysroot = (rustc --print sysroot).Trim()
$objcopy = Get-ChildItem -Path $sysroot -Recurse -Filter "llvm-objcopy.exe" |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $objcopy) {
    throw "llvm-objcopy not found. Run: rustup component add llvm-tools"
}

$elf = "target\thumbv7em-none-eabihf\release\stm32f767-selftest"
& $objcopy -O binary $elf "$elf.bin"
& $objcopy -O ihex   $elf "$elf.hex"

Write-Host ""
Write-Host "Built:"
Write-Host "  $elf.bin   <- drag this onto the NODE_F767ZI USB drive to flash"
Write-Host "  $elf.hex"
