import os
import json
import gzip
from typing import TypedDict

from icicle import *

class Process(TypedDict):
    pid: int
    ppid: int
    executable: str

class Thread(TypedDict):
    tid: int
    name: str

class Region(TypedDict):
    start: int
    end: int
    r: bool
    w: bool
    x: bool
    m: bool # TODO: never false?
    name: str

class Coredump(TypedDict):
    process: Process
    thread: Thread
    registers: dict[str, int]
    regions: list[Region]

with open("dump.json", "r") as f:
    dump: Coredump = json.load(f)

pid = dump["process"]["pid"]
executable = dump["process"]["executable"]
print(f"Process: {pid}, {executable}")

emu = Icicle("aarch64")
print(emu)

def mem_protection(r: bool, w: bool, x: bool):
    if not r and not w and not x:
        return MemoryProtection.NoAccess
    if r and not w and not x:
        return MemoryProtection.ReadOnly
    if r and w and not x:
        return MemoryProtection.ReadWrite
    if not r and not w and x:
        return MemoryProtection.ExecuteOnly
    if r and not w and x:
        return MemoryProtection.ExecuteRead
    if r and w and x:
        return MemoryProtection.ExecuteReadWrite
    raise NotImplementedError(f"Unsupported combination: R={r}, W={w}, X={x}")

lazy_regions = []
total_size = 0
for region in dump["regions"]:
    start = region["start"]
    end = region["end"]
    r = region["r"]
    w = region["w"]
    x = region["x"]

    perms = "r" if r else "-"
    perms += "w" if w else "-"
    perms += "x" if x else "-"
    name = region["name"]

    size = end - start
    total_size += size

    print(f"Mapping {hex(start)}-{hex(end)}[{hex(size)}] {perms} {name}")
    emu.mem_map(start, size, MemoryProtection.NoAccess)
    lazy_regions.append((start, end, mem_protection(r, w, x)))

    """
    datafile = os.path.join("regions", f"{hex(start)}-{hex(end)}.bin")
    if not os.path.exists(datafile):
        print(f"   ERROR: {datafile} not found")
    else:
        with gzip.open(datafile, "rb") as f:
            data = f.read()
        try:
            emu.mem_write(start, data)
        except MemoryException as e:
            print(f"    ERROR: {e}")
    """

print(f"Total size: {total_size / 1024 / 1024:.2f} MiB")

# Set registers
for name, value in dump["registers"].items():
    reg_name = {
        "fp": "x29",
        "lr": "x30",
    }.get(name, name)
    print(f"{name} -> {reg_name} = {hex(value)}")
    emu.reg_write(reg_name, value)

def step():
    status = emu.step(1)
    if status == RunStatus.UnhandledException and emu.exception_code == ExceptionCode.ExecViolation:
        address = emu.exception_value
        for i, (start, end, protection) in enumerate(lazy_regions):
            if address >= start and address < end:
                size = end - start
                print(f"Remapping region {hex(start)}-{hex(end)}[{hex(size)}]")
                emu.mem_protect(start, size, protection)
                datafile = os.path.join("regions", f"{hex(start)}-{hex(end)}.bin")
                if not os.path.exists(datafile):
                    print(f"   ERROR: {datafile} not found")
                    raise NotImplementedError()
                else:
                    with gzip.open(datafile, "rb") as f:
                        data = f.read()
                    try:
                        emu.mem_write(start, data)
                    except MemoryException as e:
                        print(f"    ERROR: {e}")

                del lazy_regions[i]
                status = emu.step(1)
                return status

pc = emu.reg_read("pc")
x8 = emu.reg_read("x8")
print(f"PC: {hex(pc)}, X8: {hex(x8)}")
status = step()
pc = emu.reg_read("pc")
x8 = emu.reg_read("x8")
print(f"status: {status}, PC: {hex(pc)}, X8: {hex(x8)}")