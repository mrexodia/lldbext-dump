import lldb
import shlex
import argparse
import json
import base64
import os
import gzip
import shutil

def create_coredump_options():
  parser = argparse.ArgumentParser("coredump", description="Attempt to dump the process to a filename")
  parser.add_argument("file", help="The filename to dump to.")
  return parser

def coredump(debugger: lldb.SBDebugger, command: str, exe_ctx: lldb.SBExecutionContext, result: lldb.SBCommandReturnObject, internal_dict: dict):
  parser = create_coredump_options()
  try:
    command_args = shlex.split(command)
    args = parser.parse_args(command_args)
  except:
    print("Failed to parse arguments!")
    return

  file: str = os.path.expanduser(args.file)
  basedir = os.path.dirname(file)
  regiondir = os.path.join(basedir, "regions")
  #if os.path.exists(regiondir):
  #  os.removedirs(regiondir)
  #os.mkdir(regiondir)
  if not os.path.exists(regiondir):
    os.mkdir(regiondir)

  target = debugger.GetSelectedTarget()
  print(f"Target: {target}")
  process = target.GetProcess()
  pinfo = process.GetProcessInfo()
  print(f"Process: {process}")
  thread = process.GetSelectedThread()
  print(f"Thread: {thread}")
  frame = thread.GetSelectedFrame()
  print(f"Frame: {frame}")
  registers = frame.GetRegisters()
  asize = process.GetAddressByteSize()
  print(f"Address size: {asize}")

  dump = {
    "process": {
      "pid": pinfo.GetProcessID(),
      "ppid": pinfo.GetParentProcessID(),
      "executable": pinfo.GetName(),
    },
    "thread": {
      "tid": thread.GetThreadID(),
      "name": thread.GetName(),
    },
    "registers": {},
    "regions": [],
  }

  for i in range(len(registers)):
    group = registers.GetValueAtIndex(i)
    print(f"[{i}] name: {group.name}")

    child: lldb.SBValue
    for child in group.children:
      if child.GetByteSize() == asize:
        dump["registers"][child.name] = child.GetValueAsUnsigned()
    break

  dump_regions = False
  regions = process.GetMemoryRegions()
  for i in range(len(regions)):
    region = lldb.SBMemoryRegionInfo()
    if not regions.GetMemoryRegionAtIndex(i, region):
      print(f"[{i}] Failed to get region info!")
      continue

    #interpreter = debugger.GetCommandInterpreter()
    #res = lldb.SBCommandReturnObject()
    #interpreter.ResolveCommand("memory region --all", res)

    base = region.GetRegionBase()
    end = region.GetRegionEnd()
    name = region.GetName()
    if name is None:
      name = ""

    if dump_regions:
      size = end - base
      error = lldb.SBError()
      data = process.ReadMemory(base, size, error)
      if not error.Success():
        print(f"Failed to read region {region}, error: {error}")
      else:
        datab = bytearray(data)
        with gzip.open(os.path.join(regiondir, f"{hex(base)}-{hex(end)}.bin"), "wb") as f:
          f.write(datab)

    jinfo = {
      "start": base,
      "end": end,
      "x": region.IsExecutable(),
      "r": region.IsReadable(),
      "w": region.IsWritable(),
      "m": region.IsMapped(),
      "name": name,
      "pretty": str(region)
    }
    dump["regions"].append(jinfo)

  with open(file, "w") as f:
    json.dump(dump, f, indent=2)

  print("Command completed!")
