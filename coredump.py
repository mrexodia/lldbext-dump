# import this into lldb with a command like
# command script import -r coredump.py
import lldb
import importlib
import coredump_impl

def coredump(debugger: lldb.SBDebugger, command: str, exe_ctx: lldb.SBExecutionContext, result: lldb.SBCommandReturnObject, internal_dict: dict):
  importlib.reload(coredump_impl)
  return coredump_impl.coredump(debugger, command, exe_ctx, result, internal_dict)

#
# code that runs when this script is imported into LLDB
#
def __lldb_init_module(debugger: lldb.SBDebugger, internal_dict: dict):
  # This initializer is being run from LLDB in the embedded command interpreter
  # Make the options so we can generate the help text for the new LLDB
  # command line command prior to registering it with LLDB below

  parser = coredump_impl.create_coredump_options()
  coredump.__doc__ = parser.format_help()
  # Add any commands contained in this module to LLDB
  debugger.HandleCommand('command script add -o -f %s.coredump coredump' % __name__)
