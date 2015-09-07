import posix
import ../../libipset.nim/libipset

export ipset_cmd_enum


#proc outfn(fmt: string, n: varargs[string, $]):
proc c_printf(frmt: cstring) {.cdecl, importc: "printf", header: "<stdio.h>", varargs.}

proc ipcmd*(setname: string, arg1: cstring, cmd: ipset_cmd_enum): int =
  ipset_load_types()

  var session = ipset_session_init(c_printf);

  if session.isNil:
    echo "Cannot init session"
    return 1

  var ret = ipset_parse_setname(session, IPSET_SETNAME, setname)
  if ret < 0:
    return 2

  var err = ipset_session_error(session)
  if not err.isNil:
    echo err
    return 3

  case cmd:
    of IPSET_CMD_CREATE:
      ret = ipset_parse_typename(session, IPSET_OPT_TYPENAME, arg1)
      if ret < 0:
        return 7
      var typ = ipset_type_get(session, cmd)
      if typ.isNil:
        return 8

    of IPSET_CMD_TEST, IPSET_CMD_ADD:

      var typ = ipset_type_get(session, cmd)
      if typ.isNil:
        return 7

      ret = ipset_parse_elem(session, true, arg1)
      if ret < 0:
        return 8

    else:
      discard

  ret = ipset_cmd(session, cmd, 99)
  if ret < 0:
    return 5

  ret = ipset_commit(session)
  if ret < 0:
    return 6
  discard ipset_session_fini(session)

  return 0


when isMainModule:
  var setname = "blacklist1"
  echo ipcmd(setname, "8.8.8.8", IPSET_CMD_TEST)
  if ipcmd(setname, "8.8.8.8", IPSET_CMD_TEST) == 7:
    echo ipcmd(setname, "iphash", IPSET_CMD_CREATE)
  #echo ipcmd("blacklist", "8.8.8.8", IPSET_CMD_ADD)
