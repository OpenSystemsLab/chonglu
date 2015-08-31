import ../../libipset.nim/libipset

export ipset_cmd_enum


#proc outfn(fmt: string, n: varargs[string, $]):
proc c_printf(frmt: cstring) {.importc: "printf", header: "<stdio.h>", varargs.}

proc ipcmd*(blacklist: string, address: cstring, cmd: ipset_cmd_enum): int =
  ipset_load_types()

  var session = ipset_session_init(c_printf);

  if session.isNil:
    echo "Cannot init session"
    return 1

  var ret = ipset_parse_setname(session, IPSET_SETNAME, blacklist)
  if ret < 0:
    return 2

  var err = ipset_session_error(session)
  if not err.isNil:
    echo err

  var typ = ipset_type_get(session, cmd)
  if typ.isNil:
    return 3



  ret = ipset_parse_elem(session, true, address)
  if ret < 0:
    return 4

  ret = ipset_cmd(session, cmd, 777)
  if ret < 0:
    return 5

  ret = ipset_commit(session)
  if ret < 0:
    return 7

  discard ipset_session_fini(session)


  return 0


when isMainModule:
  echo ipcmd("blacklist", "8.8.8.8", IPSET_CMD_ADD)
