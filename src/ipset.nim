import ../../libipset.nim/libipset

export ipset_cmd_enum


proc ipcmd*(blacklist: string, address: cstring, cmd: ipset_cmd_enum): int =
  var session = ipset_session_init(nil);

  if session.isNil:
    echo "Cannot init session"
    return 1

  var ret = ipset_parse_setname(session, IPSET_SETNAME, blacklist)
  if ret < 0:
    return 2

  var typ = ipset_type_get(session, cmd)
  if typ.isNil:
    return 3

  ret = ipset_parse_elem(session, typ.last_elem_optional, address)
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
