import posix
import strutils
import parseopt2
import redis
import tables
import times
import logging

import ipset
import ../../pfring.nim/pfring/wrapper

import config

const
  name = "chonglu"
  version = "0.0.1"

  help = """
$# - SYN Flood Stopper

Usase:
  chonglu [--config=path]

Options:
  -h --help        show this help
  -v --version     show version
  --config=<path>  path to config file [default: $#]
""" % [name, defaultConfig]

type
  Info = object
    counters: array[0..5, int]
    lastActive: Time

var
  ring: ptr pfring
  cfg: Config
  lookupTable = initTable[int32, Info]()
  banList: seq[int32] = @[]

proc showVersion() =
  quit("$# version $# compiled at $# $#" % [name, version, CompileDate, CompileTime], QuitSuccess)

proc showHelp() =
  quit(help, QuitSuccess)

proc parseCommandLine(configFile: var string) =
  var opt = initOptParser()
  while true:
    opt.next()
    let key = opt.key.toLower()
    case opt.kind:
    of cmdLongOption, cmdShortOption:
      case key:
      of "h", "help": showHelp()
      of "v", "version": showVersion()
      of "config": configFile = opt.val
      else: showHelp()
    of cmdArgument: discard
    of cmdEnd: break

proc signalHandler() {.noconv.} =
  var stat: pfring_stat

  let res = pfring_stats(ring, addr stat)
  if res == 0:
    info("Received ", stat.recv, " packets, dropped ", stat.drop, " packets")
  pfring_close(ring)
  quit(QuitSuccess)


proc accumulateCounters(info: Info): int =
  result = 0
  for i in info.counters:
    result += i

proc packetListener(h: ptr pfring_pkthdr, p: cstring, user_bytes: ptr cstring) {.cdecl.} =
  var src_addr: InAddr
  var hasSyn, hasAck: bool
  var currentSecond: int

  discard pfring_parse_pkt(p, h, 4, 0, 0)

  # Small hack to make pfring_parse_pkt parse L4 info
  # Still dont know why header pointer dont reset for each loop, like C code does
  h.extended_hdr.parsed_pkt.offset.l4_offset = 0

  var pkt = addr h.extended_hdr.parsed_pkt

  if banList.contains(pkt.ip_src.v4):
    # already banned
    return

  if pkt.l3_proto.int != IPPROTO_TCP:
    return

  if pkt.ip_version == 4:
    if not (pkt.l4_dst_port in cfg.ports):
      return

    if cfg.debugMode:
      var dst_addr: InAddr
      src_addr.s_addr = htonl(pkt.ip_src.v4)
      dst_addr.s_addr = htonl(pkt.ip_dst.v4)

      debug(inet_ntoa(src_addr), ":", pkt.l4_src_port, " => ", inet_ntoa(dst_addr), ":", pkt.l4_dst_port)

    hasSyn = (pkt.tcp.flags and TH_SYN) != 0
    #hasAck = (pkt.tcp.flags and TH_ACK) != 0

    if hasSyn:
      currentSecond = getLocalTime(getTime()).second mod cfg.recalculationTime

      if not lookupTable.hasKey(pkt.ip_src.v4):
        var info: Info
        info.lastActive = getTime()
        info.counters[currentSecond] = 1
        lookupTable[pkt.ip_src.v4] = info
      else:
        var indexForNullify = abs(cfg.recalculationTime - currentSecond)
        var info = lookupTable[pkt.ip_src.v4]
        info.counters[indexForNullify] = 0
        inc(info.counters[currentSecond])
        info.lastActive = getTime()
        lookupTable[pkt.ip_src.v4] = info


        var requestsPerCalculationPeriod = lookupTable[pkt.ip_src.v4].accumulateCounters()
        var requestsPerSecond = int(requestsPerCalculationPeriod / cfg.recalculationTime)

        if requestsPerSecond >= cfg.rateLimit:
          warn("IP: ", inet_ntoa(src_addr), " exeed rate limit ", requestsPerSecond, " requrests", inet_ntoa(src_addr))

          # call ipset ban
          let ret = ipcmd(cfg.blacklistName, inet_ntoa(src_addr), IPSET_CMD_ADD)
          if ret == 0:
            # Add to ban list
            banList.add(pkt.ip_src.v4)
          else:
            error("Ban failed with error: ", ret)

  # else: ipv6 is not supported yet

proc initLogger() =
  if cfg.logPath.isNil or cfg.logPath == "":
    return

  addHandler(newFileLogger(cfg.logPath))


proc main() =
  initLogger()

  info(name, " started")

  var flags: uint32 = 0
  flags = flags or PF_RING_PROMISC
  flags = flags or PF_RING_DO_NOT_PARSE
  ring = pfring_open(cfg.iface, 1500, flags)

  if ring.isNil:
    quit("pfring_open error: $#" % $errno, QuitFailure)


  setControlCHook(signalHandler)

  #discard pfring_set_socket_mode(r, recv_only_mode)
  discard pfring_enable_ring(ring)

  info("Start listening for incoming packets on ", cfg.iface, " and ports ", cfg.ports)

  discard pfring_loop(ring, packetListener, nil, 1)

when isMainModule:
  var cfgFile: string
  parseCommandLine(cfgFile)
  cfg = parseConfig(cfgFile)


  main()
