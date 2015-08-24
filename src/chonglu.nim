import posix
import strutils
import parseopt2
import redis
import tables

import ../../pfring.nim/pfring/core

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
    count: int
    firstTime: Timeval


var
  ring: Ring
  cfg: Config
  counters = initTable[int32, Info]()

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
  let stat = ring.getStats()
  echo "Received " & $stat.received & " packets, dropped " & $stat.dropped & " packets"
  ring.close()
  quit(QuitSuccess)

proc packetListener(h: ptr pfring_pkthdr, p: ptr cstring, user_bytes: ptr cstring) =
  var src_addr, dst_addr {.global.}: InAddr
  var hasSyn, hasAck: bool
  var info: Info
  p.parsePacket(h, 4, 0, 0)
  let pkt = addr h.extended_hdr.parsed_pkt

  if pkt.l3_proto.int != IPPROTO_TCP:
    return

  if pkt.ip_version == 4:
    if not (pkt.l4_dst_port in cfg.ports):
      return

    src_addr.s_addr = htonl(pkt.ip_src.v4)
    dst_addr.s_addr = htonl(pkt.ip_dst.v4)
    echo "$#:$# => $#:$#" % [$inet_ntoa(src_addr), $pkt.l4_src_port, $inet_ntoa(dst_addr), $pkt.l4_dst_port]

    hasSyn = (pkt.tcp.flags and TH_SYN) != 0
    hasAck = (pkt.tcp.flags and TH_ACK) != 0

    if hasSyn:
      if not counters.hasKey(pkt.ip_src.v4):
        info.count = 1
        counters[pkt.ip_src.v4] = info
      else:
        info = counters[pkt.ip_src.v4]
        inc(info.count)
        counters[pkt.ip_src.v4] = info
        echo info.count





  # else: ipv6 is not supported yet
proc main() =
  ring = newRing(cfg.iface, 65536, PF_RING_PROMISC or PF_RING_DO_NOT_PARSE)

  if ring.cptr.isNil:
    quit("pfring_open error: $#" % $errno, QuitFailure)

  setControlCHook(signalHandler)

  ring.setDirection(ReceiveOnly)
  ring.setSocketMode(ReadOnly)
  #ring.setBPFFilter(config.filter)
  ring.enable()
  ring.startLoop(packetListener, nil, true);

when isMainModule:
  var cfgFile: string
  parseCommandLine(cfgFile)
  cfg = parseConfig(cfgFile)
  main()
