import posix
import strutils
import parseopt2
import redis

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
  echo "Blah"
#  var stat = ring.getStats()
#  echo "Received " & $stat.received & " packets, dropped " & $stat.dropped & " packets"
#  ring.close()
  quit(QuitSuccess)


proc packetListener(h: ptr pfring_pkthdr, p: ptr cstring, user_bytes: ptr cstring) =
  p.parsePacket(h, 4, 0, 0)
  let packet = addr h.extended_hdr.parsed_pkt

  if packet.l3_proto.int != IPPROTO_TCP:
    return

  var flags = packet.tcp.flags
  var syn =  (flags and TH_SYN) != 0
  var ack =  (flags and TH_ACK) != 0
  var fin = (flags and TH_FIN) != 0

  var s = "..."

  if syn:
    s[0] = 'S'
  if ack:
    s[1] = 'A'
  if fin:
    s[2] = 'F'
  echo s
  if packet.ip_version == 4:
    var src_addr, dst_addr: InAddr

    echo packet.ip_src.v4, ", ", packet.ip_dst.v4, ", ", packet.tcp.flags

    src_addr.s_addr = htonl(packet.ip_src.v4)
    dst_addr.s_addr = htonl(packet.ip_dst.v4)
    echo inet_ntoa(src_addr), " ", inet_ntoa(dst_addr)
    echo packet.l4_src_port, " ", packet.l4_dst_port
    #echo packet.l3_proto, " ", packet.ip_tos
  else:
    echo "IPv6"

proc main(config: Config) =
  var ring = newRing(config.interfaces, 65536, PF_RING_PROMISC or PF_RING_DO_NOT_PARSE)

  if ring.cptr.isNil:
    quit("pfring_open error: $#" % $errno, QuitFailure)

  setControlCHook(signalHandler)

  #ring.setDirection(ReceiveOnly)
  #ring.setSocketMode(ReadOnly)
  #ring.setBPFFilter(config.filter)
  ring.enable()
  ring.startLoop(packetListener, nil, true);

when isMainModule:
  var cfgFile: string
  parseCommandLine(cfgFile)
  let cfg = parseConfig(cfgFile)
  main(cfg)
