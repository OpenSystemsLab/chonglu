import posix
import strutils
import parseopt2
import redis
import pfring/core

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

proc callback(h: ptr pfring_pkthdr, p: ptr cstring, user_bytes: ptr cstring) =
  p.parsePacket(h, 4, 1, 1)
  var flags = h.extended_hdr.parsed_pkt.tcp.flags
  var syn =  (flags and TH_SYN) != 0
  var ack =  (flags and TH_ACK) != 0

  if syn and not ack:
    echo "SYN"
  elif syn and ack:
    echo "SYN-ACK"
  elif ack and not syn:
    echo "ACK"
  else:
    echo "UKN"

proc main(config: Config) =
  var ring = newRing(config.interfaces, 65536, PF_RING_PROMISC or PF_RING_DO_NOT_PARSE)
  if ring.cptr.isNil:
    quit("pfring_open error: $#" % $errno, QuitFailure)

  ring.setDirection(ReceiveOnly)
  ring.setSocketMode(ReadOnly)
  ring.setBPFFilter(config.filter)
  ring.enable()

  ring.setLooper(callback, nil, true);

  ring.close()

when isMainModule:
  var cfgFile: string
  parseCommandLine(cfgFile)
  let cfg = parseConfig(cfgFile)
  main(cfg)
