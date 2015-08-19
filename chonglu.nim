import strutils
import parseopt2
import redis

import pfring/types
import pfring/core


const
  version = "0.0.1"
  help = """
chonglu - SYN Flood Stopper

Usase:
  chonglu [options]

Options:
  -h --help                  show this help
  -v --version               show version
  --interfaces=<interfaces>  listen on interfaces [default: $#]
  --filter=<expression>      specify BPF filter rule [default: $#]
  --limit=<rate>             limit SYN requests per second [default: $#]
"""
  defaultInterfaces = "any"
  defaultFilter = "tcp and port 80"
  defaultRequestLimit = 10

type
  Options = object
    interfaces: string
    filter: string
    requestLimit: int


proc showVersion() =
  quit("chonglu version $# compiled at $# $#" % [version, CompileDate, CompileTime], QuitSuccess)

proc showHelp() =
  quit(help % [defaultInterfaces, defaultFilter, $defaultRequestLimit], QuitSuccess)

proc initOptions(): Options =
  result.interfaces = defaultInterfaces
  result.filter = defaultFilter
  result.requestLimit = defaultRequestLimit

proc parseCommandLine(options: var Options) =
  var opt = initOptParser()
  while true:
    opt.next()
    let key = opt.key.toLower()
    let val = opt.val
    case opt.kind:
    of cmdLongOption, cmdShortOption:
      case key:
      of "h", "help": showHelp()
      of "v", "version": showVersion()
      of "interfaces": options.interfaces = val
      of "filter": options.filter = val
      of "limit": options.requestLimit = parseInt(val)
      else: showHelp()
    of cmdArgument: discard
    of cmdEnd: break

proc main(options: Options) =
  var ring = newRing(options.interfaces, 65536, PF_RING_PROMISC or PF_RING_DO_NOT_PARSE)
  ring.close()

when isMainModule:
  var options = initOptions()
  parseCommandLine(options)
