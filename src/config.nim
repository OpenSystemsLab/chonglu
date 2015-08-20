import os, parsecfg, streams, strutils
const
  defaultConfig* = "/etc/chonglu.conf"
  defaultInterfaces = "any"
  defaultFilter = "tcp and port 80"
  defaultRateLimit = 10

type
  Config* = object
    interfaces*: string
    filter*: string
    rateLimit*: int

proc initConfig(): Config =
  result.interfaces = defaultInterfaces
  result.filter = defaultFilter
  result.rateLimit = defaultRateLimit

proc parseConfig*(path: string): Config =
  if not fileExists(path):
    quit("Fatal error, config file: '$#' not found" % path, QuitFailure)

  result = initConfig()
  if fileExists(defaultConfig):
    var f = newFileStream(path, fmRead)
    if f.isNil:
      quit("Fatal error, can't open config file: '$#'" % path, QuitFailure)
      var p: CfgParser
      open(p, f, path)
      while true:
        var e = next(p)
        case e.kind:
          of cfgEof:
            break
          of cfgKeyValuePair:
            discard
          of cfgError:
            echo(e.msg)
          else: discard
      close(p)
