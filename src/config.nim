import os, parsecfg, streams, strutils
const
  defaultConfig* = "/etc/chonglu.conf"
  defaultPorts = @[80.uint16, 443.uint16]

type
  backend* = enum
    Memory,
    Redis,
    LMDB

  Config* = object
    iface*: string
    ports*: seq[uint16]
    rateLimit*: int
    resetOnAck*: bool
    backend*: backend
    redisHost*, redisPort*, redisDatabase*, redisPrefix*: string



proc initConfig(): Config =
  result.iface = "any"
  result.ports = @[]
  result.rateLimit = 10
  result.resetOnAck = false
  result.backend = Memory



proc parseConfig*(path: string): Config =
  if not fileExists(path):
    quit("Fatal error, config file: '$#' not found" % path, QuitFailure)

  result = initConfig()

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
        if e.key == "interface":
          result.iface = e.value
        elif e.key == "port":
          result.ports.add(parseInt(e.value).uint16)
        elif e.key == "rate_limit":
          result.rateLimit = parseInt(e.value)
        elif e.key == "reset_on_ack":
          result.resetOnAck = parseBool(e.value)
        elif e.key == "backend":
          if e.value.toLower == "memory":
            result.backend = Memory
          elif e.value.toLower == "redis":
            result.backend = Redis
          if e.value.toLower == "lmdb":
            result.backend = LMDB
        elif e.key == "redis_host":
          result.redisHost = e.value
        elif e.key == "redis_port":
          result.redisPort = e.value
        elif e.key == "redis_database":
          result.redisDatabase = e.value
        elif e.key == "redis_prefix":
          result.redisPrefix = e.value
        else:
          echo("Unknown config value: " & e.key & ": " & e.value)
      of cfgError:
        echo(e.msg)
      else: discard

  close(p)

  if result.ports.len == 0:
    result.ports = defaultPorts
