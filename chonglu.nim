import pfring/types
import pfring/core

const
  INTERFACES = "any"
  PORTS = [22, 80]
  REQUEST_LIMIT = 10

var ring = newRing(INTERFACES, 65536, PF_RING_PROMISC or PF_RING_DO_NOT_PARSE)
ring.close()
