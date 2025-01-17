when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronos,
  stew/results,
  times
import
  ./constants

export
  chronos,
  times,
  results,
  constants

# This module contains the NonceManager interface
# The NonceManager is responsible for managing the messageId used to generate RLN proofs
# It should be used to fetch a new messageId every time a proof is generated
# It refreshes the messageId every `epoch` seconds

type
  Nonce* = uint64
  NonceManager* = ref object of RootObj
    epoch*: float64
    nextNonce*: Nonce
    lastNonceTime*: float64
    nonceLimit*: Nonce

  NonceManagerErrorKind* = enum
    NonceLimitReached

  NonceManagerError* = object
    kind*: NonceManagerErrorKind
    error*: string

  NonceManagerResult*[T] = Result[T, NonceManagerError]

proc `$`*(ne: NonceManagerError): string =
  case ne.kind
  of NonceLimitReached:
    return "NonceLimitReached: " & ne.error

proc init*(T: type NonceManager, nonceLimit: Nonce): T =
  return NonceManager(
    epoch: 0,
    nextNonce: 0,
    lastNonceTime: 0,
    nonceLimit: nonceLimit
  )


proc get*(n: NonceManager): NonceManagerResult[Nonce] =
  let now = getTime().toUnixFloat()
  var retNonce = n.nextNonce

  if now - n.lastNonceTime >= n.epoch: retNonce = 0
  n.nextNonce = retNonce + 1
  n.lastNonceTime = now

  if retNonce >= n.nonceLimit:
    return err(NonceManagerError(kind: NonceLimitReached, 
                                 error: "Nonce limit reached. Please wait for the next epoch"))
  
  return ok(retNonce)
