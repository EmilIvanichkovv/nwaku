## Types for waku_store protocol.

import
  bearssl,
  libp2p/[switch, peerinfo],
  libp2p/protocols/protocol,
  ../waku_swap/waku_swap_types,
  ../waku_message,
  ../../node/message_store/message_store,
  ../../utils/pagination

export waku_message
export pagination

# Constants required for pagination -------------------------------------------
const MaxPageSize* = 100 # Maximum number of waku messages in each page

type

  QueryHandlerFunc* = proc(response: HistoryResponse) {.gcsafe, closure.}

  IndexedWakuMessage* = object
    ## This type is used to encapsulate a WakuMessage and its Index
    msg*: WakuMessage
    index*: Index

  PagingDirection* {.pure.} = enum
    ## PagingDirection determines the direction of pagination
    BACKWARD = uint32(0)
    FORWARD = uint32(1)

  PagingInfo* = object
    ## This type holds the information needed for the pagination
    pageSize*: uint64
    cursor*: Index
    direction*: PagingDirection

  HistoryQuery* = object
    topics*: seq[ContentTopic]
    pagingInfo*: PagingInfo # used for pagination

  HistoryResponse* = object
    messages*: seq[WakuMessage]
    pagingInfo*: PagingInfo # used for pagination

  HistoryRPC* = object
    requestId*: string
    query*: HistoryQuery
    response*: HistoryResponse

  HistoryPeer* = object
    peerInfo*: PeerInfo

  WakuStore* = ref object of LPProtocol
    switch*: Switch
    rng*: ref BrHmacDrbgContext
    peers*: seq[HistoryPeer]
    messages*: seq[IndexedWakuMessage]
    store*: MessageStore
    wakuSwap*: WakuSwap