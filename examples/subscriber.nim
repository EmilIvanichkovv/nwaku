import
  std/[tables, sequtils],
  stew/byteutils,
  stew/shims/net,
  chronicles,
  chronos,
  confutils,
  libp2p/crypto/crypto,
  eth/keys,
  eth/p2p/discoveryv5/enr

import
  ../../../waku/common/logging,
  ../../../waku/node/peer_manager,
  ../../../waku/waku_core,
  ../../../waku/waku_node,
  ../../../waku/waku_enr,
  ../../../waku/waku_discv5

# An accesible bootstrap node. See wakuv2.prod fleets.status.im
const bootstrapNode = "enr:-Nm4QOdTOKZJKTUUZ4O_W932CXIET-M9NamewDnL78P5u9DOGnZl" &
                      "K0JFZ4k0inkfe6iY-0JAaJVovZXc575VV3njeiABgmlkgnY0gmlwhAjS" &
                      "3ueKbXVsdGlhZGRyc7g6ADg2MW5vZGUtMDEuYWMtY24taG9uZ2tvbmct" &
                      "Yy53YWt1djIucHJvZC5zdGF0dXNpbS5uZXQGH0DeA4lzZWNwMjU2azGh" &
                      "Ao0C-VvfgHiXrxZi3umDiooXMGY9FvYj5_d1Q4EeS7eyg3RjcIJ2X4N1" &
                      "ZHCCIyiFd2FrdTIP"

# careful if running pub and sub in the same machine
const wakuPort = 50000
const discv5Port = 8000

proc setupAndSubscribe(rng: ref HmacDrbgContext) {.async.} =
    # use notice to filter all waku messaging
    setupLogLevel(logging.LogLevel.NOTICE)
    notice "starting subscriber", wakuPort=wakuPort, discv5Port=discv5Port
    let
        nodeKey = crypto.PrivateKey.random(Secp256k1, rng[])[]
        ip = parseIpAddress("0.0.0.0")
        flags = CapabilitiesBitfield.init(lightpush = false, filter = false, store = false, relay = true)

    var enrBuilder = EnrBuilder.init(nodeKey)

    let recordRes = enrBuilder.build()
    let record =
      if recordRes.isErr():
        error "failed to create enr record", error=recordRes.error
        quit(QuitFailure)
      else: recordRes.get()

    var builder = WakuNodeBuilder.init()
    builder.withNodeKey(nodeKey)
    builder.withRecord(record)
    import
  std/[tables, sequtils],
  stew/byteutils,
  stew/shims/net,
  chronicles,
  chronos,
  confutils,
  libp2p/crypto/crypto,
  eth/keys,
  eth/p2p/discoveryv5/enr

import
  ../../../waku/common/logging,
  ../../../waku/node/peer_manager,
  ../../../waku/waku_core,
  ../../../waku/waku_node,
  ../../../waku/waku_enr,
  ../../../waku/waku_discv5,
  ../../../waku/common/protobuf,
  ../../../waku/utils/noise as waku_message_utils,
  ../../../waku/waku_noise/noise_types,
  ../../../waku/waku_noise/noise_utils,
  ../../../waku/waku_noise/noise_handshake_processing,
  ../../../waku/waku_core

# An accesible bootstrap node. See wakuv2.prod fleets.status.im
const bootstrapNode = "enr:-Nm4QOdTOKZJKTUUZ4O_W932CXIET-M9NamewDnL78P5u9DOGnZl" &
                      "K0JFZ4k0inkfe6iY-0JAaJVovZXc575VV3njeiABgmlkgnY0gmlwhAjS" &
                      "3ueKbXVsdGlhZGRyc7g6ADg2MW5vZGUtMDEuYWMtY24taG9uZ2tvbmct" &
                      "Yy53YWt1djIucHJvZC5zdGF0dXNpbS5uZXQGH0DeA4lzZWNwMjU2azGh" &
                      "Ao0C-VvfgHiXrxZi3umDiooXMGY9FvYj5_d1Q4EeS7eyg3RjcIJ2X4N1" &
                      "ZHCCIyiFd2FrdTIP"

# careful if running pub and sub in the same machine
const wakuPort = 50000
const discv5Port = 8000


proc setupAndSubscribe(rng: ref HmacDrbgContext) {.async.} =
    var readyForFinalization = false
    ################################
    # Bob static/ephemeral key initialization and commitment
    let bobStaticKey = genKeyPair(rng[])
    let bobEphemeralKey = genKeyPair(rng[])
    let r = randomSeqByte(rng[], 32)
    let bobCommittedStaticKey = commitPublicKey(getPublicKey(bobStaticKey), r)

    #########################
    # Content Topic information
    let applicationName = "waku-noise-sessions"
    let applicationVersion = "0.1"
    let shardId = "10"
    # let qrMessageNametag = randomSeqByte(rng[], MessageNametagLength)
    let qrMessageNametag = @[(byte)30, 130, 182, 16, 52, 172, 86, 100, 223, 18, 25, 91, 214, 155, 116, 115]

    let hsPattern = NoiseHandshakePatterns["WakuPairing"]
    let qr = toQr(applicationName, applicationVersion, shardId, getPublicKey(bobEphemeralKey), bobCommittedStaticKey)
    writeFile("qr.txt", qr)
    # let qr = "d2FrdS1ub2lzZS1zZXNzaW9ucw==:MC4x:MTA=:yCiNlUk6faX6956MHR1A8D_Yh7jJTCBnpD_ZuSUECxk=:3vZocwymHRMVG7vkz4ZvwS9XMWyF2-KVVANebcC4OKg="

    # We set the contentTopic from the content topic parameters exchanged in the QR
    let contentTopic: ContentTopic = "/" & applicationName & "/" & applicationVersion & "/wakunoise/1/sessions_shard-" & shardId & "/proto"

    let preMessagePKs: seq[NoisePublicKey] = @[toNoisePublicKey(getPublicKey(bobEphemeralKey))]
    echo "preMessagePKs", preMessagePKs
    var bobHS = initialize(hsPattern = hsPattern, ephemeralKey = bobEphemeralKey, staticKey = bobStaticKey, prologue = qr.toBytes, preMessagePKs = preMessagePKs)

    var
      sentTransportMessage: seq[byte]
      aliceStep, bobStep: HandshakeStepResult
      msgFromPb: ProtobufResult[WakuMessage]
      wakuMsg: Result[WakuMessage, cstring]
      pb: ProtoBuffer
      readPayloadV2: PayloadV2
      aliceMessageNametag, bobMessageNametag: MessageNametag
      aliceHSResult, bobHSResult: HandshakeResult


    # use notice to filter all waku messaging
    setupLogLevel(logging.LogLevel.NOTICE)
    notice "starting subscriber", wakuPort=wakuPort, discv5Port=discv5Port
    let
        nodeKey = crypto.PrivateKey.random(Secp256k1, rng[])[]
        ip = parseIpAddress("0.0.0.0")
        flags = CapabilitiesBitfield.init(lightpush = false, filter = false, store = false, relay = true)

    var enrBuilder = EnrBuilder.init(nodeKey)

    let recordRes = enrBuilder.build()
    let record =
      if recordRes.isErr():
        error "failed to create enr record", error=recordRes.error
        quit(QuitFailure)
      else: recordRes.get()

    var builder = WakuNodeBuilder.init()
    builder.withNodeKey(nodeKey)
    builder.withRecord(record)
    builder.withNetworkConfigurationDetails(ip, Port(wakuPort)).tryGet()
    let node = builder.build().tryGet()

    var bootstrapNodeEnr: enr.Record
    discard bootstrapNodeEnr.fromURI(bootstrapNode)

    let discv5Conf = WakuDiscoveryV5Config(
      discv5Config: none(DiscoveryConfig),
      address: ip,
      port: Port(discv5Port),
      privateKey: keys.PrivateKey(nodeKey.skkey),
      bootstrapRecords: @[bootstrapNodeEnr],
      autoupdateRecord: true,
    )

    # assumes behind a firewall, so not care about being discoverable
    let wakuDiscv5 = WakuDiscoveryV5.new(
      node.rng,
      discv5Conf,
      some(node.enr),
      some(node.peerManager),
      node.topicSubscriptionQueue,
    )

    await node.start()
    await node.mountRelay()
    node.peerManager.start()

    (await wakuDiscv5.start()).isOkOr:
      error "failed to start discv5", error = error
      quit(1)

    # wait for a minimum of peers to be connected, otherwise messages wont be gossiped
    while true:
      let numConnectedPeers = node.peerManager.peerStore[ConnectionBook].book.values().countIt(it == Connected)
      if numConnectedPeers >= 6:
        notice "subscriber is ready", connectedPeers=numConnectedPeers, required=6
        break
      notice "waiting to be ready", connectedPeers=numConnectedPeers, required=6
      await sleepAsync(5000)

    # Make sure it matches the publisher. Use default value
    # see spec: https://rfc.vac.dev/spec/23/
    let pubSubTopic = PubsubTopic("/waku/2/default-waku/proto")

    # any content topic can be chosen. make sure it matches the publisher
    # let contentTopic = ContentTopic("/examples/1/pubsub-example/proto")

    proc handler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
      # let payloadStr = string.fromBytes(msg.payload)
      if msg.contentTopic == contentTopic:
        readPayloadV2 = decodePayloadV2(msg).get()
        if readPayloadV2.messageNametag == qrMessageNametag:
          notice "message received", payload=readPayloadV2,
                                    pubsubTopic=pubsubTopic,
                                    contentTopic=msg.contentTopic,
                                    timestamp=msg.timestamp

          bobStep = stepHandshake(rng[], bobHS, readPayloadV2 = readPayloadV2, messageNametag = qrMessageNametag).get()
          bobMessageNametag = toMessageNametag(bobHS)
          # We set as a transport message the commitment randomness r
          sentTransportMessage = r

          # At this step, Bob writes and returns a payload
          bobStep = stepHandshake(rng[], bobHS, transportMessage = sentTransportMessage, messageNametag = bobMessageNametag).get()

          ###############################################
          # We prepare a Waku message from Bob's payload2
          wakuMsg = encodePayloadV2(bobStep.payload2, contentTopic)

          await sleepAsync(5000)
          await node.publish(some(pubSubTopic), wakuMsg.get)
          notice "published step 2 message from bob", text = wakuMsg.get.version , psTopic = pubSubTopic, contentTopic = contentTopic, alicePayload=bobStep.payload2

        elif readPayloadV2.messageNametag != bobMessageNametag:
          bobMessageNametag = toMessageNametag(bobHS)
          notice "step 3 message received", payload=readPayloadV2,
                                    pubsubTopic=pubsubTopic,
                                    contentTopic=msg.contentTopic,
                                    timestamp=msg.timestamp
        # Bob reads Alice's payloads, and returns the (decrypted) transport message Alice sent to him
          bobStep = stepHandshake(rng[], bobHS, readPayloadV2 = readPayloadV2, messageNametag = bobMessageNametag).get()
          readyForFinalization = true

    node.subscribe((kind: PubsubSub, topic: pubsubTopic), some(handler))
    while true:
      if readyForFinalization:
        notice "Finalizing handshake"
        bobHSResult = finalizeHandshake(bobHS)

        proc realMessageHandler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
          let realMessageContentTopic = "/" & applicationName & "/" & applicationVersion & "/wakunoise/1/sessions_shard-" & shardId & "/real" & "/proto"

          if msg.contentTopic == realMessageContentTopic:
            readPayloadV2 = decodePayloadV2(msg).get()
            notice "Received real message", payload=readPayloadV2,
                              pubsubTopic=pubsubTopic,
                              contentTopic=msg.contentTopic,
                              timestamp=msg.timestamp
            let readMessage = readMessage(bobHSResult, readPayloadV2, inboundMessageNametagBuffer = bobHSResult.nametagsInbound).get()
            echo readMessage
            echo bobHSResult.h


        node.subscribe((kind: PubsubSub, topic: pubsubTopic), some(realMessageHandler))
        break
      await sleepAsync(5000)






when isMainModule:
  let rng = crypto.newRng()
  asyncSpawn setupAndSubscribe(rng)
  runForever()
.withNetworkConfigurationDetails(ip, Port(wakuPort)).tryGet()
    let node = builder.build().tryGet()

    var bootstrapNodeEnr: enr.Record
    discard bootstrapNodeEnr.fromURI(bootstrapNode)

    let discv5Conf = WakuDiscoveryV5Config(
      discv5Config: none(DiscoveryConfig),
      address: ip,
      port: Port(discv5Port),
      privateKey: keys.PrivateKey(nodeKey.skkey),
      bootstrapRecords: @[bootstrapNodeEnr],
      autoupdateRecord: true,
    )

    # assumes behind a firewall, so not care about being discoverable
    let wakuDiscv5 = WakuDiscoveryV5.new(
      node.rng,
      discv5Conf,
      some(node.enr),
      some(node.peerManager),
      node.topicSubscriptionQueue,
    )

    await node.start()
    await node.mountRelay()
    node.peerManager.start()

    (await wakuDiscv5.start()).isOkOr:
      error "failed to start discv5", error = error
      quit(1)

    # wait for a minimum of peers to be connected, otherwise messages wont be gossiped
    while true:
      let numConnectedPeers = node.peerManager.peerStore[ConnectionBook].book.values().countIt(it == Connected)
      if numConnectedPeers >= 6:
        notice "subscriber is ready", connectedPeers=numConnectedPeers, required=6
        break
      notice "waiting to be ready", connectedPeers=numConnectedPeers, required=6
      await sleepAsync(5000)

    # Make sure it matches the publisher. Use default value
    # see spec: https://rfc.vac.dev/spec/23/
    let pubSubTopic = PubsubTopic("/waku/2/default-waku/proto")

    # any content topic can be chosen. make sure it matches the publisher
    let contentTopic = ContentTopic("/examples/1/pubsub-example/proto")

    proc handler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
      let payloadStr = string.fromBytes(msg.payload)
      if msg.contentTopic == contentTopic:
        notice "message received", payload=payloadStr,
                                   pubsubTopic=pubsubTopic,
                                   contentTopic=msg.contentTopic,
                                   timestamp=msg.timestamp
    node.subscribe((kind: PubsubSub, topic: pubsubTopic), some(handler))

when isMainModule:
  let rng = crypto.newRng()
  asyncSpawn setupAndSubscribe(rng)
  runForever()
