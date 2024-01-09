import
  std/[tables,times,sequtils],
  stew/byteutils,
  stew/shims/net,
  chronicles,
  chronos,
  confutils,
  libp2p/crypto/crypto,
  eth/keys,
  eth/p2p/discoveryv5/enr,
  testutils/unittests


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


proc now*(): Timestamp =
  getNanosecondTime(getTime().toUnixFloat())

# An accesible bootstrap node. See wakuv2.prod fleets.status.im


const bootstrapNode = "enr:-Nm4QOdTOKZJKTUUZ4O_W932CXIET-M9NamewDnL78P5u9D" &
                      "OGnZlK0JFZ4k0inkfe6iY-0JAaJVovZXc575VV3njeiABgmlkgn" &
                      "Y0gmlwhAjS3ueKbXVsdGlhZGRyc7g6ADg2MW5vZGUtMDEuYWMtY" &
                      "24taG9uZ2tvbmctYy53YWt1djIucHJvZC5zdGF0dXNpbS5uZXQG" &
                      "H0DeA4lzZWNwMjU2azGhAo0C-VvfgHiXrxZi3umDiooXMGY9FvY" &
                      "j5_d1Q4EeS7eyg3RjcIJ2X4N1ZHCCIyiFd2FrdTIP"

# careful if running pub and sub in the same machine
const wakuPort = 60000
const discv5Port = 9000



proc setupAndPublish(rng: ref HmacDrbgContext) {.async.} =
    var readyForFinalization = false

    #########################
    # Content Topic information
    let applicationName = "waku-noise-sessions"
    let applicationVersion = "0.1"
    let shardId = "10"
    # let qrMessageNametag = randomSeqByte(rng[], MessageNametagLength)
    let qrMessageNametag = @[(byte)30, 130, 182, 16, 52, 172, 86, 100, 223, 18, 25, 91, 214, 155, 116, 115]

    let hsPattern = NoiseHandshakePatterns["WakuPairing"]


    # Bob static/ephemeral key initialization and commitment
    let aliceStaticKey = genKeyPair(rng[])
    let aliceEphemeralKey = genKeyPair(rng[])
    let s = randomSeqByte(rng[], 32)
    let aliceCommittedStaticKey = commitPublicKey(getPublicKey(aliceStaticKey), s)

    # let qr = toQr(applicationName, applicationVersion, shardId, getPublicKey(bobEphemeralKey), bobCommittedStaticKey)
    # let qr = "d2FrdS1ub2lzZS1zZXNzaW9ucw==:MC4x:MTA=:yCiNlUk6faX6956MHR1A8D_Yh7jJTCBnpD_ZuSUECxk=:3vZocwymHRMVG7vkz4ZvwS9XMWyF2-KVVANebcC4OKg="
    let qr = readFile("qr.txt")
    let (readApplicationName, readApplicationVersion, readShardId, readEphemeralKey, readCommittedStaticKey) = fromQr(qr)

    # We set the contentTopic from the content topic parameters exchanged in the QR
    let contentTopic: ContentTopic = "/" & applicationName & "/" & applicationVersion & "/wakunoise/1/sessions_shard-" & shardId & "/proto"

    let preMessagePKs: seq[NoisePublicKey] = @[toNoisePublicKey(readEphemeralKey)]
    echo "preMessagePKs", preMessagePKs
    var aliceHS = initialize(hsPattern = hsPattern, ephemeralKey = aliceEphemeralKey, staticKey = aliceStaticKey, prologue = qr.toBytes, preMessagePKs = preMessagePKs, initiator = true)

    var
      sentTransportMessage: seq[byte]
      aliceStep, bobStep: HandshakeStepResult
      msgFromPb: ProtobufResult[WakuMessage]
      wakuMsg: Result[WakuMessage, cstring]
      pb: ProtoBuffer
      readPayloadV2: PayloadV2
      aliceMessageNametag, bobMessageNametag: MessageNametag
      aliceHSResult, bobHSResult: HandshakeResult


    # We set the transport message to be H(sA||s)
    sentTransportMessage = digestToSeq(aliceCommittedStaticKey)


    # By being the handshake initiator, Alice writes a Waku2 payload v2 containing her handshake message
    # and the (encrypted) transport message
    # The message is sent with a messageNametag equal to the one received through the QR code
    aliceStep = stepHandshake(rng[], aliceHS, transportMessage = sentTransportMessage, messageNametag = qrMessageNametag).get()

    ###############################################
    # We prepare a Waku message from Alice's payload2
    wakuMsg = encodePayloadV2(aliceStep.payload2, contentTopic)


    # use notice to filter all waku messaging
    setupLogLevel(logging.LogLevel.NOTICE)
    notice "starting publisher", wakuPort=wakuPort, discv5Port=discv5Port
    let
        nodeKey = crypto.PrivateKey.random(Secp256k1, rng[]).get()
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
        notice "publisher is ready", connectedPeers=numConnectedPeers, required=6
        break
      notice "waiting to be ready", connectedPeers=numConnectedPeers, required=6
      await sleepAsync(5000)

    # Make sure it matches the publisher. Use default value
    # see spec: https://rfc.vac.dev/spec/23/
    let pubSubTopic = PubsubTopic("/waku/2/default-waku/proto")

    # any content topic can be chosen
    # let contentTopic = ContentTopic("/examples/1/pubsub-example/proto")

    notice "publisher service started"
    let text = "hi there i'm a publisher"
    let message = wakuMsg        # current timestamp
    await node.publish(some(pubSubTopic), message.get)
    notice "published step 1 message from alice", text = message.get.version , psTopic = pubSubTopic, contentTopic = contentTopic, alicePayload=aliceStep.payload2
    await sleepAsync(5000)
    let aliceAuthcode = genAuthcode(aliceHS)
    echo aliceAuthcode

    aliceMessageNametag = toMessageNametag(aliceHS)
    let currAliceMessageNametag = aliceMessageNametag

    proc handler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
      # let payloadStr = string.fromBytes(msg.payload)
      if msg.contentTopic == contentTopic:
        readPayloadV2 = decodePayloadV2(msg).get()
        if readPayloadV2.messageNametag == currAliceMessageNametag:

          notice "Step 2 message received", payload=readPayloadV2,
                                    pubsubTopic=pubsubTopic,
                                    contentTopic=msg.contentTopic,
                                    timestamp=msg.timestamp

          # While Alice reads and returns the (decrypted) transport message
          aliceStep = stepHandshake(rng[], aliceHS, readPayloadV2 = readPayloadV2, messageNametag = aliceMessageNametag).get()

          # STEP 3 BEGINS
          aliceMessageNametag = toMessageNametag(aliceHS)
          # We set as a transport message the commitment randomness s
          sentTransportMessage = s
          # Similarly as in first step, Alice writes a Waku2 payload containing the handshake message and the (encrypted) transport message
          aliceStep = stepHandshake(rng[], aliceHS, transportMessage = sentTransportMessage, messageNametag = aliceMessageNametag).get()

          await sleepAsync(5000)
          ###############################################
          # We prepare a Waku message from Bob's payload2
          let wakuMsgStep3 = encodePayloadV2(aliceStep.payload2, contentTopic)

          await node.publish(some(pubSubTopic), wakuMsgStep3.get)
          readyForFinalization = true
          notice "published step 3 message from alice", text = message.get.version , psTopic = pubSubTopic, contentTopic = contentTopic, alicePayload=aliceStep.payload2
          await sleepAsync(5000)

    node.subscribe((kind: PubsubSub, topic: pubsubTopic), some(handler))

    while true:
      if readyForFinalization:
        notice "Finalizing handshake"
        aliceHSResult = finalizeHandshake(aliceHS)
        break
      await sleepAsync(5000)

    var
      payload2: PayloadV2
      realMessage: seq[byte]
      readMessage: seq[byte]

    # Bob writes to Alice
    realMessage = @[(byte)42,42,42,42]
    let realMessageContentTopic = "/" & applicationName & "/" & applicationVersion & "/wakunoise/1/sessions_shard-" & shardId & "/real" & "/proto"
    payload2 = writeMessage(aliceHSResult, realMessage, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    echo aliceHSResult.h
    wakuMsg = encodePayloadV2(  payload2, realMessageContentTopic)
    await node.publish(some(pubSubTopic), wakuMsg.get)
    notice "Sending real message", payload=payload2,
                                  pubsubTopic=pubsubTopic,
                                  contentTopic=realMessageContentTopic


when isMainModule:
  let rng = crypto.newRng()
  asyncSpawn setupAndPublish(rng)
  runForever()
