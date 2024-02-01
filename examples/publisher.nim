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
  testutils/unittests,
  nimcrypto/utils


import
  ../waku/common/logging,
  ../waku/node/peer_manager,
  ../waku/waku_core,
  ../waku/waku_node,
  ../waku/waku_enr,
  ../waku/waku_discv5,
  ../waku/common/protobuf,
  ../waku/utils/noise as waku_message_utils,
  ../waku/waku_noise/noise_types,
  ../waku/waku_noise/noise_utils,
  ../waku/waku_noise/noise_handshake_processing,
  ../waku/waku_core

import ../../status-node-manager/libs/waku-utils/waku_handshake_utils

proc now*(): Timestamp =
  getNanosecondTime(getTime().toUnixFloat())

# An accesible bootstrap node. See wakuv2.prod fleets.status.im


const bootstrapNode = "enr:-P-4QGVNANzbhCI49du6Moyw98AjuMhKoOpE_Jges9JlCq-ICAVadktjfcNpuhQgT0g1cu86_S3nbM7eYkCsqDAQG7UBgmlkgnY0gmlwhI_G-a6KbXVsdGlhZGRyc7hgAC02KG5vZGUtMDEuZG8tYW1zMy5zdGF0dXMucHJvZC5zdGF0dXNpbS5uZXQGdl8ALzYobm9kZS0wMS5kby1hbXMzLnN0YXR1cy5wcm9kLnN0YXR1c2ltLm5ldAYBu94DiXNlY3AyNTZrMaECoVyonsTGEQvVioM562Q1fjzTb_vKD152PPIdsV7sM6SDdGNwgnZfg3VkcIIjKIV3YWt1Mg8"

# careful if running pub and sub in the same machine
const wakuPort = 60000
const discv5Port = 9000



proc setupAndPublish(rng: ref HmacDrbgContext) {.async.} =
    var readyForFinalization = false

    #########################
    # Content Topic information
    let contentTopicInfo = ContentTopicInfo(
      applicationName: "waku-noise-sessions",
      applicationVersion: "0.1",
      shardId: "10",)

    ################################
    # Alice static/ephemeral key initialization and commitment
    let aliceInfo = initAgentKeysAndCommitment(rng)
    let s = aliceInfo.commitment

    let qr = readFile("qr.txt")
    let (_, _, _, readEphemeralKey, _) = fromQr(qr)
    let qrMessageNameTag = cast[seq[byte]](readFile("qrMessageNametag.txt"))
    # var qrMessageNameTag = fromHex(readFile("qrMessageNametag.txt"))

    # We set the contentTopic from the content topic parameters exchanged in the QR
    let contentTopic = initContentTopicFromQr(qr)

    var aliceHS = initHS(aliceInfo, qr, true)

    var
      sentTransportMessage: seq[byte]
      aliceStep: HandshakeStepResult
      wakuMsg: Result[WakuMessage, cstring]
      readPayloadV2: PayloadV2
      aliceMessageNametag: MessageNametag
      aliceHSResult: HandshakeResult


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
      if numConnectedPeers >= 2:
        notice "publisher is ready", connectedPeers=numConnectedPeers, required=6
        break
      notice "waiting to be ready", connectedPeers=numConnectedPeers, required=6
      await sleepAsync(5000)

    # Make sure it matches the publisher. Use default value
    # see spec: https://rfc.vac.dev/spec/23/
    let pubSubTopic = PubsubTopic("/waku/2/default-waku/proto")


    aliceHSResult = await initiatorHandshake(rng, node, pubSubTopic, contentTopic,qr, qrMessageNameTag, aliceInfo)

    var
      payload2: PayloadV2
      realMessage: seq[byte]
      readMessage: seq[byte]


    # # Scenario 1: Dump a lof of messages
    # var i = 150
    # while i > 0:
    #   # Bob writes to Alice
    #   realMessage = @[(byte)42,42,42,42]
    #   let realMessage2 = @[(byte)11,1,11,1]
    #   let realMessageContentTopic = "/" & contentTopicInfo.applicationName & "/" & contentTopicInfo.applicationVersion & "/wakunoise/1/sessions_shard-" & contentTopicInfo.shardId & "/real" & "/proto"

    #   payload2 = writeMessage(aliceHSResult, realMessage, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)

    #   wakuMsg = encodePayloadV2(  payload2, contentTopic)
    #   await node.publish(some(pubSubTopic), wakuMsg.get)
    #   notice "Sending real message", payload=payload2.messageNametag

    #   await sleepAsync(100)
    #   i = i - 1


    # Scenario 2: Fake lost messages
    let msgFirst = @[(byte)11,11,11,11]
    let payloadFirst = writeMessage(aliceHSResult, msgFirst, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    let wakuMsgFirst = encodePayloadV2(  payloadFirst, contentTopic)
    await node.publish(some(pubSubTopic), wakuMsgFirst.get)
    notice "Sending real message", realMessage=msgFirst, payload=payloadFirst


    let lostMsg1 = @[(byte)61,66,66,66]
    let payloadLost1 = writeMessage(aliceHSResult, lostMsg1, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    let wakuMsgLost1 = encodePayloadV2(  payloadLost1, contentTopic)

    let lostMsg2 = @[(byte)62,66,66,66]
    let payloadLost2 = writeMessage(aliceHSResult, lostMsg2, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    let wakuMsgLost2 = encodePayloadV2(  payloadLost2, contentTopic)

    let thirdMsg = @[(byte)11,1,11,1]
    let payload3 = writeMessage(aliceHSResult, thirdMsg, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    let wakuMsg3 = encodePayloadV2(  payload3, contentTopic)
    await node.publish(some(pubSubTopic), wakuMsg3.get)
    notice "Sending real message", realMessage=thirdMsg, payload=payload3


    let lostMsg3 = @[(byte)63,66,66,66]
    let payloadLost3 = writeMessage(aliceHSResult, lostMsg3, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    let wakuMsgLost3 = encodePayloadV2(  payloadLost3, contentTopic)

    await sleepAsync(10000)
    await node.publish(some(pubSubTopic), wakuMsgLost1.get)
    notice "Sending real message", realMessage=lostMsg1, payload=payloadLost1


    let thirdMsg1 = @[(byte)11,1,11,1]
    let payload31 = writeMessage(aliceHSResult, thirdMsg1, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)
    let wakuMsg31 = encodePayloadV2(  payload31, contentTopic)
    await node.publish(some(pubSubTopic), wakuMsg31.get)
    notice "Sending real message", realMessage=thirdMsg1, payload=payload31


    await sleepAsync(10000)
    await node.publish(some(pubSubTopic), wakuMsgLost2.get)
    notice "Sending real message", realMessage=lostMsg2, payload=payloadLost2

    await sleepAsync(1000)

    await node.publish(some(pubSubTopic), wakuMsgLost3.get)
    notice "Sending real message", realMessage=lostMsg3, payload=payloadLost3


     # Bob writes to Alice
    # realMessage = @[(byte)5,5,5,5]
    # let realMessageContentTopic = "/" & contentTopicInfo.applicationName & "/" & contentTopicInfo.applicationVersion & "/wakunoise/1/sessions_shard-" & contentTopicInfo.shardId & "/real" & "/proto"

    # payload2 = writeMessage(aliceHSResult, realMessage, outboundMessageNametagBuffer = aliceHSResult.nametagsOutbound)

    # wakuMsg = encodePayloadV2(  payload2, contentTopic)

    # await node.publish(some(pubSubTopic), wakuMsg.get)
    # notice "Sending real message", payload=payload2,
    #                                 wakuMsg=wakuMsg,
    #                               pubsubTopic=pubsubTopic,
    #                               contentTopic=contentTopic

when isMainModule:
  let rng = crypto.newRng()
  asyncSpawn setupAndPublish(rng)
  runForever()
