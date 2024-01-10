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

import ../../nimbus-node-manager/libs/waku-utils/waku_handshake_utils

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
    let contentTopicInfo = ContentTopicInfo(
      applicationName: "waku-noise-sessions",
      applicationVersion: "0.1",
      shardId: "10",)

    ################################
    # Alice static/ephemeral key initialization and commitment
    let aliceInfo = initAgentKeysAndCommitment(rng)
    let s = aliceInfo.commitment

    let qr = readFile("qr.txt")
    let qrMessageNameTag = cast[seq[byte]](readFile("qrMessageNametag.txt"))
    echo qrMessageNameTag

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
      if numConnectedPeers >= 6:
        notice "publisher is ready", connectedPeers=numConnectedPeers, required=6
        break
      notice "waiting to be ready", connectedPeers=numConnectedPeers, required=6
      await sleepAsync(5000)

    # Make sure it matches the publisher. Use default value
    # see spec: https://rfc.vac.dev/spec/23/
    let pubSubTopic = PubsubTopic("/waku/2/default-waku/proto")

    ###############################################
    # We prepare a Waku message from Alice's payload2
    echo "qrMessageNametag ", qrMessageNametag
    echo "aliceMessageNametag ", aliceMessageNametag

    wakuMsg = prepareHandShakeInitiatorMsg(rng, contentTopic, aliceInfo,
                                           qrMessageNameTag, aliceMessageNametag,
                                           aliceHS, aliceStep)
    echo "aliceMessageNametag ", aliceMessageNametag

    await publishHandShakeInitiatorMsg(node, pubSubTopic, contentTopic, wakuMsg.get())
    echo "aliceMessageNametag ", aliceMessageNametag

    # aliceMessageNametag = toMessageNametag(aliceHS)
    let step2Nametag = aliceMessageNametag
    echo "step2Nametag ", step2Nametag
    proc handler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
      # let payloadStr = string.fromBytes(msg.payload)
      if msg.contentTopic == contentTopic:
        readPayloadV2 = decodePayloadV2(msg).get()
        if readPayloadV2.messageNametag == step2Nametag:
          echo "aliceMessageNametag ", aliceMessageNametag

          handleHandShakeMsg(rng, pubSubTopic, contentTopic,step = 2, readPayloadV2,
                             aliceStep, aliceHS, aliceMessageNametag)
          echo "aliceMessageNametag ", aliceMessageNametag

          # await sleepAsync(5000)
          let handShakeMsgStep3 = prepareHandShakeMsg(rng, contentTopic, aliceInfo,
                                                    aliceMessageNametag, aliceHS,
                                                    aliceStep, step = 3)
          echo "aliceMessageNametag ", aliceMessageNametag

          await publishHandShakeMsg( node, pubSubTopic, contentTopic, handShakeMsgStep3.get(), 3)
          readyForFinalization = true
          echo "aliceMessageNametag ", aliceMessageNametag

    node.subscribe((kind: PubsubSub, topic: pubsubTopic), some(handler))

    while true:
      if readyForFinalization:
        notice "Finalizing handshake"
        aliceHSResult = finalizeHandshake(aliceHS)
        await sleepAsync(5000)
        break
      await sleepAsync(5000)

    var
      payload2: PayloadV2
      realMessage: seq[byte]
      readMessage: seq[byte]

    # Bob writes to Alice
    realMessage = @[(byte)42,42,42,42]
    let realMessageContentTopic = "/" & contentTopicInfo.applicationName & "/" & contentTopicInfo.applicationVersion & "/wakunoise/1/sessions_shard-" & contentTopicInfo.shardId & "/real" & "/proto"
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
