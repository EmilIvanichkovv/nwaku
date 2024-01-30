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

# An accesible bootstrap node. See wakuv2.prod fleets.status.im
const bootstrapNode = "enr:-P-4QGVNANzbhCI49du6Moyw98AjuMhKoOpE_Jges9JlCq-ICAVadktjfcNpuhQgT0g1cu86_S3nbM7eYkCsqDAQG7UBgmlkgnY0gmlwhI_G-a6KbXVsdGlhZGRyc7hgAC02KG5vZGUtMDEuZG8tYW1zMy5zdGF0dXMucHJvZC5zdGF0dXNpbS5uZXQGdl8ALzYobm9kZS0wMS5kby1hbXMzLnN0YXR1cy5wcm9kLnN0YXR1c2ltLm5ldAYBu94DiXNlY3AyNTZrMaECoVyonsTGEQvVioM562Q1fjzTb_vKD152PPIdsV7sM6SDdGNwgnZfg3VkcIIjKIV3YWt1Mg8"
# careful if running pub and sub in the same machine
const wakuPort = 50000
const discv5Port = 8000


proc setupAndSubscribe(rng: ref HmacDrbgContext) {.async.} =
    var readyForFinalization = false

    ################################
    # Bob static/ephemeral key initialization and commitment
    let bobInfo = initAgentKeysAndCommitment(rng)
    let r = bobInfo.commitment

    #########################
    # Content Topic information
    let contentTopicInfo = ContentTopicInfo(
      applicationName: "waku-noise-sessions",
      applicationVersion: "0.1",
      shardId: "10",)

    let (qr, qrMessageNametag) = initQr(rng, contentTopicInfo, bobInfo)
    writeFile("qr.txt", qr)
    writeFile("qrMessageNametag.txt", qrMessageNametag)
    echo qrMessageNametag

    # We set the contentTopic from the content topic parameters exchanged in the QR
    let contentTopic = initContentTopicFromQr(qr)
    echo "contentTopic: ", contentTopic
    var bobHS = initHS(bobInfo, qr)


    var
      bobStep: HandshakeStepResult
      wakuMsg: Result[WakuMessage, cstring]
      readPayloadV2: PayloadV2
      bobMessageNametag: MessageNametag
      bobHSResult: HandshakeResult


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
    var step2Nameteag: MessageNametag
    echo "qrMessageNametag ", qrMessageNametag
    proc handler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
      # let payloadStr = string.fromBytes(msg.payload)
      if msg.contentTopic == contentTopic:
        readPayloadV2 = decodePayloadV2(msg).get()
        if readPayloadV2.messageNametag == qrMessageNametag:
          echo "bobMessageNametag ", bobMessageNametag
          handleHandShakeInitiatorMsg(rng, pubSubTopic, contentTopic, readPayloadV2,
                                      bobStep, bobHS, bobMessageNametag,
                                      qrMessageNametag)
          echo "bobMessageNametag ", bobMessageNametag
          step2Nameteag = bobMessageNametag
          wakuMsg = prepareHandShakeMsg(rng, contentTopic, bobInfo,
                                            bobMessageNametag, bobHS, bobStep,
                                            step = 2)
          echo "bobMessageNametag ", bobMessageNametag
          await publishHandShakeMsg(node, pubSubTopic, contentTopic,
                                    wakuMsg.get(), step = 2)

        elif readPayloadV2.messageNametag != step2Nameteag:
          # bobMessageNametag = toMessageNametag(bobHS)
          handleHandShakeMsg(rng, pubSubTopic, contentTopic, step = 3, readPayloadV2,
                             bobStep, bobHS, bobMessageNametag)
        #   notice "step 3 message received", payload=readPayloadV2,
        #                             pubsubTopic=pubsubTopic,
        #                             contentTopic=msg.contentTopic,
        #                             timestamp=msg.timestamp
        # # Bob reads Alice's payloads, and returns the (decrypted) transport message Alice sent to him
        #   bobStep = stepHandshake(rng[], bobHS, readPayloadV2 = readPayloadV2, messageNametag = bobMessageNametag).get()
          readyForFinalization = true

    node.subscribe((kind: PubsubSub, topic: pubsubTopic), some(handler))
    while true:
      if readyForFinalization:
        notice "Finalizing handshake"
        bobHSResult = finalizeHandshake(bobHS)

        proc realMessageHandler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
          let realMessageContentTopic = "/" & contentTopicInfo.applicationName & "/" & contentTopicInfo.applicationVersion & "/wakunoise/1/sessions_shard-" & contentTopicInfo.shardId & "/real" & "/proto"

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
