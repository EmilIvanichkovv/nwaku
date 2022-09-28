{.push raises: [Defect].}

import
  stew/results
import
  ../../../protocol/waku_store/message_store

type RetentionPolicyResult*[T] = Result[T, string]

type MessageRetentionPolicy* = ref object of RootObj


method execute*(p: MessageRetentionPolicy, store: MessageStore): RetentionPolicyResult[void] {.base.} = discard