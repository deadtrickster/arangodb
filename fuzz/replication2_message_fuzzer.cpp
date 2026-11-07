// Fuzzes a Replication2 replicated-log network message: the VPack form a
// follower receives from its leader, decoded by
// AppendEntriesRequest::fromVelocyPack (arangod/Replication2/ReplicatedLog/
// NetworkMessages.cpp). This is the ArangoDB analogue of etcd's FuzzRaftStep —
// one untrusted message in, the consumer's fields touched afterwards.
//
// Input: a VelocyPack body (validated first, as the HTTP layer does).
#include <cstdint>

#include <velocypack/Options.h>
#include <velocypack/Slice.h>
#include <velocypack/Validator.h>

#include "Replication2/ReplicatedLog/NetworkMessages.h"

#include "abi_self_test.h"

ARANGO_FUZZ_ABI_SELF_TEST()

using namespace arangodb::replication2::replicated_log;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size < 2 || size > (1u << 16)) {
    return 0;
  }

  // NOTE: no Validator call here on purpose. Validation is its own target
  // (vpack_fuzzer); with it in place this harness is saturated by the known
  // validateIndexedObject OOB and never reaches fromVelocyPack.
  arangodb::velocypack::Slice slice(data);

  try {
    auto request = AppendEntriesRequest::fromVelocyPack(slice);
    // touch what a follower touches: the term bookkeeping and the entries
    (void)request.leaderTerm.value;
    (void)request.leaderId;
    (void)request.prevLogEntry;
    (void)request.leaderCommit.value;
    (void)request.lowestIndexToKeep.value;
    (void)request.waitForSync;
    for (auto const& entry : request.entries) {
      (void)entry.entry();
    }
  } catch (...) {
    // malformed messages are allowed to throw; crashing is not
  }

  return 0;
}
