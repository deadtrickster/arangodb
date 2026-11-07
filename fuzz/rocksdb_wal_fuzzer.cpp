// Fuzzes RocksDB's WAL record decoder the way pg-fuzz's xlogreader does:
// build a physically valid log, mutate it, then RECOMPUTE the record CRC so
// the decoder parses the mutated bytes instead of discarding them at the
// checksum. The oracle is the Reader itself: a Reporter callback is expected
// behaviour, a crash is not.
//
// Format (db/log_format.h): header = CRC(4) + Size(2) + Type(1), then payload;
// the CRC covers exactly `header + 6 .. length + header_size - 1` (type byte +
// payload, plus the log number for recyclable records), stored masked.
//
// Input format: byte 0 selects the mutation, bytes 1.. are the payload of the
// first record; the harness builds a small valid multi-record log around it,
// applies the mutation, fixes the CRCs, and reads the whole log back.
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "db/log_format.h"
#include "db/log_reader.h"
#include "rocksdb/env.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/status.h"
#include "util/crc32c.h"
#include "file/sequence_file_reader.h"

#include "abi_self_test.h"

ARANGO_FUZZ_ABI_SELF_TEST()

using namespace ROCKSDB_NAMESPACE;

namespace {

class CountingReporter : public log::Reader::Reporter {
 public:
  void Corruption(size_t bytes, Status const& status) override {
    ++corruptions_;
    last_status_ = status.ToString();
  }
  size_t corruptions_ = 0;
  std::string last_status_;
};

// One physical record: 7-byte header + payload, CRC recomputed.
void PutRecord(std::string& out, uint8_t type, char const* payload, size_t n) {
  size_t const off = out.size();
  out.resize(off + 7 + n);
  char* p = out.data() + off;
  p[4] = static_cast<char>(n & 0xff);
  p[5] = static_cast<char>((n >> 8) & 0xff);
  p[6] = static_cast<char>(type);
  std::memcpy(p + 7, payload, n);
  uint32_t const crc = crc32c::Value(reinterpret_cast<char const*>(p) + 6, n + 1);
  EncodeFixed32(p, crc32c::Mask(crc));  // masked, exactly as the writer stores it
}

// Fix up the CRC of every record in a buffer whose headers we recognise.
// The mutation happens before this call, so any header/payload edit is
// "accepted" by the checksum and the decoder runs on the mutated bytes.
void RecomputeCrcs(std::string& buf) {
  size_t pos = 0;
  while (pos + 7 <= buf.size()) {
    char* p = buf.data() + pos;
    auto type = static_cast<uint8_t>(p[6]);
    uint32_t n = static_cast<uint8_t>(p[4]) | (static_cast<uint8_t>(p[5]) << 8);
    size_t const header = (type >= log::kRecyclableFullType &&
                           type <= log::kRecyclableUserDefinedTimestampSizeType)
                              ? log::kRecyclableHeaderSize
                              : log::kHeaderSize;
    if (pos + header + n > buf.size()) {
      break;  // truncated tail: leave it, the reader reports it
    }
    uint32_t const crc =
        crc32c::Value(reinterpret_cast<char const*>(p) + 6, n + header - 6);
    EncodeFixed32(p, crc32c::Mask(crc));
    pos += header + n;
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size < 2 || size > (1u << 15)) {
    return 0;
  }
  uint8_t const mutation = data[0];
  char const* payload = reinterpret_cast<char const*>(data) + 1;
  std::size_t const payloadLen = size - 1;

  // A valid small log: header record, the fuzzed record, a trailer record.
  std::string log;
  PutRecord(log, log::kFullType, "seed-header", 12);
  PutRecord(log, log::kFullType, payload, payloadLen);
  PutRecord(log, log::kFullType, "seed-trailer", 12);

  // Mutate: one byte inside the fuzzed record's payload, or its header, or a
  // splice — then make every CRC valid again so the decoder must parse it.
  // ALL five modes operate at `first` = 7+12 = 19, i.e. strictly AFTER the
  // 19-byte seed-header preamble: no mode removes or overwrites the first
  // record, so the property-(c) oracle below (first ReadRecord == seed-header)
  // needs no exemption list. A future sixth mode must either keep that
  // invariant or extend the oracle's exemption.
  {
    size_t const first = 7 + 12;  // start of the fuzzed record
    size_t const recLen = 7 + payloadLen;
    switch (mutation % 5) {
      case 0:  // flip a payload byte
        if (payloadLen > 0) {
          log[first + 7 + (mutation % payloadLen)] ^=
              static_cast<char>(1 << (mutation % 8));
        }
        break;
      case 1:  // flip the type byte
        log[first + 6] = static_cast<char>(mutation % 16);
        break;
      case 2:  // lie about the length
        if (recLen > 8) {
          log[first + 4] = static_cast<char>(mutation);
        }
        break;
      case 3:  // duplicate the record
        log.insert(first, log.substr(first, recLen));
        break;
      case 4:  // truncate inside the record
        if (recLen > 8) {
          log.resize(first + 7 + (mutation % payloadLen));
        }
        break;
      default:
        break;
    }
  }
  RecomputeCrcs(log);

  // Read it back through the real Reader, over a MemEnv FileSystem.
  std::shared_ptr<Env> env(NewMemEnv(Env::Default()));
  std::shared_ptr<FileSystem> const fs = env->GetFileSystem();
  std::string const fname = "/wal";
  {
    std::unique_ptr<FSWritableFile> wf;
    IOStatus s = fs->NewWritableFile(fname, FileOptions(), &wf, nullptr);
    if (!s.ok()) {
      return 0;
    }
    s = wf->Append(log, IOOptions(), nullptr);
    if (!s.ok()) {
      return 0;
    }
    wf->Close(IOOptions(), nullptr);
  }

  CountingReporter reporter;
  std::unique_ptr<SequentialFileReader> reader;
  if (!SequentialFileReader::Create(fs, fname, FileOptions(), &reader,
                                    nullptr /*dbg*/,
                                    nullptr /*rate limiter*/)
           .ok()) {
    return 0;
  }

  log::Reader logReader(nullptr, std::move(reader), &reporter,
                        true /*checksum*/, 0 /*log_number*/);

  std::string record;
  Slice slice;
  int recordIndex = 0;
  while (logReader.ReadRecord(&slice, &record)) {
    // Property (c) of the recyclable-spin regression class: every record
    // written BEFORE the damage must come back unchanged. The harness frames
    // the fuzzed record with a known-good first record ("seed-header"), so the
    // first thing the reader returns must be exactly that, whatever the
    // mutation did to the middle of the log. A fix that "simplifies" the
    // resync into swallowing the damage fails here, in-process, on the exact
    // input.
    if (recordIndex == 0) {
      if (slice.size() != 12 ||
          std::memcmp(slice.data(), "seed-header", 12) != 0) {
        std::fprintf(stderr,
                     "REGRESSION: first record came back wrong: %.12s (%zu B)\n",
                     slice.data(), slice.size());
        abort();
      }
    }
    ++recordIndex;
  }
  // Property (a): the read terminates (being here at all proves it - the
  // pre-fix spin never left the loop). Property (b): corruption reported, not
  // swallowed - a non-zero reporter count is EXPECTED for damaged logs; a
  // desync that reports nothing and returns nothing would lose data silently.
  return 0;
}
