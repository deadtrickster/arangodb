// Fuzzes arangod's HTTP/2 framing: raw bytes into nghttp2, the library
// H2CommTask drives (3rdParty/nghttp2-lib). The session is configured the way a
// server is — nghttp2_session_server_new, the same callbacks H2CommTask installs
// (on_begin_headers, on_header, on_data_chunk_recv, on_frame_recv) — and the
// input is handed to nghttp2_session_mem_recv, which is exactly what the comm
// task does with bytes off the socket after the h2 preface.
//
// Nothing else in the tree reaches this path: the in-tree shell fuzzer speaks
// HTTP/1.1 and the Go harness never sends frames.
#include <cstdint>
#include <cstring>

#include <nghttp2/nghttp2.h>

#include "abi_self_test.h"

ARANGO_FUZZ_ABI_SELF_TEST()

namespace {

int on_begin_headers(nghttp2_session*, nghttp2_frame const*, void*) { return 0; }

int on_header(nghttp2_session*, nghttp2_frame const*, uint8_t const* name,
              size_t namelen, uint8_t const* value, size_t valuelen,
              uint8_t, void*) {
  // touch the buffers the way H2CommTask does when it copies them out
  return static_cast<int>(namelen + valuelen);
}

int on_data_chunk(nghttp2_session*, uint8_t, int32_t stream_id,
                  uint8_t const* data, size_t len, void*) { return 0; }

int on_frame_recv(nghttp2_session*, nghttp2_frame const* frame, void*) {
  // reading the frame header is what the comm task does before dispatching
  (void)frame->hd.type;
  (void)frame->hd.length;
  return 0;
}

ssize_t send_cb(nghttp2_session*, uint8_t const*, size_t length, int,
                void*) {
  return static_cast<ssize_t>(length);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size == 0 || size > (1u << 16)) {
    return 0;
  }

  nghttp2_session_callbacks* callbacks = nullptr;
  if (nghttp2_session_callbacks_new(&callbacks) != 0) {
    return 0;
  }
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          on_begin_headers);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                            on_data_chunk);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv);
  nghttp2_session_callbacks_set_send_callback(callbacks, send_cb);

  nghttp2_session* session = nullptr;
  int rv = nghttp2_session_server_new(&session, callbacks, nullptr);
  nghttp2_session_callbacks_del(callbacks);
  if (rv != 0 || session == nullptr) {
    return 0;
  }

  // the client preface is consumed by the comm task before frames arrive, but
  // feeding it here is harmless: nghttp2 ignores/misparses it like any input
  (void)nghttp2_session_mem_recv(session, data, size);
  (void)nghttp2_session_send(session);

  nghttp2_session_del(session);
  return 0;
}
