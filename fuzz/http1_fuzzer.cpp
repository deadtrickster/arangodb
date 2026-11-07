// Fuzzes arangod's HTTP/1.1 framing: raw bytes into llhttp, the parser that
// HttpCommTask installs (3rdParty/llhttp). Mirrors the callbacks the task uses
// (on_message_begin/url/status/header_field/header_value/headers_complete/body/
// message_complete) so the code runs is the same parser in the same mode.
//
// Unlike the VelocyPack targets this one is standalone: llhttp is plain C with
// no dependency on the rest of the tree.
#include <cstdint>
#include <cstring>
#include <initializer_list>

#include <llhttp.h>

namespace {

struct Counter {
  int messages = 0;
  int urlBytes = 0;
  int headerFields = 0;
  int headerBytes = 0;
  int bodyBytes = 0;
};

int on_message_begin(llhttp_t*) { return 0; }

int on_url(llhttp_t*, char const* at, size_t len) { return 0; }

int on_status(llhttp_t*, char const* at, size_t len) { return 0; }

int on_header_field(llhttp_t*, char const* at, size_t len) { return 0; }

int on_header_value(llhttp_t*, char const* at, size_t len) { return 0; }

int on_headers_complete(llhttp_t* p) {
  // HttpCommTask rejects a request whose Content-Length it cannot honour; keep
  // the same touch of the parsed state so that path is exercised.
  (void)p->content_length;
  return 0;
}

int on_body(llhttp_t* p, char const* at, size_t len) {
  // touching the body length is what the comm task does before buffering
  (void)p->content_length;
  return 0;
}

int on_message_complete(llhttp_t* p) { return 0; }

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size == 0 || size > (1u << 16)) {
    return 0;
  }

  llhttp_t parser;
  llhttp_settings_t settings;
  llhttp_settings_init(&settings);
  settings.on_message_begin = on_message_begin;
  settings.on_url = on_url;
  settings.on_status = on_status;
  settings.on_header_field = on_header_field;
  settings.on_header_value = on_header_value;
  settings.on_headers_complete = on_headers_complete;
  settings.on_body = on_body;
  settings.on_message_complete = on_message_complete;

  // both directions the server can run the parser in: HTTP_REQUEST is what
  // arangod uses for inbound traffic, HTTP_RESPONSE matters for the client tools
  for (llhttp_type_t type : {HTTP_REQUEST, HTTP_RESPONSE}) {
    llhttp_init(&parser, type, &settings);
    llhttp_set_lenient_headers(&parser, 1);
    llhttp_errno_t err =
        llhttp_execute(&parser, reinterpret_cast<char const*>(data), size);
    if (err == HPE_PAUSED_UPGRADE || err == HPE_PAUSED) {
      llhttp_resume(&parser);
    }
    (void)llhttp_finish(&parser);
  }

  return 0;
}
