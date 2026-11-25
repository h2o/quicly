// An HTTP/0.9 (ALPN hq-interop) server built on Google QUICHE, for measuring QUICHE's BBRv3 with the ccbench kit. It
// serves `GET /N\r\n` with N bytes on the request stream, as quicly's http09-style `cli` server does, so that quicly's
// `cli` can be the client. Every connection uses BBRv3 with an initial window of --initial_cwnd packets of
// --max_packet_size bytes, the same window in bytes as quicly's (packets times the maximum UDP payload size); nothing the
// client sends changes them. Blackhole detection is disabled, as the traces have outages longer than its timeout (2 TLPs
// and 5 RTOs, at least about 6.5 seconds), which quicly's server and TCP outlast.
//
// Requires quiche.patch, applied by build-quiche.sh: Bbr3Sender::SetInitialCongestionWindowInBytes, and 1472-byte packets.
//
// usage: hq_server --certificate_file=CRT --key_file=KEY [--initial_cwnd=30] [--max_packet_size=1472] HOST PORT

#include <signal.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/congestion_control/bbr3_sender.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_dispatcher.h"
#include "quiche/quic/core/quic_generic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_default_proof_providers.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/web_transport.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, initial_cwnd, 30, "Initial congestion window, in packets of --max_packet_size.");
DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, max_packet_size, 1472,
                                "Largest UDP payload to send; at most kMaxOutgoingPacketSize.");

namespace quic {
namespace {

// the body is arbitrary bytes, sent in slices of this buffer, which outlives every connection
constexpr size_t kChunkSize = 16384;
const char kChunk[kChunkSize] = {};

// Serves one request stream: reads `GET /N\r\n`, then writes N bytes and the FIN as the stream accepts them.
class HqStreamVisitor : public webtransport::StreamVisitor {
 public:
  explicit HqStreamVisitor(webtransport::Stream* stream) : stream_(stream) {}

  void OnCanRead() override {
    std::string data;
    webtransport::Stream::ReadResult result = stream_->Read(&data);
    if (remaining_.has_value()) {
      return;  // the request has been read; anything after it is ignored
    }
    request_ += data;
    size_t eol = request_.find("\r\n");
    if (eol == std::string::npos) {
      if (result.fin || request_.size() > 1024) {
        stream_->ResetWithUserCode(0);
      }
      return;
    }
    uint64_t length;
    absl::string_view line = absl::string_view(request_).substr(0, eol);
    if (!absl::ConsumePrefix(&line, "GET /") || !absl::SimpleAtoi(line, &length)) {
      std::cerr << "unsupported request: " << request_.substr(0, eol) << std::endl;
      stream_->ResetWithUserCode(0);
      return;
    }
    remaining_ = length;
    OnCanWrite();
  }

  void OnCanWrite() override {
    while (remaining_.has_value() && !fin_sent_ && stream_->CanWrite()) {
      size_t length = *remaining_ < kChunkSize ? *remaining_ : kChunkSize;
      std::vector<quiche::QuicheMemSlice> slices;
      if (length != 0) {
        slices.emplace_back(kChunk, length, [](absl::string_view) {});
      }
      *remaining_ -= length;
      webtransport::StreamWriteOptions options;
      options.set_send_fin(*remaining_ == 0);
      absl::Status status = stream_->Writev(absl::MakeSpan(slices), options);
      if (!status.ok()) {
        std::cerr << "write failed: " << status << std::endl;
        stream_->ResetWithUserCode(0);
        return;
      }
      fin_sent_ = options.send_fin();
    }
  }

  void OnResetStreamReceived(webtransport::StreamErrorCode) override {}
  void OnStopSendingReceived(webtransport::StreamErrorCode) override {}
  void OnWriteSideInDataRecvdState() override {}

 private:
  webtransport::Stream* stream_;
  std::string request_;
  std::optional<uint64_t> remaining_;  // bytes of the response still to be written, once the request has been read
  bool fin_sent_ = false;
};

class HqSessionVisitor : public webtransport::SessionVisitor {
 public:
  explicit HqSessionVisitor(webtransport::Session& session) : session_(session) {}

  void OnIncomingBidirectionalStreamAvailable() override {
    while (webtransport::Stream* stream = session_.AcceptIncomingBidirectionalStream()) {
      stream->SetVisitor(std::make_unique<HqStreamVisitor>(stream));
      stream->visitor()->OnCanRead();
    }
  }

  // Logs the sender's settings once the handshake has completed, after the negotiated config has been applied.
  void OnSessionReady() override {
    // every session is a QuicGenericServerSession, created by HqDispatcher
    const QuicConnection* connection = static_cast<QuicGenericSessionBase&>(session_).connection();
    const SendAlgorithmInterface* cc = connection->sent_packet_manager().GetSendAlgorithm();
    std::cerr << "session ready: cc=" << CongestionControlTypeToString(cc->GetCongestionControlType())
              << " cwnd=" << cc->GetCongestionWindow() << " max_packet_length=" << connection->max_packet_length()
              << " pacing_rate=" << connection->sent_packet_manager().GetSendAlgorithm()->PacingRate(0) << std::endl;
  }
  void OnSessionClosed(webtransport::SessionErrorCode, const std::string&) override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(absl::string_view) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

 private:
  webtransport::Session& session_;
};

class HqDispatcher : public QuicDispatcher {
 public:
  HqDispatcher(const QuicConfig* config, const QuicCryptoServerConfig* crypto_config,
               QuicVersionManager* version_manager, std::unique_ptr<QuicConnectionHelperInterface> helper,
               std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
               std::unique_ptr<QuicAlarmFactory> alarm_factory, uint8_t expected_server_connection_id_length,
               ConnectionIdGeneratorInterface& generator, QuicByteCount initial_cwnd, QuicByteCount max_packet_size)
      : QuicDispatcher(config, crypto_config, version_manager, std::move(helper), std::move(session_helper),
                       std::move(alarm_factory), expected_server_connection_id_length, generator),
        initial_cwnd_(initial_cwnd),
        max_packet_size_(max_packet_size) {}

 protected:
  std::unique_ptr<QuicSession> CreateQuicSession(QuicConnectionId connection_id, const QuicSocketAddress& self_address,
                                                 const QuicSocketAddress& peer_address, absl::string_view /*alpn*/,
                                                 const ParsedQuicVersion& version,
                                                 const ParsedClientHello& /*parsed_chlo*/,
                                                 ConnectionIdGeneratorInterface& connection_id_generator) override {
    auto* connection = new QuicConnection(connection_id, self_address, peer_address, helper(), alarm_factory(),
                                          writer(), /*owns_writer=*/false, Perspective::IS_SERVER,
                                          ParsedQuicVersionVector{version}, connection_id_generator);
    // The connection options that select a congestion controller or an initial window are requested by the client;
    // quicly's client sends none, so these settings hold for the whole connection.
    connection->sent_packet_manager().SetSendAlgorithm(kBBRv3);
    auto* cc = static_cast<Bbr3Sender*>(connection->sent_packet_manager().GetSendAlgorithm());
    cc->SetInitialCongestionWindowInBytes(initial_cwnd_);
    connection->SetMaxPacketLength(max_packet_size_);
    std::cerr << "connection created: cc=" << CongestionControlTypeToString(cc->GetCongestionControlType())
              << " cwnd=" << cc->GetCongestionWindow() << " max_packet_length=" << connection->max_packet_length()
              << std::endl;
    auto session = std::make_unique<QuicGenericServerSession>(
        connection, /*owns_connection=*/true, this, config(), "hq-interop",
        [](webtransport::Session& session) { return std::make_unique<HqSessionVisitor>(session); },
        /*datagram_observer=*/nullptr, crypto_config(), compressed_certs_cache());
    session->Initialize();
    return session;
  }

 private:
  QuicByteCount initial_cwnd_;  // in bytes
  QuicByteCount max_packet_size_;
};

class HqServer : public QuicServer {
 public:
  HqServer(std::unique_ptr<ProofSource> proof_source, QuicSimpleServerBackend* backend, QuicByteCount initial_cwnd,
           QuicByteCount max_packet_size)
      : QuicServer(std::move(proof_source), /*proof_verifier=*/nullptr, backend, GetQuicVersionsForGenericSession()),
        initial_cwnd_(initial_cwnd),
        max_packet_size_(max_packet_size) {}

 protected:
  QuicDispatcher* CreateQuicDispatcher() override {
    return new HqDispatcher(&config(), &crypto_config(), version_manager(),
                            std::make_unique<QuicDefaultConnectionHelper>(),
                            std::make_unique<QuicSimpleCryptoServerStreamHelper>(), event_loop()->CreateAlarmFactory(),
                            expected_server_connection_id_length(), connection_id_generator(), initial_cwnd_,
                            max_packet_size_);
  }

 private:
  QuicByteCount initial_cwnd_;  // in bytes
  QuicByteCount max_packet_size_;
};

int Main(int argc, char** argv) {
  quiche::QuicheSystemEventLoop event_loop("hq_server");
  const char* usage = "Usage: hq_server [options] HOST PORT";
  std::vector<std::string> args = quiche::QuicheParseCommandLineFlags(usage, argc, argv);
  int32_t initial_cwnd = quiche::GetQuicheCommandLineFlag(FLAGS_initial_cwnd);
  int32_t max_packet_size = quiche::GetQuicheCommandLineFlag(FLAGS_max_packet_size);
  QuicIpAddress host;
  int port;
  if (args.size() != 2 || !host.FromString(args[0]) || !absl::SimpleAtoi(args[1], &port) || initial_cwnd <= 0 ||
      max_packet_size <= 0 || static_cast<QuicByteCount>(max_packet_size) > kMaxOutgoingPacketSize) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }
  // run-one.py sends SIGHUP to the server every 30 seconds to have quicly's server print statistics
  signal(SIGHUP, SIG_IGN);
  // without this, the server closes a connection when it sees no progress for 2 TLPs and 5 RTOs
  SetQuicReloadableFlag(quic_disable_server_blackhole_detection, true);

  QuicMemoryCacheBackend backend;  // unused; QuicServer requires a backend
  HqServer server(quiche::CreateDefaultProofSource(), &backend,
                  static_cast<QuicByteCount>(initial_cwnd) * static_cast<QuicByteCount>(max_packet_size), max_packet_size);
  if (!server.CreateUDPSocketAndListen(QuicSocketAddress(host, port))) {
    std::cerr << "failed to listen on " << args[0] << ":" << args[1] << std::endl;
    return 1;
  }
  server.HandleEventsForever();
  return 0;
}

}  // namespace
}  // namespace quic

int main(int argc, char** argv) { return quic::Main(argc, argv); }
