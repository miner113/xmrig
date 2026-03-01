/* XMRig
 * Copyright (c) 2018-2025 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2025 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <uv.h>


#include "base/net/stratum/JunoRpcClient.h"
#include "3rdparty/rapidjson/document.h"
#include "3rdparty/rapidjson/error/en.h"
#include "base/io/json/Json.h"
#include "base/io/json/JsonRequest.h"
#include "base/io/log/Log.h"
#include "base/kernel/interfaces/IClientListener.h"
#include "base/kernel/Platform.h"
#include "base/net/dns/Dns.h"
#include "base/net/dns/DnsRecords.h"
#include "base/net/http/Fetch.h"
#include "base/net/http/HttpData.h"
#include "base/net/http/HttpListener.h"
#include "base/net/stratum/SubmitResult.h"
#include "base/net/tools/NetBuffer.h"
#include "base/tools/Cvt.h"
#include "base/tools/Timer.h"
#include "net/JobResult.h"


#include <algorithm>
#include <cassert>
#include <cstring>


namespace {

// Simple base64 encoder for HTTP Basic Auth
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::string &input) {
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < input.size()) {
        size_t remaining = input.size() - i;
        uint32_t octet_a = static_cast<unsigned char>(input[i++]);
        uint32_t octet_b = (remaining > 1) ? static_cast<unsigned char>(input[i++]) : 0;
        uint32_t octet_c = (remaining > 2) ? static_cast<unsigned char>(input[i++]) : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output += base64_chars[(triple >> 18) & 0x3F];
        output += base64_chars[(triple >> 12) & 0x3F];
        output += (remaining > 1) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        output += (remaining > 2) ? base64_chars[triple & 0x3F] : '=';
    }

    return output;
}

} // anonymous namespace


namespace xmrig {


Storage<JunoRpcClient> JunoRpcClient::m_storage;


static const char *kJsonRPC = "/";


// ZMQ protocol constants
static const char kZMQGreeting[64] = { static_cast<char>(-1), 0, 0, 0, 0, 0, 0, 0, 0, 127, 3, 0, 'N', 'U', 'L', 'L' };
static constexpr size_t kZMQGreetingSize1 = 11;

static const char kZMQHandshake[] = "\4\x19\5READY\xbSocket-Type\0\0\0\3SUB";
static const char kZMQSubscribe[] = "\0\x0dhashblock";  // Subscribe to hashblock notifications


xmrig::JunoRpcClient::JunoRpcClient(int id, IClientListener *listener) :
    BaseClient(id, listener)
{
    m_httpListener = std::make_shared<HttpListener>(this);
    m_timer        = new Timer(this);
    m_key          = m_storage.add(this);
}


xmrig::JunoRpcClient::~JunoRpcClient()
{
    delete m_timer;
    delete m_ZMQSocket;
}


void xmrig::JunoRpcClient::deleteLater()
{
    if (m_pool.zmq_port() >= 0) {
        ZMQClose(true);
    }
    else {
        delete this;
    }
}


bool xmrig::JunoRpcClient::disconnect()
{
    if (m_state != UnconnectedState) {
        setState(UnconnectedState);
    }

    return true;
}


bool xmrig::JunoRpcClient::isTLS() const
{
#   ifdef XMRIG_FEATURE_TLS
    return m_pool.isTLS();
#   else
    return false;
#   endif
}


int64_t xmrig::JunoRpcClient::submit(const JobResult &result)
{
    if (result.jobId != m_currentJobId) {
        return -1;
    }

    submitBlock(result);

    return m_sequence++;
}


void xmrig::JunoRpcClient::connect()
{
    auto connectError = [this](const char *message) {
        if (!isQuiet()) {
            LOG_ERR("%s " RED("connect error: ") RED_BOLD("\"%s\""), tag(), message);
        }

        retry();
    };

    setState(ConnectingState);

    if (!m_pool.algorithm().isValid()) {
        return connectError("Invalid algorithm.");
    }

    // For ZMQ support, resolve DNS first
    if (m_pool.zmq_port() >= 0) {
        m_dns = Dns::resolve(m_pool.host(), this);
    }
    else {
        getBlockTemplate();
    }
}


void xmrig::JunoRpcClient::connect(const Pool &pool)
{
    setPool(pool);
    connect();
}


void xmrig::JunoRpcClient::setPool(const Pool &pool)
{
    BaseClient::setPool(pool);

    // Set algorithm to rx/juno if not already set
    if (!m_pool.algorithm().isValid()) {
        m_pool.setAlgo(Algorithm::RX_JUNO);
    }

    m_pollInterval = std::max<uint64_t>(1000, m_pool.pollInterval());
}


void xmrig::JunoRpcClient::onHttpData(const HttpData &data)
{
    if (data.status != 200) {
        if (!isQuiet()) {
            LOG_ERR("%s " RED("HTTP error: %d"), tag(), data.status);
        }
        return retry();
    }

    m_ip = data.ip().c_str();

#   ifdef XMRIG_FEATURE_TLS
    m_tlsVersion     = data.tlsVersion();
    m_tlsFingerprint = data.tlsFingerprint();
#   endif

    rapidjson::Document doc;
    if (doc.Parse(data.body.c_str()).HasParseError()) {
        if (!isQuiet()) {
            LOG_ERR("%s " RED("JSON decode failed: ") RED_BOLD("\"%s\""), tag(), rapidjson::GetParseError_En(doc.GetParseError()));
        }

        return retry();
    }

    // Check for error
    if (doc.HasMember("error") && !doc["error"].IsNull()) {
        const auto &error = doc["error"];
        if (error.IsObject() && error.HasMember("message")) {
            const char *message = error["message"].GetString();
            if (!isQuiet()) {
                LOG_ERR("%s " RED("RPC error: ") RED_BOLD("\"%s\""), tag(), message);
            }
        }
        return retry();
    }

    // Parse result
    if (!doc.HasMember("result")) {
        return retry();
    }

    const auto &result = doc["result"];

    // Check if this is a submitblock response (result is null or string)
    if (result.IsNull() || result.IsString()) {
        // Block submitted
        const char *status = result.IsString() ? result.GetString() : "accepted";

        // Check for success responses
        bool success = result.IsNull() ||
                       strcmp(status, "duplicate") == 0 ||
                       strcmp(status, "inconclusive") == 0 ||
                       strcmp(status, "duplicate-inconclusive") == 0;

        if (success) {
            if (!isQuiet()) {
                LOG_NOTICE("%s " GREEN_BOLD("BLOCK ACCEPTED") " (%s)", tag(), result.IsNull() ? "accepted" : status);
            }
            handleSubmitResponse(m_sequence - 1, nullptr);
        }
        else {
            if (!isQuiet()) {
                LOG_ERR("%s " RED("BLOCK REJECTED: ") RED_BOLD("\"%s\""), tag(), status);
            }
            handleSubmitResponse(m_sequence - 1, status);
        }

        // Get new block template after submission
        getBlockTemplate();
        return;
    }

    // Parse block template
    if (result.IsObject() && result.HasMember("height")) {
        if (!parseBlockTemplate(result)) {
            return retry();
        }
    }
}


void xmrig::JunoRpcClient::onTimer(const Timer *)
{
    if (m_state == ConnectingState) {
        connect();
    }
    else if (m_state == ConnectedState) {
        // Poll for new block template
        getBlockTemplate();
    }
}


void xmrig::JunoRpcClient::onResolved(const DnsRecords &records, int status, const char* error)
{
    m_dns.reset();

    if (status < 0 && records.isEmpty()) {
        if (!isQuiet()) {
            LOG_ERR("%s " RED("DNS error: ") RED_BOLD("\"%s\""), tag(), error);
        }

        retry();
        return;
    }

    const auto &record = records.get();
    m_ip = record.ip();

    auto req = new uv_connect_t;
    req->data = m_storage.ptr(m_key);

    uv_tcp_t* s = new uv_tcp_t;
    s->data = m_storage.ptr(m_key);

    uv_tcp_init(uv_default_loop(), s);
    uv_tcp_nodelay(s, 1);

    if (Platform::hasKeepalive()) {
        uv_tcp_keepalive(s, 1, 60);
    }

    if (m_pool.zmq_port() > 0) {
        delete m_ZMQSocket;
        m_ZMQSocket = s;
        uv_tcp_connect(req, s, record.addr(m_pool.zmq_port()), onZMQConnect);
    }
}


void xmrig::JunoRpcClient::getBlockTemplate()
{
    using namespace rapidjson;
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    // Build JSON-RPC 1.0 request (Bitcoin/Zcash style)
    doc.AddMember("jsonrpc", "1.0", allocator);
    doc.AddMember("id", m_sequence, allocator);
    doc.AddMember("method", "getblocktemplate", allocator);

    // Params is an array containing request object with capabilities
    Value params(kArrayType);
    Value requestObj(kObjectType);

    Value capabilities(kArrayType);
    capabilities.PushBack("coinbasetxn", allocator);
    capabilities.PushBack("workid", allocator);
    capabilities.PushBack("coinbase/append", allocator);
    requestObj.AddMember("capabilities", capabilities, allocator);

    params.PushBack(requestObj, allocator);
    doc.AddMember("params", params, allocator);

    rpcSend(doc);
}


void xmrig::JunoRpcClient::submitBlock(const JobResult &result)
{
    using namespace rapidjson;

    // Serialize the complete block
    std::vector<uint8_t> block;

    // Header (140 bytes)
    // Version (4 bytes LE)
    block.push_back(m_blockVersion & 0xFF);
    block.push_back((m_blockVersion >> 8) & 0xFF);
    block.push_back((m_blockVersion >> 16) & 0xFF);
    block.push_back((m_blockVersion >> 24) & 0xFF);

    // Previous hash (32 bytes)
    block.insert(block.end(), m_headerPrevHash, m_headerPrevHash + 32);

    // Merkle root (32 bytes)
    block.insert(block.end(), m_headerMerkleRoot, m_headerMerkleRoot + 32);

    // Block commitments (32 bytes)
    block.insert(block.end(), m_headerBlockCommitments, m_headerBlockCommitments + 32);

    // Time (4 bytes LE)
    block.push_back(m_headerTime & 0xFF);
    block.push_back((m_headerTime >> 8) & 0xFF);
    block.push_back((m_headerTime >> 16) & 0xFF);
    block.push_back((m_headerTime >> 24) & 0xFF);

    // Bits (4 bytes LE)
    block.push_back(m_headerBits & 0xFF);
    block.push_back((m_headerBits >> 8) & 0xFF);
    block.push_back((m_headerBits >> 16) & 0xFF);
    block.push_back((m_headerBits >> 24) & 0xFF);

    // Nonce (32 bytes) - from the job result
    const uint8_t *nonce = result.soloNonce();
    block.insert(block.end(), nonce, nonce + 32);

    // Solution (varint length + 32 bytes hash)
    // For RandomX, solution is 32 bytes (the hash)
    block.push_back(32);  // CompactSize varint for 32
    block.insert(block.end(), result.result(), result.result() + 32);

    // Transaction count (CompactSize varint)
    size_t txCount = 1 + m_transactionsHex.size();
    if (txCount < 253) {
        block.push_back(static_cast<uint8_t>(txCount));
    }
    else {
        block.push_back(253);
        block.push_back(txCount & 0xFF);
        block.push_back((txCount >> 8) & 0xFF);
    }

    // Coinbase transaction
    Buffer coinbaseBin;
    Cvt::fromHex(coinbaseBin, m_coinbaseTxnHex.c_str(), m_coinbaseTxnHex.size());
    block.insert(block.end(), coinbaseBin.data(), coinbaseBin.data() + coinbaseBin.size());

    // Other transactions
    for (const auto &txHex : m_transactionsHex) {
        Buffer txBin;
        Cvt::fromHex(txBin, txHex.c_str(), txHex.size());
        block.insert(block.end(), txBin.data(), txBin.data() + txBin.size());
    }

    // Convert to hex string
    String blockHex = Cvt::toHex(block.data(), block.size());

    // Build JSON-RPC 1.0 request
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    doc.AddMember("jsonrpc", "1.0", allocator);
    doc.AddMember("id", m_sequence, allocator);
    doc.AddMember("method", "submitblock", allocator);

    Value params(kArrayType);
    params.PushBack(blockHex.toJSON(), allocator);
    doc.AddMember("params", params, allocator);

    m_results[m_sequence] = SubmitResult(m_sequence, result.diff, result.actualDiff(), 0, result.backend);

    rpcSend(doc);
}


int64_t xmrig::JunoRpcClient::rpcSend(const rapidjson::Document &doc)
{
    FetchRequest req(HTTP_POST, m_pool.host(), m_pool.port(), kJsonRPC, doc, m_pool.isTLS(), isQuiet());

    // Add basic auth if username/password provided
    if (!m_pool.user().isEmpty() && !m_pool.password().isEmpty()) {
        std::string auth = m_pool.user().data();
        auth += ":";
        auth += m_pool.password().data();
        std::string authHeader = "Basic " + base64Encode(auth);
        req.headers.insert({ "Authorization", authHeader });
    }

    fetch(tag(), std::move(req), m_httpListener);

    return m_sequence++;
}


bool xmrig::JunoRpcClient::parseBlockTemplate(const rapidjson::Value &result)
{
    const uint64_t height = Json::getUint64(result, "height");
    const String prevHash = Json::getString(result, "previousblockhash");

    // Check if this is a new block
    if (!isOutdated(height, prevHash.data())) {
        return true;  // Same block, no update needed
    }

    // Parse header fields
    m_blockVersion = static_cast<uint32_t>(Json::getUint64(result, "version", 4));

    // Parse and reverse previousblockhash (display order -> internal order)
    String prevHashHex = Json::getString(result, "previousblockhash");
    if (prevHashHex.size() == 64) {
        Buffer temp;
        Cvt::fromHex(temp, prevHashHex.data(), 64);
        // Reverse bytes for internal order
        for (int i = 0; i < 32; ++i) {
            m_headerPrevHash[i] = temp.data()[31 - i];
        }
    }

    // Parse defaultroots for merkle root and commitments
    if (result.HasMember("defaultroots") && result["defaultroots"].IsObject()) {
        const auto &roots = result["defaultroots"];

        // Merkle root (needs reversal)
        String merkleHex = Json::getString(roots, "merkleroot");
        if (merkleHex.size() == 64) {
            Buffer temp;
            Cvt::fromHex(temp, merkleHex.data(), 64);
            for (int i = 0; i < 32; ++i) {
                m_headerMerkleRoot[i] = temp.data()[31 - i];
            }
        }

        // Block commitments (needs reversal)
        String commitmentsHex = Json::getString(roots, "blockcommitmentshash");
        if (commitmentsHex.size() == 64) {
            Buffer temp;
            Cvt::fromHex(temp, commitmentsHex.data(), 64);
            for (int i = 0; i < 32; ++i) {
                m_headerBlockCommitments[i] = temp.data()[31 - i];
            }
        }
    }

    // Time and bits
    m_headerTime = static_cast<uint32_t>(Json::getUint64(result, "curtime"));
    String bitsHex = Json::getString(result, "bits");
    if (bitsHex.size() == 8) {
        m_headerBits = static_cast<uint32_t>(strtoul(bitsHex.data(), nullptr, 16));
    }

    // Parse transactions
    m_transactionsHex.clear();
    if (result.HasMember("transactions") && result["transactions"].IsArray()) {
        for (const auto &tx : result["transactions"].GetArray()) {
            if (tx.IsObject() && tx.HasMember("data")) {
                m_transactionsHex.push_back(Json::getString(tx, "data"));
            }
        }
    }

    // Coinbase transaction
    if (result.HasMember("coinbasetxn") && result["coinbasetxn"].IsObject()) {
        m_coinbaseTxnHex = Json::getString(result["coinbasetxn"], "data");
    }

    // Parse RandomX seed hash
    // Use the randomxseedhash field from getblocktemplate - this is the seed for the current epoch
    // This is NOT the same as previousblockhash!
    String seedHashHex = Json::getString(result, "randomxseedhash");
    Buffer newSeedHash;
    if (seedHashHex.size() == 64) {
        Cvt::fromHex(newSeedHash, seedHashHex.data(), 64);
    }

    // Create job
    Job job(false, Algorithm::RX_JUNO, String());

    // Build the 140-byte block header for hashing
    uint8_t header[140];
    size_t offset = 0;

    // Version (4 bytes LE)
    header[offset++] = m_blockVersion & 0xFF;
    header[offset++] = (m_blockVersion >> 8) & 0xFF;
    header[offset++] = (m_blockVersion >> 16) & 0xFF;
    header[offset++] = (m_blockVersion >> 24) & 0xFF;

    // Previous hash (32 bytes)
    memcpy(header + offset, m_headerPrevHash, 32);
    offset += 32;

    // Merkle root (32 bytes)
    memcpy(header + offset, m_headerMerkleRoot, 32);
    offset += 32;

    // Block commitments (32 bytes)
    memcpy(header + offset, m_headerBlockCommitments, 32);
    offset += 32;

    // Time (4 bytes LE)
    header[offset++] = m_headerTime & 0xFF;
    header[offset++] = (m_headerTime >> 8) & 0xFF;
    header[offset++] = (m_headerTime >> 16) & 0xFF;
    header[offset++] = (m_headerTime >> 24) & 0xFF;

    // Bits (4 bytes LE)
    header[offset++] = m_headerBits & 0xFF;
    header[offset++] = (m_headerBits >> 8) & 0xFF;
    header[offset++] = (m_headerBits >> 16) & 0xFF;
    header[offset++] = (m_headerBits >> 24) & 0xFF;

    // Nonce placeholder (32 bytes) - will be filled by workers
    memset(header + offset, 0, 32);

    // Set job blob directly from the 108-byte header we just built
    // This avoids hex conversion/parsing issues in setZcashJob
    job.setJunoHeader(header);

    // Set seed hash and height
    job.setSeedHash(seedHashHex.data());
    job.setHeight(height);

    // Compute 64-bit target from compact "bits" field
    // The bits field is in Bitcoin/Zcash compact format: top byte is exponent, lower 3 bytes are mantissa
    // Full 256-bit target = mantissa * 2^(8*(exponent-3))
    //
    // xmrig compares: (uint64_t)hash[24..31] < target64
    // So we need to extract the 64-bit value at bytes 24-31 of the 256-bit target
    //
    // The 256-bit target has the mantissa's low byte at position (exponent-3)
    // For bits = 0x1f07ffff: exponent=31, mantissa=0x07ffff, pos=28
    // Target bytes 28,29,30 = 0xff,0xff,0x07 (little-endian)
    // Bytes 24-31 as uint64_t LE = 0x0007ffff00000000
    {
        uint32_t compact = m_headerBits;
        int exponent = (compact >> 24) & 0xff;
        uint32_t mantissa = compact & 0x007fffff;
        int mantissaPos = exponent - 3;  // Byte position of mantissa's low byte

        uint64_t target64 = 0;

        if (mantissaPos >= 32) {
            // Mantissa is beyond byte 31 - target is huge, any hash passes
            target64 = 0xFFFFFFFFFFFFFFFFULL;
        } else if (mantissaPos >= 24) {
            // Mantissa overlaps with bytes 24-31 (the 64-bit comparison region)
            // Calculate which bits of mantissa appear in bytes 24-31
            int shift = (mantissaPos - 24) * 8;
            target64 = (uint64_t)mantissa << shift;

            // If mantissa extends beyond byte 31, we can't represent it in 64 bits
            // In that case, set max target
            if (mantissaPos > 29) {
                target64 = 0xFFFFFFFFFFFFFFFFULL;
            }
        } else {
            // Mantissa is entirely below byte 24
            // The target's bytes 24-31 are all zeros
            // Any hash with non-zero bytes 24-31 would exceed this target
            // Set target64 = 0, but we need at least 1 to avoid division issues
            target64 = 0;
        }

        // Set target directly to avoid precision loss from diff round-trip
        job.setTarget64(target64);

    }

    // Mark as solo mining
    job.setSoloMining(true);

    // Generate job ID
    m_currentJobId = Cvt::toHex(Cvt::randomBytes(4));
    job.setId(m_currentJobId);

    m_job = std::move(job);
    m_prevHash = prevHash;
    m_blocktemplateHeight = height;
    m_currentSeedHash = std::move(newSeedHash);
    m_jobSteadyMs = Chrono::steadyMSecs();

    if (m_state == ConnectingState) {
        setState(ConnectedState);
    }

    m_listener->onJobReceived(this, m_job, result);
    return true;
}


bool xmrig::JunoRpcClient::isOutdated(uint64_t height, const char *hash) const
{
    return m_job.height() != height ||
           m_prevHash != hash ||
           Chrono::steadyMSecs() >= m_jobSteadyMs + m_pool.jobTimeout();
}


void xmrig::JunoRpcClient::retry()
{
    m_failures++;
    m_listener->onClose(this, static_cast<int>(m_failures));

    if (m_failures == -1) {
        return;
    }

    if (m_state == ConnectedState) {
        setState(ConnectingState);
    }

    if ((m_ZMQConnectionState != ZMQ_NOT_CONNECTED) && (m_ZMQConnectionState != ZMQ_DISCONNECTING)) {
        if (Platform::hasKeepalive()) {
            uv_tcp_keepalive(m_ZMQSocket, 0, 60);
        }
        uv_close(reinterpret_cast<uv_handle_t*>(m_ZMQSocket), onZMQClose);
    }

    m_timer->stop();
    m_timer->start(m_retryPause, 0);
}


void xmrig::JunoRpcClient::setState(SocketState state)
{
    if (m_state == state) {
        return;
    }

    m_state = state;

    switch (state) {
    case ConnectedState:
        {
            m_failures = 0;
            m_listener->onLoginSuccess(this);

            // Start poll timer
            const uint64_t interval = std::max<uint64_t>(1000, m_pollInterval);
            m_timer->start(interval, interval);
        }
        break;

    case UnconnectedState:
        m_failures = -1;
        m_timer->stop();
        break;

    default:
        break;
    }
}


// ZMQ support methods
void xmrig::JunoRpcClient::onZMQConnect(uv_connect_t* req, int status)
{
    JunoRpcClient* client = getClient(req->data);
    delete req;

    if (!client) {
        return;
    }

    if (status < 0) {
        LOG_ERR("%s " RED("ZMQ connect error: ") RED_BOLD("\"%s\""), client->tag(), uv_strerror(status));
        client->retry();
        return;
    }

    client->ZMQConnected();
}


void xmrig::JunoRpcClient::onZMQRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    JunoRpcClient* client = getClient(stream->data);
    if (client) {
        client->ZMQRead(nread, buf);
    }

    NetBuffer::release(buf);
}


void xmrig::JunoRpcClient::onZMQClose(uv_handle_t* handle)
{
    JunoRpcClient* client = getClient(handle->data);
    if (client) {
        client->m_ZMQConnectionState = ZMQ_NOT_CONNECTED;
    }
}


void xmrig::JunoRpcClient::onZMQShutdown(uv_handle_t* handle)
{
    JunoRpcClient* client = getClient(handle->data);
    if (client) {
        client->m_ZMQConnectionState = ZMQ_NOT_CONNECTED;
        m_storage.remove(client->m_key);
    }
}


void xmrig::JunoRpcClient::ZMQConnect()
{
    if (m_pool.zmq_port() <= 0) {
        return;
    }

    m_dns = Dns::resolve(m_pool.host(), this);
}


void xmrig::JunoRpcClient::ZMQConnected()
{
#   ifdef APP_DEBUG
    LOG_DEBUG(CYAN("tcp-zmq://%s:%u") BLACK_BOLD(" connected"), m_pool.host().data(), m_pool.zmq_port());
#   endif

    m_ZMQConnectionState = ZMQ_GREETING_1;
    m_ZMQSendBuf.reserve(256);
    m_ZMQRecvBuf.reserve(256);

    if (ZMQWrite(kZMQGreeting, kZMQGreetingSize1)) {
        uv_read_start(reinterpret_cast<uv_stream_t*>(m_ZMQSocket), NetBuffer::onAlloc, onZMQRead);
    }

    // Also get initial block template
    getBlockTemplate();
}


bool xmrig::JunoRpcClient::ZMQWrite(const char* data, size_t size)
{
    m_ZMQSendBuf.assign(data, data + size);

    uv_buf_t buf;
    buf.base = m_ZMQSendBuf.data();
    buf.len = static_cast<uint32_t>(m_ZMQSendBuf.size());

    const int rc = uv_try_write(reinterpret_cast<uv_stream_t*>(m_ZMQSocket), &buf, 1);

    if (static_cast<size_t>(rc) == buf.len) {
        return true;
    }

    LOG_ERR("%s " RED("ZMQ write failed, rc = %d"), tag(), rc);
    ZMQClose();
    return false;
}


void xmrig::JunoRpcClient::ZMQRead(ssize_t nread, const uv_buf_t* buf)
{
    if (nread <= 0) {
        LOG_ERR("%s " RED("ZMQ read failed, nread = %" PRId64), tag(), nread);
        ZMQClose();
        return;
    }

    m_ZMQRecvBuf.insert(m_ZMQRecvBuf.end(), buf->base, buf->base + nread);
    ZMQParse();
}


void xmrig::JunoRpcClient::ZMQParse()
{
    // Process ZMQ messages based on connection state
    switch (m_ZMQConnectionState) {
    case ZMQ_GREETING_1:
        if (m_ZMQRecvBuf.size() >= kZMQGreetingSize1) {
            m_ZMQRecvBuf.erase(m_ZMQRecvBuf.begin(), m_ZMQRecvBuf.begin() + kZMQGreetingSize1);
            m_ZMQConnectionState = ZMQ_GREETING_2;
            ZMQWrite(kZMQGreeting + kZMQGreetingSize1, sizeof(kZMQGreeting) - kZMQGreetingSize1);
        }
        break;

    case ZMQ_GREETING_2:
        if (m_ZMQRecvBuf.size() >= sizeof(kZMQGreeting) - kZMQGreetingSize1) {
            m_ZMQRecvBuf.erase(m_ZMQRecvBuf.begin(), m_ZMQRecvBuf.begin() + sizeof(kZMQGreeting) - kZMQGreetingSize1);
            m_ZMQConnectionState = ZMQ_HANDSHAKE;
            ZMQWrite(kZMQHandshake, sizeof(kZMQHandshake) - 1);
        }
        break;

    case ZMQ_HANDSHAKE:
        // Wait for READY response and subscribe
        if (m_ZMQRecvBuf.size() >= 2) {
            // Simple check for valid response
            m_ZMQRecvBuf.clear();
            m_ZMQConnectionState = ZMQ_CONNECTED;
            ZMQWrite(kZMQSubscribe, sizeof(kZMQSubscribe) - 1);

#           ifdef APP_DEBUG
            LOG_DEBUG(CYAN("tcp-zmq://%s:%u") BLACK_BOLD(" subscribed to hashblock"), m_pool.host().data(), m_pool.zmq_port());
#           endif
        }
        break;

    case ZMQ_CONNECTED:
        // Process hashblock notifications
        if (!m_ZMQRecvBuf.empty()) {
            // On any ZMQ message, trigger new block template fetch
#           ifdef APP_DEBUG
            LOG_DEBUG(CYAN("tcp-zmq://%s:%u") BLACK_BOLD(" received notification"), m_pool.host().data(), m_pool.zmq_port());
#           endif
            m_ZMQRecvBuf.clear();
            m_prevHash = nullptr;  // Force template refresh
            getBlockTemplate();
        }
        break;

    default:
        break;
    }
}


bool xmrig::JunoRpcClient::ZMQClose(bool shutdown)
{
    if ((m_ZMQConnectionState == ZMQ_NOT_CONNECTED) || (m_ZMQConnectionState == ZMQ_DISCONNECTING)) {
        return false;
    }

    m_ZMQConnectionState = ZMQ_DISCONNECTING;

    if (Platform::hasKeepalive()) {
        uv_tcp_keepalive(m_ZMQSocket, 0, 60);
    }

    uv_close(reinterpret_cast<uv_handle_t*>(m_ZMQSocket), shutdown ? onZMQShutdown : onZMQClose);
    return true;
}


} // namespace xmrig
