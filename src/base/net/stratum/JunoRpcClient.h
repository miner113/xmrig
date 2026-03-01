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

#ifndef XMRIG_JUNORPCCLIENT_H
#define XMRIG_JUNORPCCLIENT_H


#include "base/kernel/interfaces/IDnsListener.h"
#include "base/kernel/interfaces/IHttpListener.h"
#include "base/kernel/interfaces/ITimerListener.h"
#include "base/net/stratum/BaseClient.h"
#include "base/net/tools/Storage.h"


#include <memory>
#include <string>
#include <vector>


using uv_buf_t      = struct uv_buf_t;
using uv_connect_t  = struct uv_connect_s;
using uv_handle_t   = struct uv_handle_s;
using uv_stream_t   = struct uv_stream_s;
using uv_tcp_t      = struct uv_tcp_s;


namespace xmrig {


class DnsRequest;
class Timer;


/**
 * Solo mining RPC client for Juno Cash.
 *
 * Connects to a Juno node's JSON-RPC interface, fetches block templates,
 * and submits mined blocks. Supports both HTTP polling and ZMQ notifications
 * for new block detection.
 */
class JunoRpcClient : public BaseClient, public IDnsListener, public ITimerListener, public IHttpListener
{
public:
    XMRIG_DISABLE_COPY_MOVE_DEFAULT(JunoRpcClient)

    JunoRpcClient(int id, IClientListener *listener);
    ~JunoRpcClient() override;

protected:
    // IClient overrides
    bool disconnect() override;
    bool isTLS() const override;
    int64_t submit(const JobResult &result) override;
    void connect() override;
    void connect(const Pool &pool) override;
    void setPool(const Pool &pool) override;
    void deleteLater() override;

    inline bool hasExtension(Extension) const noexcept override         { return false; }
    inline const char *mode() const override                            { return "solo"; }
    inline const char *tlsFingerprint() const override                  { return m_tlsFingerprint; }
    inline const char *tlsVersion() const override                      { return m_tlsVersion; }
    inline int64_t send(const rapidjson::Value &, Callback) override    { return -1; }
    inline int64_t send(const rapidjson::Value &) override              { return -1; }
    inline void tick(uint64_t) override                                 {}

    // IHttpListener
    void onHttpData(const HttpData &data) override;

    // ITimerListener
    void onTimer(const Timer *timer) override;

    // IDnsListener
    void onResolved(const DnsRecords &records, int status, const char* error) override;

private:
    // RPC methods
    void getBlockTemplate();
    void submitBlock(const JobResult &result);
    int64_t rpcSend(const rapidjson::Document &doc);

    // Block template parsing
    bool parseBlockTemplate(const rapidjson::Value &result);
    bool isOutdated(uint64_t height, const char *hash) const;

    // State management
    void retry();
    void setState(SocketState state);

    // ZMQ support
    static void onZMQConnect(uv_connect_t* req, int status);
    static void onZMQRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void onZMQClose(uv_handle_t* handle);
    static void onZMQShutdown(uv_handle_t* handle);

    void ZMQConnect();
    void ZMQConnected();
    bool ZMQWrite(const char* data, size_t size);
    void ZMQRead(ssize_t nread, const uv_buf_t* buf);
    void ZMQParse();
    bool ZMQClose(bool shutdown = false);

    // Helper
    static inline JunoRpcClient* getClient(void* data) { return m_storage.get(data); }

    // Member variables
    std::shared_ptr<IHttpListener> m_httpListener;
    Timer *m_timer;
    String m_currentJobId;
    String m_prevHash;
    String m_tlsFingerprint;
    String m_tlsVersion;
    Buffer m_currentSeedHash;

    uint64_t m_pollInterval         = 2000;  // 2 seconds default
    uint64_t m_blocktemplateHeight  = 0;
    uint64_t m_jobSteadyMs          = 0;

    // Solo mining block template data (for submission)
    std::string m_coinbaseTxnHex;
    std::vector<std::string> m_transactionsHex;

    // Block header fields (for reconstruction during submission)
    uint32_t m_blockVersion         = 0;
    uint8_t m_headerPrevHash[32]{};
    uint8_t m_headerMerkleRoot[32]{};
    uint8_t m_headerBlockCommitments[32]{};
    uint32_t m_headerTime           = 0;
    uint32_t m_headerBits           = 0;

    // ZMQ state
    std::shared_ptr<DnsRequest> m_dns;
    uv_tcp_t* m_ZMQSocket           = nullptr;
    uintptr_t m_key                 = 0;

    enum ZMQState {
        ZMQ_NOT_CONNECTED,
        ZMQ_GREETING_1,
        ZMQ_GREETING_2,
        ZMQ_HANDSHAKE,
        ZMQ_CONNECTED,
        ZMQ_DISCONNECTING,
    } m_ZMQConnectionState          = ZMQ_NOT_CONNECTED;

    std::vector<char> m_ZMQSendBuf;
    std::vector<char> m_ZMQRecvBuf;

    static Storage<JunoRpcClient> m_storage;
};


} /* namespace xmrig */


#endif /* XMRIG_JUNORPCCLIENT_H */
