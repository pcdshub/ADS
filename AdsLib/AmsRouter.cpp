/**
   Copyright (c) 2015 Beckhoff Automation GmbH & Co. KG

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
 */

#include "AmsRouter.h"
#include "Frame.h"
#include "Log.h"

#include <algorithm>
#include <iomanip>
#include <iostream>

AmsRouter::AmsRouter(AmsNetId netId)
    : localAddr(netId)
{}

long AmsRouter::AddRoute(AmsNetId ams, const IpV4& ip)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);

    const auto oldConnection = GetConnection(ams);
    if (oldConnection && !(ip == oldConnection->destIp)) {
        /**
           There is already a route for this AmsNetId, but with
           a different IP. The old route has to be deleted, first!
         */
        return ROUTERERR_PORTALREADYINUSE;
    }

    auto conn = connections.find(ip);
    if (conn == connections.end()) {
        conn = connections.emplace(ip, std::unique_ptr<AmsConnection>(new AmsConnection { *this, ip })).first;

        /** in case no local AmsNetId was set previously, we derive one */
        if (!localAddr) {
            localAddr = AmsNetId {conn->second->ownIp};
        }
    }

    conn->second->refCount++;
    mapping[ams] = conn->second.get();
    return !conn->second->ownIp;
}

void AmsRouter::DelRoute(const AmsNetId& ams)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);

    auto route = mapping.find(ams);
    if (route != mapping.end()) {
        AmsConnection* conn = route->second;
        if (0 == --conn->refCount) {
            mapping.erase(route);
            DeleteIfLastConnection(conn);
        }
    }
}

void AmsRouter::DeleteIfLastConnection(const AmsConnection* conn)
{
    if (conn) {
        for (const auto& r : mapping) {
            if (r.second == conn) {
                return;
            }
        }
        connections.erase(conn->destIp);
    }
}

bool AmsRouter::OpenLocalPort(uint16_t &port)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    IpV4 localhost_ip { std::string("127.0.0.1") };
    AmsNetId localhost { localhost };
    LOG_INFO("Requesting a port on localhost...");
    auto conn = GetConnection(localhost);
    if (!conn) {
        if (AddRoute(localhost, localhost_ip)) {
            LOG_ERROR("Unable to add localhost route?");
            return false;
        }
        LOG_INFO("Automatically added a localhost route");
        conn = GetConnection(localhost);
        if (!conn) {
            LOG_ERROR("Still no connection? I don't know what I'm doing");
            return false;
        }
    }

    const uint8_t request[] = {
        // AMS_TCP_PORT_CONNECT 0x1000 -> 0, 16
        0, 16,
        // data length 0x00 00 00 02 -> 2, 0, 0, 0
        2, 0, 0, 0,
        // Data: Requested ADS Port (0 to let the server assign it)
        // NOTE: this is only for "local" mode
        0, 0,
    };

    Frame request_frame { sizeof(request), request };
    // conn->Write only deals in AMS frames, so use the socket directly
    if (conn->socket.write(request_frame) != request_frame.size()) {
        LOG_ERROR("Failed to write the request packet");
        return false;
    }
    uint8_t response[14] = { 0 };
    const uint8_t expected_response_header[6] { 0, 16, 8, 0, 0, 0 };
    timeval timeout = { 1, 0 };
    conn->Receive(response, sizeof(response), &timeout);
    AmsAddr *our_addr = reinterpret_cast<AmsAddr*>(&response[6]);
    std::cout << "Our address according to the server is: " << 
        our_addr->netId << " with port " << 
        our_addr->port << std::endl;

    if (memcmp(response, expected_response_header, sizeof(expected_response_header))) {
        LOG_ERROR("... but the response header was wrong anyway, so no deal.");
        std::cout << "Expected response header was: ";
        for (int idx = 0; idx < sizeof(expected_response_header); ++idx) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(expected_response_header[idx]) << " ";
        }
        std::cout << std::endl;
        std::cout << "Full response was: ";
        for (int idx = 0; idx < sizeof(response); ++idx) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(response[idx]) << " ";
        }
        std::cout << std::endl;
        return false;
    }
    if (our_addr->port != 0) {
        port = our_addr->port;
        if (!ports[port].IsOpen()) {
          ports[port].Open(port);
        }
        return true;
    }
    return false;
}

uint16_t AmsRouter::OpenPort()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);

    const int port_base = 30000; // arbitrary or meaningful?
    for (uint16_t i = port_base; i < NUM_PORTS_MAX; ++i) {
        if (!ports[i].IsOpen()) {
            return ports[i].Open(i);
        }
    }
    return 0;
}

long AmsRouter::ClosePort(uint16_t port)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if ((port < 1) || (port >= NUM_PORTS_MAX) || !ports[port].IsOpen()) {
        return ADSERR_CLIENT_PORTNOTOPEN;
    }
    ports[port].Close();
    return 0;
}

long AmsRouter::GetLocalAddress(uint16_t port, AmsAddr* pAddr)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if ((port < 1) || (port >= NUM_PORTS_MAX)) {
        return ADSERR_CLIENT_PORTNOTOPEN;
    }

    if (ports[port].IsOpen()) {
        memcpy(&pAddr->netId, &localAddr, sizeof(localAddr));
        pAddr->port = port;
        return 0;
    }
    return ADSERR_CLIENT_PORTNOTOPEN;
}

void AmsRouter::SetLocalAddress(AmsNetId netId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    localAddr = netId;
}

long AmsRouter::GetTimeout(uint16_t port, uint32_t& timeout)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if ((port < 1) || (port >= NUM_PORTS_MAX)) {
        return ADSERR_CLIENT_PORTNOTOPEN;
    }

    timeout = ports[port].tmms;
    return 0;
}

long AmsRouter::SetTimeout(uint16_t port, uint32_t timeout)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if ((port < 1) || (port >= NUM_PORTS_MAX)) {
        return ADSERR_CLIENT_PORTNOTOPEN;
    }

    ports[port].tmms = timeout;
    return 0;
}

AmsConnection* AmsRouter::GetConnection(const AmsNetId& amsDest)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    const auto it = __GetConnection(amsDest);
    if (it == connections.end()) {
        return nullptr;
    }
    return it->second.get();
}

std::map<IpV4, std::unique_ptr<AmsConnection> >::iterator AmsRouter::__GetConnection(const AmsNetId& amsDest)
{
    const auto it = mapping.find(amsDest);
    if (it != mapping.end()) {
        return connections.find(it->second->destIp);
    }
    return connections.end();
}

long AmsRouter::AdsRequest(AmsRequest& request)
{
    if (request.bytesRead) {
        *request.bytesRead = 0;
    }

    auto ads = GetConnection(request.destAddr.netId);
    if (!ads) {
        return GLOBALERR_MISSING_ROUTE;
    }
    return ads->AdsRequest(request, ports[request.port].tmms);
}

long AmsRouter::AddNotification(AmsRequest& request, uint32_t* pNotification, std::shared_ptr<Notification> notify)
{
    if (request.bytesRead) {
        *request.bytesRead = 0;
    }

    auto ads = GetConnection(request.destAddr.netId);
    if (!ads) {
        return GLOBALERR_MISSING_ROUTE;
    }

    auto& port = ports[request.port];
    const long status = ads->AdsRequest(request, port.tmms);
    if (!status) {
        *pNotification = qFromLittleEndian<uint32_t>((uint8_t*)request.buffer);
        const auto notifyId = ads->CreateNotifyMapping(*pNotification, notify);
        port.AddNotification(notifyId);
    }
    return status;
}

long AmsRouter::DelNotification(uint16_t port, const AmsAddr* pAddr, uint32_t hNotification)
{
    auto& p = ports[port];
    return p.DelNotification(*pAddr, hNotification);
}
