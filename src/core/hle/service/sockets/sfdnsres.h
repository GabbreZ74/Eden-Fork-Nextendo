// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once
#include <optional>
#include <string>

#include "core/internal_network/network.h"

#include "core/hle/service/service.h"

namespace Core {
class System;
}

namespace Service::Sockets {

void SetLastHostForIp(const std::string& ip, const std::string& host);
std::string GetLastHostForIp(const std::string& ip);

void SetLastIpForPort(u16 port, Network::IPv4Address ip);
std::optional<Network::IPv4Address> GetLastIpForPort(u16 port);

class SFDNSRES final : public ServiceFramework<SFDNSRES> {
public:
    explicit SFDNSRES(Core::System& system_);
    ~SFDNSRES() override;

private:
    void GetHostByNameRequest(HLERequestContext& ctx);
    void GetGaiStringErrorRequest(HLERequestContext& ctx);
    void GetHostByNameRequestWithOptions(HLERequestContext& ctx);
    void GetAddrInfoRequest(HLERequestContext& ctx);
    void GetAddrInfoRequestWithOptions(HLERequestContext& ctx);
    void ResolverSetOptionRequest(HLERequestContext& ctx);
};

class DNS_PRIV final : public ServiceFramework<DNS_PRIV> {
public:
    explicit DNS_PRIV(Core::System& system_);
    ~DNS_PRIV() override;
};

} // namespace Service::Sockets
