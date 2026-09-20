// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/settings.h"
#include "common/string_util.h"
#include "common/swap.h"
#include "core/core.h"
#include "core/hle/service/ipc_helpers.h"
#include "core/hle/service/sockets/sfdnsres.h"
#include "core/hle/service/sockets/sockets.h"
#include "core/hle/service/sockets/sockets_translate.h"
#include "core/internal_network/network.h"
#include "core/memory.h"

namespace Service::Sockets {

std::mutex g_last_host_mutex;
std::unordered_map<std::string, std::string> g_last_host_for_ip;

void SetLastHostForIp(const std::string& ip, const std::string& host) {
    std::lock_guard lock(g_last_host_mutex);
    g_last_host_for_ip[ip] = host;
}

std::string GetLastHostForIp(const std::string& ip) {
    std::lock_guard lock(g_last_host_mutex);

    const auto it = g_last_host_for_ip.find(ip);
    if (it != g_last_host_for_ip.end()) {
        return it->second;
    }

    return {};
}

std::mutex g_last_ip_for_port_mutex;
std::unordered_map<u16, Network::IPv4Address> g_last_ip_for_port;

void SetLastIpForPort(u16 port, Network::IPv4Address ip) {
    if (port == 0) {
        return;
    }

    std::lock_guard lock(g_last_ip_for_port_mutex);
    g_last_ip_for_port[port] = ip;
}

std::optional<Network::IPv4Address> GetLastIpForPort(u16 port) {
    if (port == 0) {
        return std::nullopt;
    }

    std::lock_guard lock(g_last_ip_for_port_mutex);

    const auto it = g_last_ip_for_port.find(port);
    if (it != g_last_ip_for_port.end()) {
        return it->second;
    }

    return std::nullopt;
}

namespace {

std::optional<Network::IPv4Address> ParseIPv4Address(std::string_view address) {
    Network::IPv4Address result{};

    size_t start = 0;

    for (size_t i = 0; i < 4; ++i) {
        const size_t end = address.find('.', start);
        const size_t length =
            end == std::string_view::npos ? address.size() - start : end - start;

        if (length == 0 || length > 3) {
            return std::nullopt;
        }

        unsigned int value = 0;

        const auto [ptr, ec] =
            std::from_chars(address.data() + start, address.data() + start + length, value);

        if (ec != std::errc{} || ptr != address.data() + start + length || value > 255) {
            return std::nullopt;
        }

        result[i] = static_cast<u8>(value);

        if (end == std::string_view::npos) {
            if (i != 3) {
                return std::nullopt;
            }
        } else {
            start = end + 1;
        }
    }

    return result;
}

bool RedirectionNextendoActive() {
    return Settings::values.network_profile.GetValue() == "nextendo";
}

std::optional<std::pair<std::string, Network::IPv4Address>>
GetNextendoRedirect(const std::string& host) {
    if (!RedirectionNextendoActive()) {
        return std::nullopt;
    }

    std::string redirect_ip;

    if (host.starts_with("nncs2-") && host.ends_with(".n.n.srv.nintendo.net")) {
        redirect_ip = "164.132.111.120";
    } else if (host == "nintendo.net" || host.ends_with(".nintendo.net") ||
               host == "nintendo.com" || host.ends_with(".nintendo.com") ||
               host == "nintendowifi.net" || host.ends_with(".nintendowifi.net") ||
               host == "nintendo.co.jp" || host.ends_with(".nintendo.co.jp")) {
        redirect_ip = "51.178.29.194";
    } else {
        return std::nullopt;
    }

    const auto ip = ParseIPv4Address(redirect_ip);
    if (!ip) {
        return std::nullopt;
    }

    LOG_INFO(Service, "[Nextendo] Redirecting host '{}' -> '{}'", host, redirect_ip);

    return std::make_pair(redirect_ip, *ip);
}

} // namespace

SFDNSRES::SFDNSRES(Core::System& system_) : ServiceFramework{system_, "sfdnsres"} {
    static const FunctionInfo functions[] = {
        {0, nullptr, "SetDnsAddressesPrivateRequest"},
        {1, nullptr, "GetDnsAddressPrivateRequest"},
        {2, &SFDNSRES::GetHostByNameRequest, "GetHostByNameRequest"},
        {3, nullptr, "GetHostByAddrRequest"},
        {4, nullptr, "GetHostStringErrorRequest"},
        {5, &SFDNSRES::GetGaiStringErrorRequest, "GetGaiStringErrorRequest"},
        {6, &SFDNSRES::GetAddrInfoRequest, "GetAddrInfoRequest"},
        {7, nullptr, "GetNameInfoRequest"},
        {8, nullptr, "RequestCancelHandleRequest"},
        {9, nullptr, "CancelRequest"},
        {10, &SFDNSRES::GetHostByNameRequestWithOptions, "GetHostByNameRequestWithOptions"},
        {11, nullptr, "GetHostByAddrRequestWithOptions"},
        {12, &SFDNSRES::GetAddrInfoRequestWithOptions, "GetAddrInfoRequestWithOptions"},
        {13, nullptr, "GetNameInfoRequestWithOptions"},
        {14, &SFDNSRES::ResolverSetOptionRequest, "ResolverSetOptionRequest"},
        {15, nullptr, "ResolverGetOptionRequest"},
    };

    RegisterHandlers(functions);
}

SFDNSRES::~SFDNSRES() = default;

enum class NetDbError : s32 {
    Internal = -1,
    Success = 0,
    HostNotFound = 1,
    TryAgain = 2,
    NoRecovery = 3,
    NoData = 4,
};

static constexpr std::array blockedDomains = {
    "srv.nintendo.net",
    "nintendo.es",
    "nintendowifi.net",
    "nintendo-europe.com",
    "nintendo.com.hk",
    "nintendo.com.au",
    "nintendo.co.kr",
    "nintendo.co.uk",
    "nintendo.co.jp",
    "nintendo.co.nz",
    "nintendo.co.za",
    "nintendo.com",
    "nintendo.jp",
    "nintendo.tw",
    "nintendo.at",
    "nintendo.be",
    "nintendo.dk",
    "nintendo.de",
    "nintendo.fi",
    "nintendo.fr",
    "nintendo.gr",
    "nintendo.hu",
    "nintendo.it",
    "nintendo.nl",
    "nintendo.no",
    "nintendo.pt",
    "nintendo.ru",
    "nintendo.ch",
    "nintendo.se",
    "nintendoswitch.com.cn",
    "nintendoswitch.com",
    "sun.hac.lp1.d4c.nintendo.net",
    "phoenix-api.wbagora.com",
    "battle.net",
    "microsoft.com",
    "mojang.com",
    "xboxlive.com",
    "api.epicgames.dev",
    "minecraftservices.com",
    "508223012e5a5ff19f30a391b2bdadc0.my.2k.com",
};

static bool IsBlockedHost(const std::string& host) {
    return std::any_of(
        blockedDomains.begin(), blockedDomains.end(),
        [&host](const std::string& domain) { return host.find(domain) != std::string::npos; });
}

static NetDbError GetAddrInfoErrorToNetDbError(GetAddrInfoError result) {
    switch (result) {
    case GetAddrInfoError::SUCCESS:
        return NetDbError::Success;
    case GetAddrInfoError::AGAIN:
        return NetDbError::TryAgain;
    case GetAddrInfoError::NODATA:
        return NetDbError::HostNotFound;
    case GetAddrInfoError::SERVICE:
        return NetDbError::Success;
    default:
        return NetDbError::HostNotFound;
    }
}

static Errno GetAddrInfoErrorToErrno(GetAddrInfoError result) {
    switch (result) {
    case GetAddrInfoError::SUCCESS:
        return Errno::SUCCESS;
    case GetAddrInfoError::AGAIN:
        return Errno::SUCCESS;
    case GetAddrInfoError::NODATA:
        return Errno::SUCCESS;
    case GetAddrInfoError::SERVICE:
        return Errno::INVAL;
    default:
        return Errno::SUCCESS;
    }
}

template <typename T>
static void Append(std::vector<u8>& vec, T t) {
    const size_t offset = vec.size();
    vec.resize(offset + sizeof(T));
    std::memcpy(vec.data() + offset, &t, sizeof(T));
}

static void AppendNulTerminated(std::vector<u8>& vec, std::string_view str) {
    const size_t offset = vec.size();
    vec.resize(offset + str.size() + 1);
    std::memmove(vec.data() + offset, str.data(), str.size());
}

static std::vector<u8> SerializeAddrInfoAsHostEnt(
    const std::vector<Network::AddrInfo>& vec, std::string_view host) {

    std::vector<u8> data;

    AppendNulTerminated(data, host);

    Append<u32_be>(data, 0);
    Append<u16_be>(data, static_cast<u16>(Domain::INET));
    Append<u16_be>(data, sizeof(Network::IPv4Address));

    const size_t count = vec.size();
    ASSERT(count <= UINT32_MAX);

    Append<u32_be>(data, static_cast<uint32_t>(count));

    for (const Network::AddrInfo& addrinfo : vec) {
        Append<u32_le>(data, Network::IPv4AddressToInteger(addrinfo.addr.ip));

        LOG_INFO(Service, "Resolved host '{}' to IPv4 address {}", host,
                 Network::IPv4AddressToString(addrinfo.addr.ip));
    }

    return data;
}

static std::pair<u32, GetAddrInfoError> GetHostByNameRequestImpl(HLERequestContext& ctx) {
    struct InputParameters {
        u8 use_nsd_resolve;
        u32 cancel_handle;
        u64 process_id;
    };

    static_assert(sizeof(InputParameters) == 0x10);

    IPC::RequestParser rp{ctx};
    const auto parameters = rp.PopRaw<InputParameters>();

    LOG_WARNING(
        Service,
        "called with ignored parameters: use_nsd_resolve={}, cancel_handle={}, process_id={}",
        parameters.use_nsd_resolve, parameters.cancel_handle, parameters.process_id);

    const auto host_buffer = ctx.ReadBuffer(0);
    const std::string host = Common::StringFromBuffer(host_buffer);

    if (const auto redirect = GetNextendoRedirect(host)) {
        const auto& [redirect_ip, ip] = *redirect;

        const Network::AddrInfo addrinfo{
            .family = Network::Domain::INET,
            .protocol = Network::Protocol::TCP,
            .addr = Network::SockAddrIn{
                .ip = ip,
                .portno = 0,
            },
            .canon_name = host,
        };

        const std::vector<Network::AddrInfo> redirected{addrinfo};
        const std::vector<u8> data = SerializeAddrInfoAsHostEnt(redirected, host);
        const u32 data_size = u32(data.size());

        ctx.WriteBuffer(data, 0);
        SetLastHostForIp(redirect_ip, host);

        return {data_size, GetAddrInfoError::SUCCESS};
    }

    if (IsBlockedHost(host)) {
        LOG_WARNING(Network, "Resolution of hostname {} requested, returning EAI_AGAIN", host);
        return {0, GetAddrInfoError::AGAIN};
    }

    auto res_v = Network::GetAddressInfo(host, /*service*/ std::nullopt);

    if (auto* res = std::get_if<std::vector<Network::AddrInfo>>(&res_v)) {
        const std::vector<u8> data = SerializeAddrInfoAsHostEnt(*res, host);
        const u32 data_size = u32(data.size());

        ctx.WriteBuffer(data, 0);

        return {data_size, GetAddrInfoError::SUCCESS};
    }

    auto* err = std::get_if<Network::GetAddrInfoError>(&res_v);
    return {0, Translate(*err)};
}

void SFDNSRES::GetHostByNameRequest(HLERequestContext& ctx) {
    auto [data_size, emu_gai_err] = GetHostByNameRequestImpl(ctx);

    struct OutputParameters {
        NetDbError netdb_error;
        Errno bsd_errno;
        u32 data_size;
    };

    static_assert(sizeof(OutputParameters) == 0xc);

    IPC::ResponseBuilder rb{ctx, 5};
    rb.Push(ResultSuccess);

    rb.PushRaw(OutputParameters{
        .netdb_error = GetAddrInfoErrorToNetDbError(emu_gai_err),
        .bsd_errno = GetAddrInfoErrorToErrno(emu_gai_err),
        .data_size = data_size,
    });
}

void SFDNSRES::GetHostByNameRequestWithOptions(HLERequestContext& ctx) {
    auto [data_size, emu_gai_err] = GetHostByNameRequestImpl(ctx);

    struct OutputParameters {
        u32 data_size;
        NetDbError netdb_error;
        Errno bsd_errno;
    };

    static_assert(sizeof(OutputParameters) == 0xc);

    IPC::ResponseBuilder rb{ctx, 5};
    rb.Push(ResultSuccess);

    rb.PushRaw(OutputParameters{
        .data_size = data_size,
        .netdb_error = GetAddrInfoErrorToNetDbError(emu_gai_err),
        .bsd_errno = GetAddrInfoErrorToErrno(emu_gai_err),
    });
}

static std::vector<u8> SerializeAddrInfo(const std::vector<Network::AddrInfo>& vec,
                                         std::string_view host) {
    std::vector<u8> data;

    for (const Network::AddrInfo& addrinfo : vec) {
        Append<u32_be>(data, 0xBEEFCAFE);
        Append<u32_be>(data, 0);
        Append<u32_be>(data, static_cast<u32>(Translate(addrinfo.family)));
        Append<u32_be>(data, static_cast<u32>(Translate(addrinfo.socket_type)));
        Append<u32_be>(data, static_cast<u32>(Translate(addrinfo.protocol)));
        Append<u32_be>(data, 16);

        Append<u16_be>(data, static_cast<u16>(Translate(addrinfo.addr.family)));
        Append<u16_le>(data, addrinfo.addr.portno);
        Append<u32_le>(data, Network::IPv4AddressToInteger(addrinfo.addr.ip));

        data.resize(data.size() + 8, 0);

        if (addrinfo.canon_name.has_value()) {
            AppendNulTerminated(data, *addrinfo.canon_name);
        } else {
            data.push_back(0);
        }

        LOG_INFO(Service, "Resolved host '{}' to IPv4 address {}", host,
                 Network::IPv4AddressToString(addrinfo.addr.ip));
    }

    data.resize(data.size() + 4, 0);

    return data;
}

static std::pair<u32, GetAddrInfoError> GetAddrInfoRequestImpl(HLERequestContext& ctx) {
    struct InputParameters {
        u8 use_nsd_resolve;
        u32 cancel_handle;
        u64 process_id;
    };

    static_assert(sizeof(InputParameters) == 0x10);

    IPC::RequestParser rp{ctx};
    const auto parameters = rp.PopRaw<InputParameters>();

    LOG_WARNING(
        Service,
        "called with ignored parameters: use_nsd_resolve={}, cancel_handle={}, process_id={}",
        parameters.use_nsd_resolve, parameters.cancel_handle, parameters.process_id);

    const auto host_buffer = ctx.ReadBuffer(0);
    const std::string host = Common::StringFromBuffer(host_buffer);

    std::optional<std::string> service = std::nullopt;

    if (ctx.CanReadBuffer(1)) {
        const std::span<const u8> service_buffer = ctx.ReadBuffer(1);
        service = Common::StringFromBuffer(service_buffer);
    }

    if (const auto redirect = GetNextendoRedirect(host)) {
        const auto& [redirect_ip, ip] = *redirect;

        u16 port = 0;

        if (service && !service->empty()) {
            unsigned int parsed_port = 0;

            const auto [ptr, ec] =
                std::from_chars(service->data(), service->data() + service->size(), parsed_port);

            if (ec == std::errc{} &&
                ptr == service->data() + service->size() &&
                parsed_port <= UINT16_MAX) {
                port = static_cast<u16>(parsed_port);
            }
        }

        const Network::AddrInfo addrinfo{
            .family = Network::Domain::INET,
            .socket_type = Network::Type::STREAM,
            .protocol = Network::Protocol::TCP,
            .addr = Network::SockAddrIn{
                .ip = ip,
                .portno = port,
            },
            .canon_name = host,
        };

        const std::vector<Network::AddrInfo> redirected{addrinfo};
        const std::vector<u8> data = SerializeAddrInfo(redirected, host);
        const u32 data_size = u32(data.size());

        ctx.WriteBuffer(data, 0);

        SetLastHostForIp(redirect_ip, host);

        if (port != 0) {
            SetLastIpForPort(port, ip);
        }

        return {data_size, GetAddrInfoError::SUCCESS};
    }

    if (IsBlockedHost(host)) {
        LOG_WARNING(Network, "Resolution of hostname {} requested, returning EAI_AGAIN", host);
        return {0, GetAddrInfoError::AGAIN};
    }

    auto res_v = Network::GetAddressInfo(host, service);

    if (auto* res = std::get_if<std::vector<Network::AddrInfo>>(&res_v)) {
        const std::vector<u8> data = SerializeAddrInfo(*res, host);
        const u32 data_size = u32(data.size());

        ctx.WriteBuffer(data, 0);

        return {data_size, GetAddrInfoError::SUCCESS};
    }

    auto* err = std::get_if<Network::GetAddrInfoError>(&res_v);
    return {0, Translate(*err)};
}

void SFDNSRES::GetAddrInfoRequest(HLERequestContext& ctx) {
    auto [data_size, emu_gai_err] = GetAddrInfoRequestImpl(ctx);

    struct OutputParameters {
        Errno bsd_errno;
        GetAddrInfoError gai_error;
        u32 data_size;
    };

    static_assert(sizeof(OutputParameters) == 0xc);

    IPC::ResponseBuilder rb{ctx, 5};
    rb.Push(ResultSuccess);

    rb.PushRaw(OutputParameters{
        .bsd_errno = GetAddrInfoErrorToErrno(emu_gai_err),
        .gai_error = emu_gai_err,
        .data_size = data_size,
    });
}

void SFDNSRES::GetGaiStringErrorRequest(HLERequestContext& ctx) {
    struct InputParameters {
        GetAddrInfoError gai_errno;
    };

    IPC::RequestParser rp{ctx};
    auto input = rp.PopRaw<InputParameters>();

    const std::string result = Translate(input.gai_errno);
    ctx.WriteBuffer(result);

    IPC::ResponseBuilder rb{ctx, 2};
    rb.Push(ResultSuccess);
}

void SFDNSRES::GetAddrInfoRequestWithOptions(HLERequestContext& ctx) {
    auto [data_size, emu_gai_err] = GetAddrInfoRequestImpl(ctx);

    struct OutputParameters {
        u32 data_size;
        GetAddrInfoError gai_error;
        NetDbError netdb_error;
        Errno bsd_errno;
    };

    static_assert(sizeof(OutputParameters) == 0x10);

    IPC::ResponseBuilder rb{ctx, 6};
    rb.Push(ResultSuccess);

    rb.PushRaw(OutputParameters{
        .data_size = data_size,
        .gai_error = emu_gai_err,
        .netdb_error = GetAddrInfoErrorToNetDbError(emu_gai_err),
        .bsd_errno = GetAddrInfoErrorToErrno(emu_gai_err),
    });
}

void SFDNSRES::ResolverSetOptionRequest(HLERequestContext& ctx) {
    LOG_WARNING(Service, "(STUBBED) called");

    IPC::ResponseBuilder rb{ctx, 3};

    rb.Push(ResultSuccess);
    rb.Push<s32>(0);
}

DNS_PRIV::DNS_PRIV(Core::System& system_)
    : ServiceFramework{system_, "dns:priv"} {
    // clang-format off
    static const FunctionInfo functions[] = {
        {0, nullptr, "Cmd0"},
        {1, nullptr, "Cmd1"},
        {2, nullptr, "Cmd2"},
    };
    // clang-format on

    RegisterHandlers(functions);
}

DNS_PRIV::~DNS_PRIV() = default;

} // namespace Service::Sockets