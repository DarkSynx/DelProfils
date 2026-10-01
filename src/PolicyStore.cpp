#include "PolicyStore.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <userenv.h>
#endif

#include <array>
#include <cstdint>
#include <vector>

namespace delprofils {
namespace {

#ifdef _WIN32
constexpr DWORD kMaxPolicyBytes = 1024U * 1024U;

std::wstring makeDiagnostic(const wchar_t* action, DWORD error) {
    return std::wstring(action) + L" (WIN32=" + std::to_wstring(error) + L")";
}

bool getAllUsersPath(std::wstring& path, DWORD& error) {
    DWORD size = 0;
    if (GetAllUsersProfileDirectoryW(nullptr, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        error = GetLastError();
        return false;
    }
    std::vector<wchar_t> buffer(size, L'\0');
    if (!GetAllUsersProfileDirectoryW(buffer.data(), &size)) {
        error = GetLastError();
        return false;
    }
    path.assign(buffer.data());
    return !path.empty();
}

bool sidEquals(PSID first, PSID second) {
    return first != nullptr && second != nullptr && EqualSid(first, second) != FALSE;
}

bool makeWellKnownSid(WELL_KNOWN_SID_TYPE kind, std::array<BYTE, SECURITY_MAX_SID_SIZE>& bytes,
                      PSID& sid) {
    DWORD size = static_cast<DWORD>(bytes.size());
    if (!CreateWellKnownSid(kind, nullptr, bytes.data(), &size)) return false;
    sid = bytes.data();
    return true;
}

bool grantsWrite(DWORD mask) {
    // Do not use FILE_GENERIC_WRITE here: it contains READ_CONTROL and SYNCHRONIZE,
    // both legitimately present in FILE_GENERIC_READ/FILE_GENERIC_EXECUTE.  Testing
    // it with a bitwise intersection would therefore reject a read-only Users ACE.
    constexpr DWORD kWrite = GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                             FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD |
                             DELETE | WRITE_DAC | WRITE_OWNER;
    return (mask & kWrite) != 0;
}

bool hasSafeAcl(const std::wstring& path, DWORD& error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    const DWORD status = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS) {
        error = status;
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision)) {
        error = GetLastError();
        LocalFree(descriptor);
        return false;
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemBytes{};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> adminBytes{};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> usersBytes{};
    PSID systemSid = nullptr;
    PSID adminSid = nullptr;
    PSID usersSid = nullptr;
    bool safe = makeWellKnownSid(WinLocalSystemSid, systemBytes, systemSid) &&
                makeWellKnownSid(WinBuiltinAdministratorsSid, adminBytes, adminSid) &&
                makeWellKnownSid(WinBuiltinUsersSid, usersBytes, usersSid) &&
                (sidEquals(owner, systemSid) || sidEquals(owner, adminSid)) &&
                dacl != nullptr && (control & SE_DACL_PROTECTED) != 0;
    bool systemFull = false;
    bool adminFull = false;
    if (safe) {
        for (DWORD index = 0; index < dacl->AceCount; ++index) {
            void* rawAce = nullptr;
            if (!GetAce(dacl, index, &rawAce) || rawAce == nullptr) {
                safe = false;
                break;
            }
            const auto* header = static_cast<ACE_HEADER*>(rawAce);
            if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                safe = false;
                break;
            }
            const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
            PSID aceSid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
            if (sidEquals(aceSid, systemSid)) {
                systemFull = (ace->Mask & (GENERIC_ALL | FILE_ALL_ACCESS)) != 0;
            } else if (sidEquals(aceSid, adminSid)) {
                adminFull = (ace->Mask & (GENERIC_ALL | FILE_ALL_ACCESS)) != 0;
            } else if (sidEquals(aceSid, usersSid)) {
                if (grantsWrite(ace->Mask)) {
                    safe = false;
                    break;
                }
            } else {
                safe = false;
                break;
            }
        }
    }
    if (safe) safe = systemFull && adminFull;
    LocalFree(descriptor);
    if (!safe && error == ERROR_SUCCESS) error = ERROR_ACCESS_DENIED;
    return safe;
}

bool readFileBytes(const std::wstring& path, std::vector<BYTE>& bytes, DWORD& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    LARGE_INTEGER size{};
    const bool validSize = GetFileSizeEx(file, &size) != FALSE && size.QuadPart >= 0 &&
        static_cast<unsigned long long>(size.QuadPart) <= kMaxPolicyBytes;
    if (!validSize) {
        error = size.QuadPart > static_cast<LONGLONG>(kMaxPolicyBytes) ? ERROR_FILE_TOO_LARGE : GetLastError();
        CloseHandle(file);
        return false;
    }
    bytes.assign(static_cast<std::size_t>(size.QuadPart), 0);
    DWORD read = 0;
    const BOOL ok = bytes.empty() ? TRUE : ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != bytes.size()) {
        error = ok ? ERROR_HANDLE_EOF : GetLastError();
        return false;
    }
    return true;
}

bool decodeUtf8(const std::vector<BYTE>& bytes, std::wstring& text, DWORD& error) {
    if (bytes.empty()) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), nullptr, 0);
    if (required <= 0) {
        error = GetLastError();
        return false;
    }
    text.assign(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes.data()),
        static_cast<int>(bytes.size()), text.data(), required) != required) {
        error = GetLastError();
        return false;
    }
    return true;
}

bool sha256Hex(const std::vector<BYTE>& bytes, std::wstring& hex, DWORD& error) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultBytes = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) { error = static_cast<DWORD>(status); return false; }
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultBytes, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(algorithm, 0); error = static_cast<DWORD>(status); return false; }
    std::vector<BYTE> object(objectLength, 0);
    std::array<BYTE, 32> digest{};
    status = BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0);
    if (status >= 0 && !bytes.empty()) status = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()),
        static_cast<ULONG>(bytes.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) { error = static_cast<DWORD>(status); return false; }
    constexpr wchar_t alphabet[] = L"0123456789abcdef";
    hex.clear();
    hex.reserve(digest.size() * 2);
    for (BYTE value : digest) {
        hex.push_back(alphabet[(value >> 4) & 0x0f]);
        hex.push_back(alphabet[value & 0x0f]);
    }
    return true;
}
#endif

} // namespace

InstalledPolicy loadInstalledPolicy() {
#ifndef _WIN32
    InstalledPolicy policy;
    policy.status = InstalledPolicyStatus::IoError;
    policy.diagnostic = L"PolicyStore disponible uniquement sous Windows";
    return policy;
#else
    InstalledPolicy result;
    std::wstring allUsers;
    DWORD error = ERROR_SUCCESS;
    if (!getAllUsersPath(allUsers, error)) {
        result.status = InstalledPolicyStatus::IoError;
        result.win32Error = error;
        result.diagnostic = makeDiagnostic(L"GetAllUsersProfileDirectoryW impossible", error);
        return result;
    }
    const std::wstring directory = allUsers + L"\\DelProfils";
    const std::wstring path = directory + L"\\DelProfils.policy";
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return result;
        result.status = InstalledPolicyStatus::IoError;
        result.win32Error = error;
        result.diagnostic = makeDiagnostic(L"attribut politique inaccessible", error);
        return result;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !hasSafeAcl(directory, error) || !hasSafeAcl(path, error)) {
        result.status = InstalledPolicyStatus::UnsafeAcl;
        result.win32Error = error;
        result.diagnostic = makeDiagnostic(L"ACL politique non sûre", error);
        return result;
    }
    std::vector<BYTE> bytes;
    if (!readFileBytes(path, bytes, error)) {
        result.status = InstalledPolicyStatus::IoError;
        result.win32Error = error;
        result.diagnostic = makeDiagnostic(L"lecture politique impossible", error);
        return result;
    }
    std::wstring text;
    if (!decodeUtf8(bytes, text, error)) {
        result.status = InstalledPolicyStatus::Invalid;
        result.win32Error = error;
        result.diagnostic = makeDiagnostic(L"UTF-8 politique invalide", error);
        return result;
    }
    const auto parsed = parsePolicyConfiguration(text);
    if (!parsed.valid) {
        result.status = InstalledPolicyStatus::Invalid;
        result.diagnostic = parsed.diagnostic;
        return result;
    }
    if (!sha256Hex(bytes, result.sha256Hex, error)) {
        result.status = InstalledPolicyStatus::IoError;
        result.win32Error = error;
        result.diagnostic = makeDiagnostic(L"SHA-256 politique impossible", error);
        return result;
    }
    result.status = InstalledPolicyStatus::Loaded;
    result.configuration = parsed.configuration;
    return result;
#endif
}

} // namespace delprofils
