#include "DeferredQueueStore.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace delprofils {
namespace {

#ifdef _WIN32
constexpr DWORD kMaximumQueueBytes = 4U * 1024U * 1024U;
constexpr wchar_t kDirectoryName[] = L"DelProfils";
constexpr wchar_t kQueueName[] = L"DeferredQueue.v1";
// Files are created by an elevated administrator, not necessarily by LocalSystem.
// Giving a new file the SYSTEM owner at CreateFileW time requires SeRestorePrivilege
// and produced ERROR_INVALID_OWNER (1307) in Windows Sandbox.  The protected ACL
// validator deliberately accepts either SYSTEM or Builtin Administrators as owner;
// use the latter for newly created directory, temporary and first queue files.
constexpr wchar_t kProtectedSddl[] = L"O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";

std::wstring diagnosticFor(const wchar_t* action, DWORD error) {
    return std::wstring(action) + L" (WIN32=" + std::to_wstring(error) + L")";
}

bool getAllUsersDirectory(std::wstring& directory, DWORD& error) {
    DWORD count = 0;
    if (GetAllUsersProfileDirectoryW(nullptr, &count) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || count == 0) {
        error = GetLastError();
        return false;
    }
    std::vector<wchar_t> buffer(count, L'\0');
    if (!GetAllUsersProfileDirectoryW(buffer.data(), &count)) {
        error = GetLastError();
        return false;
    }
    directory.assign(buffer.data());
    return !directory.empty();
}

bool sidEquals(PSID left, PSID right) {
    return left != nullptr && right != nullptr && EqualSid(left, right) != FALSE;
}

bool wellKnownSid(WELL_KNOWN_SID_TYPE type, std::array<BYTE, SECURITY_MAX_SID_SIZE>& storage, PSID& sid) {
    DWORD count = static_cast<DWORD>(storage.size());
    if (!CreateWellKnownSid(type, nullptr, storage.data(), &count)) return false;
    sid = storage.data();
    return true;
}

bool fullControl(DWORD mask) {
    return (mask & GENERIC_ALL) == GENERIC_ALL || (mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
}

bool grantsMutation(DWORD mask) {
    // FILE_GENERIC_WRITE overlaps FILE_GENERIC_READ/EXECUTE on READ_CONTROL and
    // SYNCHRONIZE.  Keep only the concrete mutation bits so a Users RX ACE remains
    // acceptable while any write/delete/ACL takeover is refused.
    constexpr DWORD mutation = GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    return (mask & mutation) != 0;
}

bool hasProtectedAcl(const std::wstring& path, DWORD& error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    const DWORD result = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        error = result;
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision)) {
        error = GetLastError();
        LocalFree(descriptor);
        return false;
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemStorage{};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> adminStorage{};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> usersStorage{};
    PSID systemSid = nullptr;
    PSID adminSid = nullptr;
    PSID usersSid = nullptr;
    bool safe = wellKnownSid(WinLocalSystemSid, systemStorage, systemSid) &&
        wellKnownSid(WinBuiltinAdministratorsSid, adminStorage, adminSid) &&
        wellKnownSid(WinBuiltinUsersSid, usersStorage, usersSid) && dacl != nullptr &&
        (sidEquals(owner, systemSid) || sidEquals(owner, adminSid)) &&
        (control & SE_DACL_PROTECTED) != 0;
    bool systemFull = false;
    bool adminFull = false;
    if (safe) {
        for (DWORD index = 0; index < dacl->AceCount; ++index) {
            void* rawAce = nullptr;
            if (!GetAce(dacl, index, &rawAce) || rawAce == nullptr) {
                safe = false;
                break;
            }
            const auto* header = static_cast<const ACE_HEADER*>(rawAce);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                safe = false;
                break;
            }
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
            PSID aceSid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
            if (sidEquals(aceSid, systemSid)) {
                systemFull = systemFull || fullControl(ace->Mask);
            } else if (sidEquals(aceSid, adminSid)) {
                adminFull = adminFull || fullControl(ace->Mask);
            } else if (sidEquals(aceSid, usersSid)) {
                if (grantsMutation(ace->Mask)) {
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

bool makeProtectedSecurityAttributes(SECURITY_ATTRIBUTES& attributes, PSECURITY_DESCRIPTOR& descriptor,
                                     DWORD& error) {
    descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kProtectedSddl, SDDL_REVISION_1,
        &descriptor, nullptr)) {
        error = GetLastError();
        return false;
    }
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    return true;
}

bool queuePaths(std::wstring& directory, std::wstring& path, DWORD& error) {
    std::wstring allUsers;
    if (!getAllUsersDirectory(allUsers, error)) return false;
    directory = allUsers + L"\\" + kDirectoryName;
    path = directory + L"\\" + kQueueName;
    return true;
}

bool ensureProtectedDirectory(const std::wstring& directory, DWORD& error) {
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if ((attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY ||
            !hasProtectedAcl(directory, error)) {
            if (error == ERROR_SUCCESS) error = ERROR_ACCESS_DENIED;
            return false;
        }
        return true;
    }
    error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return false;

    SECURITY_ATTRIBUTES attributesForDirectory{};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!makeProtectedSecurityAttributes(attributesForDirectory, descriptor, error)) return false;
    const BOOL created = CreateDirectoryW(directory.c_str(), &attributesForDirectory);
    const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    if (!created && createError != ERROR_ALREADY_EXISTS) {
        error = createError;
        return false;
    }
    if (!hasProtectedAcl(directory, error)) return false;
    return true;
}

bool encodedQueueBytes(const std::vector<DeferredRecord>& records, std::vector<BYTE>& bytes,
                       std::wstring& diagnostic, DWORD& error) {
    const std::wstring encoded = encodeDeferredQueue(records);
    if (encoded.empty()) {
        diagnostic = L"file différé invalide ou dépasse 4096 entrées";
        error = ERROR_INVALID_DATA;
        return false;
    }
    if (encoded.size() > kMaximumQueueBytes) {
        diagnostic = L"file différée trop volumineuse";
        error = ERROR_FILE_TOO_LARGE;
        return false;
    }
    bytes.clear();
    bytes.reserve(encoded.size());
    for (wchar_t character : encoded) {
        if (character > 0x7f) {
            diagnostic = L"codec différé non ASCII";
            error = ERROR_INVALID_DATA;
            return false;
        }
        bytes.push_back(static_cast<BYTE>(character));
    }
    return true;
}

bool readQueueText(const std::wstring& path, std::wstring& text, DWORD& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    LARGE_INTEGER size{};
    const bool sizeValid = GetFileSizeEx(file, &size) != FALSE && size.QuadPart >= 0 &&
        static_cast<unsigned long long>(size.QuadPart) <= kMaximumQueueBytes;
    if (!sizeValid) {
        error = size.QuadPart > static_cast<LONGLONG>(kMaximumQueueBytes) ? ERROR_FILE_TOO_LARGE : GetLastError();
        CloseHandle(file);
        return false;
    }
    std::vector<BYTE> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL readOk = bytes.empty() ? TRUE : ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    if (!readOk || read != bytes.size()) {
        error = readOk ? ERROR_HANDLE_EOF : GetLastError();
        return false;
    }
    text.clear();
    text.reserve(bytes.size());
    for (BYTE byte : bytes) {
        if (byte > 0x7f) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        text.push_back(static_cast<wchar_t>(byte));
    }
    return true;
}

bool writeTemporaryQueue(const std::wstring& directory, const std::vector<BYTE>& bytes,
                         std::wstring& temporaryPath, DWORD& error) {
    SECURITY_ATTRIBUTES securityAttributes{};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!makeProtectedSecurityAttributes(securityAttributes, descriptor, error)) return false;

    HANDLE file = INVALID_HANDLE_VALUE;
    for (unsigned int attempt = 0; attempt != 32U; ++attempt) {
        temporaryPath = directory + L"\\" + kQueueName + L"." + std::to_wstring(GetCurrentProcessId()) + L"." +
            std::to_wstring(GetTickCount64()) + L"." + std::to_wstring(attempt) + L".tmp";
        file = CreateFileW(temporaryPath.c_str(), GENERIC_WRITE, 0, &securityAttributes, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (file != INVALID_HANDLE_VALUE) break;
        error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) break;
    }
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    const BOOL writeOk = bytes.empty() ? TRUE : WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    const BOOL flushed = writeOk && written == bytes.size() && FlushFileBuffers(file);
    const DWORD writeError = flushed ? ERROR_SUCCESS : (writeOk ? GetLastError() : GetLastError());
    CloseHandle(file);
    if (!flushed) {
        error = writeError;
        return false;
    }
    return true;
}

#endif

} // namespace

DeferredQueueLoadResult loadDeferredQueue() {
    DeferredQueueLoadResult result;
#ifndef _WIN32
    result.diagnostic = L"file différée disponible uniquement sous Windows";
    result.win32Error = 50U; // ERROR_NOT_SUPPORTED
    return result;
#else
    std::wstring directory;
    std::wstring path;
    DWORD error = ERROR_SUCCESS;
    if (!queuePaths(directory, path, error)) {
        result.diagnostic = diagnosticFor(L"répertoire ProgramData inaccessible", error);
        result.win32Error = error;
        return result;
    }
    const DWORD directoryAttributes = GetFileAttributesW(directory.c_str());
    if (directoryAttributes != INVALID_FILE_ATTRIBUTES) {
        if ((directoryAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
                FILE_ATTRIBUTE_DIRECTORY ||
            !hasProtectedAcl(directory, error)) {
            result.diagnostic = diagnosticFor(L"répertoire de file différée non sûr",
                error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error);
            result.win32Error = error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error;
            return result;
        }
    } else {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
            result.diagnostic = diagnosticFor(L"répertoire de file différée inaccessible", error);
            result.win32Error = error;
            return result;
        }
    }
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            result.usable = true;
            return result;
        }
        result.diagnostic = diagnosticFor(L"attribut file différée inaccessible", error);
        result.win32Error = error;
        return result;
    }
    if ((attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !hasProtectedAcl(directory, error) || !hasProtectedAcl(path, error)) {
        result.diagnostic = diagnosticFor(L"ACL ou chemin de file différée non sûr", error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error);
        result.win32Error = error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error;
        return result;
    }
    std::wstring text;
    if (!readQueueText(path, text, error) || !decodeDeferredQueue(text, result.records, result.diagnostic)) {
        if (result.diagnostic.empty()) result.diagnostic = diagnosticFor(L"lecture de file différée impossible", error);
        result.records.clear();
        result.win32Error = error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
        return result;
    }
    result.usable = true;
    return result;
#endif
}

bool saveDeferredQueue(const std::vector<DeferredRecord>& records, std::wstring& diagnostic,
                       unsigned long& win32Error) {
    diagnostic.clear();
    win32Error = 0;
#ifndef _WIN32
    (void)records;
    diagnostic = L"file différée disponible uniquement sous Windows";
    win32Error = 50U; // ERROR_NOT_SUPPORTED
    return false;
#else
    std::wstring directory;
    std::wstring path;
    DWORD error = ERROR_SUCCESS;
    if (!queuePaths(directory, path, error) || !ensureProtectedDirectory(directory, error)) {
        diagnostic = diagnosticFor(L"répertoire de file différée non disponible", error);
        win32Error = error;
        return false;
    }
    std::vector<BYTE> bytes;
    if (!encodedQueueBytes(records, bytes, diagnostic, error)) {
        win32Error = error;
        return false;
    }
    std::wstring temporaryPath;
    if (!writeTemporaryQueue(directory, bytes, temporaryPath, error)) {
        diagnostic = diagnosticFor(L"écriture temporaire de file différée impossible", error);
        win32Error = error;
        return false;
    }
    const DWORD destinationAttributes = GetFileAttributesW(path.c_str());
    BOOL committed = FALSE;
    if (destinationAttributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) {
        committed = MoveFileExW(temporaryPath.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH);
    } else if (destinationAttributes != INVALID_FILE_ATTRIBUTES &&
               (destinationAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
               hasProtectedAcl(path, error)) {
        committed = ReplaceFileW(path.c_str(), temporaryPath.c_str(), nullptr, REPLACEFILE_WRITE_THROUGH, nullptr, nullptr);
    } else if (destinationAttributes == INVALID_FILE_ATTRIBUTES) {
        error = GetLastError();
    } else {
        error = ERROR_ACCESS_DENIED;
    }
    if (!committed) {
        if (error == ERROR_SUCCESS) error = GetLastError();
        diagnostic = diagnosticFor(L"remplacement atomique de file différée impossible", error);
        win32Error = error;
        return false;
    }
    return true;
#endif
}

} // namespace delprofils
