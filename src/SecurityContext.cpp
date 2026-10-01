#include "SecurityContext.h"

#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#endif

namespace delprofils {

PrivilegeEnableResult enableProfileDeletionPrivileges() {
    PrivilegeEnableResult result;
#ifndef _WIN32
    result.diagnostic = L"activation des privilèges indisponible hors Windows";
    return result;
#else
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        result.status = PrivilegeEnableStatus::Failed;
        result.systemError = GetLastError();
        result.diagnostic = L"OpenProcessToken(TOKEN_ADJUST_PRIVILEGES) a échoué";
        return result;
    }

    LUID backup{};
    LUID restore{};
    if (!LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &backup) ||
        !LookupPrivilegeValueW(nullptr, SE_RESTORE_NAME, &restore)) {
        result.status = PrivilegeEnableStatus::Failed;
        result.systemError = GetLastError();
        result.diagnostic = L"LookupPrivilegeValueW(SeBackupPrivilege/SeRestorePrivilege) a échoué";
        CloseHandle(token);
        return result;
    }

    // TOKEN_PRIVILEGES declares Privileges[ANYSIZE_ARRAY], where the Windows
    // headers spell ANYSIZE_ARRAY as 1. Allocate the two-entry form explicitly
    // so GCC/MinGW can see that the second LUID_AND_ATTRIBUTES is in bounds.
    struct TokenPrivileges2 {
        DWORD PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[2];
    } privileges{};
    privileges.PrivilegeCount = 2;
    privileges.Privileges[0].Luid = backup;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    privileges.Privileges[1].Luid = restore;
    privileges.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    const BOOL adjusted = AdjustTokenPrivileges(
        token, FALSE, reinterpret_cast<PTOKEN_PRIVILEGES>(&privileges),
        static_cast<DWORD>(sizeof(privileges)), nullptr, nullptr);
    const DWORD adjustError = GetLastError();
    CloseHandle(token);
    if (!adjusted || adjustError == ERROR_NOT_ALL_ASSIGNED) {
        result.status = PrivilegeEnableStatus::Failed;
        result.systemError = adjusted ? ERROR_NOT_ALL_ASSIGNED : adjustError;
        result.diagnostic = adjusted
            ? L"SeBackupPrivilege ou SeRestorePrivilege non attribué au jeton"
            : L"AdjustTokenPrivileges a échoué";
        return result;
    }

    result.status = PrivilegeEnableStatus::Enabled;
    return result;
#endif
}

CurrentSidResult queryCurrentProcessSid() {
    CurrentSidResult r;
#ifndef _WIN32
    r.diagnostic = L"current SID probe unavailable outside Windows";
    return r;
#else
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        r.systemError = GetLastError();
        r.diagnostic = L"OpenProcessToken failed";
        return r;
    }

    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    const DWORD sizeError = GetLastError();
    if (bytes == 0 || sizeError != ERROR_INSUFFICIENT_BUFFER) {
        r.systemError = sizeError;
        r.diagnostic = L"GetTokenInformation(TokenUser) size query failed";
        CloseHandle(token);
        return r;
    }

    std::vector<unsigned char> buffer(bytes);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        r.systemError = GetLastError();
        r.diagnostic = L"GetTokenInformation(TokenUser) failed";
        CloseHandle(token);
        return r;
    }
    CloseHandle(token);

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    if (!tokenUser || !tokenUser->User.Sid || !IsValidSid(tokenUser->User.Sid)) {
        r.systemError = ERROR_INVALID_SID;
        r.diagnostic = L"TokenUser returned invalid SID";
        return r;
    }

    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &text) || !text) {
        r.systemError = GetLastError();
        r.diagnostic = L"ConvertSidToStringSidW failed";
        return r;
    }
    r.sid.assign(text);
    LocalFree(text);
    r.known = !r.sid.empty();
    if (!r.known) r.diagnostic = L"current process SID is empty";
    return r;
#endif
}

} // namespace delprofils
