#include "ProfileDelete.h"
#include "ProfileRoot.h"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#endif

namespace delprofils {

bool deleteRequestIsValid(const std::wstring& sid, const std::wstring& profilePath) {
    return !sid.empty() && !profilePath.empty();
}

ProfileDeleteResult deleteLocalProfile(const std::wstring& sid, const std::wstring& profilePath) {
    if (!deleteRequestIsValid(sid, profilePath)) {
#ifdef _WIN32
        return {ProfileDeleteStatus::InvalidRequest, ERROR_INVALID_PARAMETER};
#else
        return {ProfileDeleteStatus::InvalidRequest, 0};
#endif
    }

#ifndef _WIN32
    return {ProfileDeleteStatus::Unavailable, 0};
#else
    PSID validatedSid = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &validatedSid)) {
        return {ProfileDeleteStatus::InvalidRequest, GetLastError()};
    }
    LocalFree(validatedSid);

    const ProfilesRootResult profilesRoot = queryProfilesRoot();
    if (!profilesRoot.known || !isDirectChildOfProfilesRoot(profilePath, profilesRoot.path)) {
        return {ProfileDeleteStatus::InvalidRequest, ERROR_INVALID_DATA};
    }

    const DWORD attributes = GetFileAttributesW(profilePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return {ProfileDeleteStatus::Failed, GetLastError()};
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return {ProfileDeleteStatus::InvalidRequest, ERROR_INVALID_PARAMETER};
    }
    const DWORD rootAttributes = GetFileAttributesW(profilesRoot.path.c_str());
    if (rootAttributes == INVALID_FILE_ATTRIBUTES) {
        return {ProfileDeleteStatus::Failed, GetLastError()};
    }
    if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return {ProfileDeleteStatus::InvalidRequest, ERROR_INVALID_PARAMETER};
    }

    if (DeleteProfileW(sid.c_str(), profilePath.c_str(), nullptr)) {
        return {ProfileDeleteStatus::Deleted, ERROR_SUCCESS};
    }
    return {ProfileDeleteStatus::Failed, GetLastError()};
#endif
}

} // namespace delprofils
