#pragma once

#include <string>

namespace delprofils {

enum class ProfileDeleteStatus {
    Deleted,
    InvalidRequest,
    Failed,
    Unavailable
};

struct ProfileDeleteResult {
    ProfileDeleteStatus status = ProfileDeleteStatus::InvalidRequest;
    unsigned long win32Error = 0;
};

bool deleteRequestIsValid(const std::wstring& sid, const std::wstring& profilePath);
ProfileDeleteResult deleteLocalProfile(const std::wstring& sid, const std::wstring& profilePath);

} // namespace delprofils
