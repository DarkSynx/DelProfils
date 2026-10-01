#pragma once

#include "ProfilePolicy.h"

#include <string>

namespace delprofils {

enum class InstalledPolicyStatus {
    Absent,
    Loaded,
    Invalid,
    UnsafeAcl,
    IoError
};

struct InstalledPolicy {
    InstalledPolicyStatus status = InstalledPolicyStatus::Absent;
    PolicyConfiguration configuration;
    std::wstring sha256Hex;
    unsigned long win32Error = 0;
    std::wstring diagnostic;
};

InstalledPolicy loadInstalledPolicy();

} // namespace delprofils
