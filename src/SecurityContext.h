#pragma once
#include <string>

namespace delprofils {
enum class PrivilegeEnableStatus {
    Enabled,
    Unavailable,
    Failed
};

struct PrivilegeEnableResult {
    PrivilegeEnableStatus status = PrivilegeEnableStatus::Unavailable;
    unsigned long systemError = 0;
    std::wstring diagnostic;
};

struct CurrentSidResult {
    bool known = false;
    unsigned long systemError = 0;
    std::wstring sid;
    std::wstring diagnostic;
};
PrivilegeEnableResult enableProfileDeletionPrivileges();
CurrentSidResult queryCurrentProcessSid();
}
