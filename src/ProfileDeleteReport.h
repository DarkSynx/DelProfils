#pragma once

#include "ProfileDelete.h"

#include <string>

namespace delprofils {

std::wstring formatDeleteResult(const std::wstring& sid,
                                ProfileDeleteStatus status,
                                unsigned long win32Error);
std::wstring formatPolicyOutOfScope(const std::wstring& sid);
std::wstring formatQueuePendingLoaded(const std::wstring& sid);
std::wstring formatQueueStalePolicy(const std::wstring& sid);
std::wstring formatProtectionReason(const std::wstring& sid, const std::wstring& reason);

} // namespace delprofils
