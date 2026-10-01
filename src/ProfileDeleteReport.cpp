#include "ProfileDeleteReport.h"

#include "TextEscape.h"

namespace delprofils {
namespace {

std::wstring formatP1Event(const wchar_t* category, const wchar_t* value, const std::wstring& sid) {
    return std::wstring(category) + L"=" + value + L" SID=" + escapeField(sid);
}

}

std::wstring formatDeleteResult(const std::wstring& sid,
                                ProfileDeleteStatus status,
                                unsigned long win32Error) {
    std::wstring result;
    if (status == ProfileDeleteStatus::Deleted) {
        result = L"DELETE=SUCCESS";
    } else if (status == ProfileDeleteStatus::InvalidRequest) {
        result = L"DELETE=REFUSED";
    } else if (status == ProfileDeleteStatus::Unavailable) {
        result = L"DELETE=UNAVAILABLE";
    } else {
        result = L"DELETE=FAILED";
    }
    result += L" SID=" + escapeField(sid);
    if (status != ProfileDeleteStatus::Deleted) {
        result += L" WIN32=" + std::to_wstring(win32Error);
    }
    return result;
}

std::wstring formatPolicyOutOfScope(const std::wstring& sid) {
    return formatP1Event(L"POLICY", L"OUT_OF_SCOPE", sid);
}

std::wstring formatQueuePendingLoaded(const std::wstring& sid) {
    return formatP1Event(L"QUEUE", L"PENDING_LOADED", sid);
}

std::wstring formatQueueStalePolicy(const std::wstring& sid) {
    return formatP1Event(L"QUEUE", L"STALE_POLICY", sid);
}

std::wstring formatProtectionReason(const std::wstring& sid, const std::wstring& reason) {
    return L"PROTECTION=" + escapeField(reason) + L" SID=" + escapeField(sid);
}

} // namespace delprofils
