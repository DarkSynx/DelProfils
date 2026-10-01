#include "ProfileGuard.h"

namespace delprofils {

GuardDecision evaluateProfileGuard(const ProfileSignals& s) {
    GuardDecision d;
    if (s.bakEntry) d.reasons.push_back(L"SID.BAK");
    if (s.systemSid) d.reasons.push_back(L"SYSTEM_SID");
    if (s.currentProcessSid) d.reasons.push_back(L"CURRENT_PROCESS_SID");
    if (s.userHive == LoadSignal::Present) d.reasons.push_back(L"HKU_SID_PRESENT");
    if (s.classesHive == LoadSignal::Present) d.reasons.push_back(L"HKU_CLASSES_PRESENT");
    if (s.wmiLoaded == LoadSignal::Present) d.reasons.push_back(L"WMI_LOADED_TRUE");
    if (s.wmiRefCountKnown && s.wmiRefCount > 0) d.reasons.push_back(L"WMI_REFCOUNT_POSITIVE");
    if (s.wmiSpecial == LoadSignal::Present) d.reasons.push_back(L"WMI_SPECIAL_TRUE");

    if (!d.reasons.empty()) {
        d.disposition = GuardDisposition::Protected;
        return d;
    }

    if (s.currentSidCheckKnown &&
        s.userHive == LoadSignal::Absent &&
        s.classesHive == LoadSignal::Absent &&
        s.wmiLoaded == LoadSignal::Absent &&
        // A positive RefCount remains a hard loaded signal.  In contrast,
        // some current Windows Sandbox WMI providers expose RefCount as NULL
        // for an unloaded profile.  Loaded=False plus both absent HKU hives
        // is the stronger, directly observed evidence in that situation.
        (!s.wmiRefCountKnown || s.wmiRefCount == 0) &&
        s.wmiSpecial == LoadSignal::Absent) {
        d.disposition = GuardDisposition::UnloadedConfirmed;
        d.reasons.push_back(s.wmiRefCountKnown ? L"UNLOADED_CONFIRMED"
                                                : L"UNLOADED_CONFIRMED_REFCOUNT_UNAVAILABLE");
        return d;
    }

    d.disposition = GuardDisposition::Unknown;
    if (!s.currentSidCheckKnown) d.reasons.push_back(L"CURRENT_SID_UNKNOWN");
    if (s.userHive == LoadSignal::Unknown) d.reasons.push_back(L"HKU_SID_UNKNOWN");
    if (s.classesHive == LoadSignal::Unknown) d.reasons.push_back(L"HKU_CLASSES_UNKNOWN");
    if (s.wmiLoaded == LoadSignal::Unknown) d.reasons.push_back(L"WMI_LOADED_UNKNOWN");
    if (s.wmiSpecial == LoadSignal::Unknown) d.reasons.push_back(L"WMI_SPECIAL_UNKNOWN");
    if (d.reasons.empty()) d.reasons.push_back(L"NO_POSITIVE_LOAD_SIGNAL_BUT_UNLOADED_NOT_PROVEN");
    return d;
}

const wchar_t* guardDispositionLabel(GuardDisposition disposition) {
    if (disposition == GuardDisposition::Protected) return L"PROTECTED";
    if (disposition == GuardDisposition::UnloadedConfirmed) return L"UNLOADED_CONFIRMED";
    return L"UNKNOWN";
}

} // namespace delprofils
