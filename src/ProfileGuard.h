#pragma once
#include <string>
#include <vector>

namespace delprofils {

enum class LoadSignal {
    Unknown,
    Absent,
    Present
};

enum class GuardDisposition {
    Protected,
    UnloadedConfirmed,
    Unknown
};

struct ProfileSignals {
    bool currentSidCheckKnown = false;
    bool currentProcessSid = false;
    bool systemSid = false;
    bool bakEntry = false;
    LoadSignal userHive = LoadSignal::Unknown;
    LoadSignal classesHive = LoadSignal::Unknown;
    LoadSignal wmiLoaded = LoadSignal::Unknown;
    bool wmiRefCountKnown = false;
    unsigned long wmiRefCount = 0;
    LoadSignal wmiSpecial = LoadSignal::Unknown;
};

struct GuardDecision {
    GuardDisposition disposition = GuardDisposition::Unknown;
    std::vector<std::wstring> reasons;
};

GuardDecision evaluateProfileGuard(const ProfileSignals& signals);
const wchar_t* guardDispositionLabel(GuardDisposition disposition);

} // namespace delprofils
