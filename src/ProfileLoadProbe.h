#pragma once
#include "ProfileGuard.h"
#include <string>
#include <vector>

namespace delprofils {
struct ProfileLoadProbeResult {
    LoadSignal userHive = LoadSignal::Unknown;
    LoadSignal classesHive = LoadSignal::Unknown;
    std::vector<std::wstring> diagnostics;
};
ProfileLoadProbeResult probeProfileLoadedHives(const std::wstring& sid);
}
