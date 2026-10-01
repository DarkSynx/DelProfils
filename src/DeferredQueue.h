#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace delprofils {

struct DeferredRecord {
    std::wstring sid;
    std::wstring profilePath;
    std::wstring policyName;
    std::wstring policySha256;
    std::uint64_t firstObservedUtcTicks = 0;
    std::uint64_t lastObservedUtcTicks = 0;
    std::uint32_t observedLoadedCount = 0;
};

enum class QueueRecordDecision {
    Keep,
    RemoveChangedSid,
    RemoveChangedPath,
    RemoveChangedPolicy,
    RemoveProtected
};

QueueRecordDecision validateDeferredRecord(const DeferredRecord& record, std::wstring_view sid,
    std::wstring_view path, std::wstring_view policyName, std::wstring_view policySha256,
    bool protectedNow);
std::wstring encodeDeferredQueue(const std::vector<DeferredRecord>& records);
bool decodeDeferredQueue(std::wstring_view text, std::vector<DeferredRecord>& records,
                         std::wstring& diagnostic);

} // namespace delprofils
