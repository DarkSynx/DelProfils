#pragma once

#include "DeferredQueue.h"

#include <string>
#include <vector>

namespace delprofils {

struct DeferredQueueLoadResult {
    bool usable = false;
    std::vector<DeferredRecord> records;
    std::wstring diagnostic;
    unsigned long win32Error = 0;
};

DeferredQueueLoadResult loadDeferredQueue();
bool saveDeferredQueue(const std::vector<DeferredRecord>& records, std::wstring& diagnostic,
                       unsigned long& win32Error);

} // namespace delprofils
