#pragma once

#include <optional>
#include <string>
#include <vector>

namespace delprofils {

enum class ParseStatus {
    Ok = 0,
    SyntaxError = 2,
    Unsupported = 3,
    PrototypeSafetyRefusal = 30
};

struct Options {
    bool help = false;
    bool listOnly = false;
    bool unattended = false;
    bool quiet = false;
    bool promptEach = false;
    bool ignoreErrors = false;
    bool roamingOnly = false;
    bool ntuserini = false;
    bool pendingOnly = false;
    bool audit = false;
    std::optional<unsigned long> days;
    std::optional<std::wstring> policyName;
    std::wstring remoteComputer;
    std::vector<std::wstring> includePatterns;
    std::vector<std::wstring> excludePatterns;
};

struct ParseResult {
    ParseStatus status = ParseStatus::Ok;
    Options options;
    std::wstring diagnostic;
};

ParseResult parseCommandLine(const std::vector<std::wstring>& args);

} // namespace delprofils
