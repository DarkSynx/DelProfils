#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace delprofils {

struct NamedPolicy {
    std::wstring name;
    std::vector<std::wstring> includePatterns;
    std::vector<std::wstring> excludePatterns;
    std::vector<std::wstring> protectedNames;
};

struct PolicyConfiguration {
    std::optional<std::wstring> defaultPolicyName;
    std::vector<NamedPolicy> policies;
};

struct PolicyParseResult {
    bool valid = false;
    PolicyConfiguration configuration;
    std::wstring diagnostic;
};

PolicyParseResult parsePolicyConfiguration(std::wstring_view text);
const NamedPolicy* findNamedPolicy(const PolicyConfiguration& configuration, std::wstring_view name);
bool policyIncludesBasename(const NamedPolicy& policy, std::wstring_view basename);
bool policyProtectsBasename(const NamedPolicy& policy, std::wstring_view basename);

} // namespace delprofils
