#include "ProfilePolicy.h"

#include "Wildcard.h"

#include <algorithm>

namespace delprofils {
namespace {

std::wstring asciiLower(std::wstring_view value) {
    std::wstring result(value);
    for (wchar_t& ch : result) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return result;
}

std::wstring trimAscii(std::wstring_view value) {
    std::size_t begin = 0;
    std::size_t end = value.size();
    while (begin < end && (value[begin] == L' ' || value[begin] == L'\t')) ++begin;
    while (end > begin && (value[end - 1] == L' ' || value[end - 1] == L'\t')) --end;
    return std::wstring(value.substr(begin, end - begin));
}

bool validPolicyName(std::wstring_view value) {
    if (value.empty() || value.size() > 64) return false;
    for (wchar_t ch : value) {
        const bool alpha = (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z');
        const bool digit = ch >= L'0' && ch <= L'9';
        if (!alpha && !digit && ch != L'_' && ch != L'-') return false;
    }
    return true;
}

bool validPattern(std::wstring_view value) {
    if (value.empty() || value.size() > 1024 || value == L"." || value == L"..") return false;
    for (wchar_t ch : value) {
        if (ch == 0 || ch == L'"' || ch == L'/' || ch == L'\\' || ch == L':' ||
            ch == L'<' || ch == L'>' || ch == L'|' || ch < 0x20 || ch == 0x7f) {
            return false;
        }
    }
    return true;
}

PolicyParseResult invalid(std::wstring diagnostic) {
    PolicyParseResult result;
    result.diagnostic = std::move(diagnostic);
    return result;
}

bool containsInsensitive(const std::vector<NamedPolicy>& policies, std::wstring_view name) {
    const std::wstring normalized = asciiLower(name);
    return std::any_of(policies.begin(), policies.end(), [&](const NamedPolicy& policy) {
        return asciiLower(policy.name) == normalized;
    });
}

bool containsExact(const std::vector<std::wstring>& values, const std::wstring& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace

const NamedPolicy* findNamedPolicy(const PolicyConfiguration& configuration, std::wstring_view name) {
    const std::wstring normalized = asciiLower(name);
    for (const auto& policy : configuration.policies) {
        if (asciiLower(policy.name) == normalized) return &policy;
    }
    return nullptr;
}

bool policyIncludesBasename(const NamedPolicy& policy, std::wstring_view basename) {
    const std::wstring candidate(basename);
    bool included = false;
    for (const auto& pattern : policy.includePatterns) {
        if (wildcardMatch(pattern, candidate)) {
            included = true;
            break;
        }
    }
    if (!included) return false;
    for (const auto& pattern : policy.excludePatterns) {
        if (wildcardMatch(pattern, candidate)) return false;
    }
    return true;
}

bool policyProtectsBasename(const NamedPolicy& policy, std::wstring_view basename) {
    const std::wstring candidate(basename);
    for (const auto& pattern : policy.protectedNames) {
        if (wildcardMatch(pattern, candidate)) return true;
    }
    return false;
}

PolicyParseResult parsePolicyConfiguration(std::wstring_view text) {
    if (!text.empty() && text.front() == 0xfeff) text.remove_prefix(1);
    PolicyConfiguration configuration;
    NamedPolicy* currentPolicy = nullptr;
    bool inGlobalSection = false;
    bool globalSectionSeen = false;
    bool defaultSeen = false;

    std::size_t offset = 0;
    std::size_t lineNumber = 0;
    while (offset <= text.size()) {
        const std::size_t end = text.find(L'\n', offset);
        std::wstring line = trimAscii(text.substr(offset, end == std::wstring_view::npos ?
            std::wstring_view::npos : end - offset));
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        ++lineNumber;
        if (!line.empty()) {
            if (line.front() == L'[' && line.back() == L']') {
                const std::wstring section = asciiLower(trimAscii(std::wstring_view(line).substr(1, line.size() - 2)));
                currentPolicy = nullptr;
                inGlobalSection = false;
                if (section == L"delprofils") {
                    if (globalSectionSeen) {
                        return invalid(L"section [delprofils] dupliquée ligne " + std::to_wstring(lineNumber));
                    }
                    globalSectionSeen = true;
                    inGlobalSection = true;
                } else if (section.rfind(L"policy:", 0) == 0) {
                    const std::wstring name = trimAscii(std::wstring_view(section).substr(7));
                    if (!validPolicyName(name) || containsInsensitive(configuration.policies, name)) {
                        return invalid(L"nom de politique invalide ou dupliqué ligne " + std::to_wstring(lineNumber));
                    }
                    configuration.policies.push_back({name, {}, {}, {}});
                    currentPolicy = &configuration.policies.back();
                } else {
                    return invalid(L"section inconnue ligne " + std::to_wstring(lineNumber));
                }
            } else {
                const std::size_t equal = line.find(L'=');
                if (equal == std::wstring::npos || line.find(L'=', equal + 1) != std::wstring::npos) {
                    return invalid(L"affectation invalide ligne " + std::to_wstring(lineNumber));
                }
                const std::wstring key = asciiLower(trimAscii(std::wstring_view(line).substr(0, equal)));
                const std::wstring value = trimAscii(std::wstring_view(line).substr(equal + 1));
                if (value.empty()) return invalid(L"valeur vide ligne " + std::to_wstring(lineNumber));
                if (inGlobalSection) {
                    if (key != L"default-policy" || defaultSeen || !validPolicyName(value)) {
                        return invalid(L"option globale invalide ligne " + std::to_wstring(lineNumber));
                    }
                    configuration.defaultPolicyName = value;
                    defaultSeen = true;
                } else if (currentPolicy != nullptr) {
                    if ((key != L"include" && key != L"exclude" && key != L"protect") || !validPattern(value)) {
                        return invalid(L"règle de politique invalide ligne " + std::to_wstring(lineNumber));
                    }
                    std::vector<std::wstring>* destination = key == L"include" ? &currentPolicy->includePatterns :
                        key == L"exclude" ? &currentPolicy->excludePatterns : &currentPolicy->protectedNames;
                    if (containsExact(*destination, value)) {
                        return invalid(L"règle de politique dupliquée ligne " + std::to_wstring(lineNumber));
                    }
                    destination->push_back(value);
                } else {
                    return invalid(L"règle hors section ligne " + std::to_wstring(lineNumber));
                }
            }
        }
        if (end == std::wstring_view::npos) break;
        offset = end + 1;
    }

    if (configuration.policies.empty()) return invalid(L"aucune politique déclarée");
    for (const auto& policy : configuration.policies) {
        if (policy.includePatterns.empty()) return invalid(L"politique sans include: " + policy.name);
    }
    if (configuration.defaultPolicyName.has_value() &&
        findNamedPolicy(configuration, *configuration.defaultPolicyName) == nullptr) {
        return invalid(L"default-policy inconnue");
    }
    PolicyParseResult result;
    result.valid = true;
    result.configuration = std::move(configuration);
    return result;
}

} // namespace delprofils
