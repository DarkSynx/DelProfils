#include "CommandLine.h"

#include <string_view>
#include <utility>

namespace delprofils {
namespace {

std::wstring asciiLower(std::wstring_view s) {
    std::wstring out(s);
    for (auto& ch : out) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return out;
}

bool badPattern(std::wstring_view p) {
    if (p.empty() || p.size() > 1024 || p == L"." || p == L"..") return true;
    for (wchar_t ch : p) {
        if (ch == 0 || ch == L'"' || ch == L'/' || ch == L'\\' || ch == L':' ||
            ch == L'<' || ch == L'>' || ch == L'|' || ch < 0x20 || ch == 0x7f) {
            return true;
        }
    }
    return false;
}

bool validComputer(std::wstring_view s) {
    if (s.rfind(L"\\\\", 0) == 0) s.remove_prefix(2);
    if (s.empty()) return false;
    if (s == L"." || s == L"localhost") return true; // still refused as /c in 1.0
    if (s.size() > 253) return false;
    for (wchar_t ch : s) {
        const bool ok = (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
                        (ch >= L'0' && ch <= L'9') || ch == L'-' || ch == L'.';
        if (!ok) return false;
    }
    return true;
}

bool parseDays(std::wstring_view s, unsigned long& out) {
    if (s.empty()) return false;
    unsigned long value = 0;
    for (wchar_t ch : s) {
        if (ch < L'0' || ch > L'9') return false;
        const unsigned digit = static_cast<unsigned>(ch - L'0');
        if (value > (365000UL - digit) / 10UL) return false;
        value = value * 10UL + digit;
    }
    if (value < 1 || value > 365000UL) return false;
    out = value;
    return true;
}

bool validPolicyName(std::wstring_view value) {
    if (value.empty() || value.size() > 64) return false;
    for (wchar_t character : value) {
        const bool letter = (character >= L'a' && character <= L'z') ||
            (character >= L'A' && character <= L'Z');
        const bool digit = character >= L'0' && character <= L'9';
        if (!letter && !digit && character != L'_' && character != L'-') return false;
    }
    return true;
}

ParseResult syntax(Options o, std::wstring msg) {
    return {ParseStatus::SyntaxError, std::move(o), std::move(msg)};
}

} // namespace

ParseResult parseCommandLine(const std::vector<std::wstring>& args) {
    Options o;
    // /q must silence an error even when a preceding argument is invalid.
    // This pre-scan is deliberately limited to the exact switch; malformed
    // forms such as /q:foo remain syntax errors and do not become quiet.
    for (const auto& raw : args) {
        if (raw.size() == 2 && (raw[0] == L'/' || raw[0] == L'-') &&
            asciiLower(std::wstring_view(raw).substr(1)) == L"q") {
            o.quiet = true;
            break;
        }
    }
    if (args.empty()) {
        o.listOnly = true;
        return {ParseStatus::Ok, std::move(o), {}};
    }
    bool seenDays = false;
    bool seenComputer = false;
    bool seenPolicy = false;
    std::size_t patternCount = 0;

    for (const auto& raw : args) {
        if (raw.size() < 2 || (raw[0] != L'/' && raw[0] != L'-')) {
            return syntax(std::move(o), L"argument positionnel ou option invalide");
        }
        const std::wstring body = asciiLower(std::wstring_view(raw).substr(1));

        if (body == L"?") o.help = true;
        else if (body == L"l") o.listOnly = true;
        else if (body == L"u") o.unattended = true;
        else if (body == L"q") o.quiet = true;
        else if (body == L"p") o.promptEach = true;
        else if (body == L"i") o.ignoreErrors = true;
        else if (body == L"r") o.roamingOnly = true;
        else if (body == L"ntuserini") o.ntuserini = true;
        else if (body == L"pending") {
            o.pendingOnly = true;
            o.listOnly = true;
        } else if (body == L"audit") {
            o.audit = true;
            o.listOnly = true;
        } else if (body.rfind(L"policy:", 0) == 0) {
            if (seenPolicy) return syntax(std::move(o), L"/policy ne peut apparaître qu'une fois");
            const std::wstring value = raw.substr(8);
            if (!validPolicyName(value)) return syntax(std::move(o), L"nom /policy invalide");
            o.policyName = value;
            seenPolicy = true;
        }
        else if (body.rfind(L"d:", 0) == 0) {
            if (seenDays) return syntax(std::move(o), L"/d ne peut apparaître qu'une fois");
            unsigned long days = 0;
            if (!parseDays(std::wstring_view(raw).substr(3), days)) {
                return syntax(std::move(o), L"valeur /d invalide");
            }
            o.days = days;
            seenDays = true;
        } else if (body.rfind(L"c:", 0) == 0) {
            if (seenComputer) return syntax(std::move(o), L"/c ne peut apparaître qu'une fois");
            std::wstring value = raw.substr(3);
            // DelProf2 treats an empty /c: as the local computer. Preserve that
            // behavior; a command with no action is still rejected below.
            if (!value.empty() && !validComputer(value)) {
                return syntax(std::move(o), L"cible /c invalide");
            }
            if (value.rfind(L"\\\\", 0) == 0) value.erase(0, 2);
            o.remoteComputer = std::move(value);
            seenComputer = true;
        } else if (body.rfind(L"id:", 0) == 0 || body.rfind(L"ed:", 0) == 0) {
            if (++patternCount > 256) return syntax(std::move(o), L"trop de motifs");
            const bool include = body.rfind(L"id:", 0) == 0;
            std::wstring value = raw.substr(4);
            if (badPattern(value)) return syntax(std::move(o), L"motif invalide");
            (include ? o.includePatterns : o.excludePatterns).push_back(std::move(value));
        } else {
            return syntax(std::move(o), L"option inconnue");
        }
    }

    if ((o.quiet && o.promptEach) || (o.unattended && o.promptEach) || (o.promptEach && o.listOnly)) {
        return syntax(std::move(o), L"combinaison d'options incompatible");
    }
    if (o.ntuserini && !o.days) return syntax(std::move(o), L"/ntuserini exige /d");
    if (o.pendingOnly && o.audit) return syntax(std::move(o), L"/pending et /audit sont incompatibles");
    if (o.pendingOnly && (o.unattended || o.promptEach || o.days.has_value() || !o.includePatterns.empty() ||
                          !o.excludePatterns.empty() || o.ntuserini || o.ignoreErrors ||
                          !o.remoteComputer.empty() || o.roamingOnly)) {
        return syntax(std::move(o), L"/pending ne peut pas être combiné à cette option");
    }
    if (o.audit && (o.unattended || o.promptEach || o.ignoreErrors || !o.remoteComputer.empty() ||
                    o.roamingOnly)) {
        return syntax(std::move(o), L"/audit ne peut pas être combiné à cette option");
    }

    if (o.help) return {ParseStatus::Ok, std::move(o), {}};

    // DelProf2 accepts actions without a positive selector: the initial set is
    // every eligible inactive profile, narrowed by /ed when supplied. Preserve
    // that behavior for commands such as the lycée GPO /q /ed:admin*.
    // An explicitly empty /c: remains an error for deletion because it is an
    // ambiguous target; /l /c: is handled as local inventory above.
    if (seenComputer && o.remoteComputer.empty() && !o.listOnly) {
        return syntax(std::move(o), L"/c: vide n'est permis qu'avec /l");
    }

    return {ParseStatus::Ok, std::move(o), {}};
}

} // namespace delprofils
