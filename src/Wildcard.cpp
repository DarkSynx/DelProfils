#include "Wildcard.h"

namespace delprofils {
namespace {
bool unitEqual(wchar_t a, wchar_t b) {
    if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
    if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b - L'A' + L'a');
    return a == b;
}
}

bool wildcardMatch(std::wstring_view pattern, std::wstring_view value) {
    std::size_t p = 0, v = 0;
    std::size_t star = std::wstring_view::npos;
    std::size_t retry = 0;
    while (v < value.size()) {
        if (p < pattern.size() && (pattern[p] == L'?' || unitEqual(pattern[p], value[v]))) {
            ++p; ++v;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            star = p++;
            retry = v;
        } else if (star != std::wstring_view::npos) {
            p = star + 1;
            v = ++retry;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == L'*') ++p;
    return p == pattern.size();
}

} // namespace delprofils
