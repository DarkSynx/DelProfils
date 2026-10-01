#include "TextEscape.h"

namespace delprofils {
namespace {
void appendHex4(std::wstring& out, wchar_t ch) {
    static constexpr wchar_t hex[] = L"0123456789ABCDEF";
    const unsigned v = static_cast<unsigned>(ch) & 0xFFFFU;
    out += L"\\u";
    out += hex[(v >> 12) & 0xF];
    out += hex[(v >> 8) & 0xF];
    out += hex[(v >> 4) & 0xF];
    out += hex[v & 0xF];
}

bool isBidiControl(wchar_t ch) {
    const unsigned v = static_cast<unsigned>(ch);
    return v == 0x061CU || v == 0x200EU || v == 0x200FU ||
           (v >= 0x202AU && v <= 0x202EU) ||
           (v >= 0x2066U && v <= 0x2069U);
}
}

std::wstring escapeField(std::wstring_view text) {
    std::wstring out;
    out.reserve(text.size());
    for (wchar_t ch : text) {
        switch (ch) {
            case L'\\': out += L"\\\\"; break;
            case L'\t': out += L"\\t"; break;
            case L'\r': out += L"\\r"; break;
            case L'\n': out += L"\\n"; break;
            default: {
                const unsigned v = static_cast<unsigned>(ch);
                if (v < 0x20U || v == 0x7FU ||
                    (v >= 0xD800U && v <= 0xDFFFU) || isBidiControl(ch)) {
                    appendHex4(out, ch);
                } else {
                    out.push_back(ch);
                }
            }
        }
    }
    return out;
}
}
