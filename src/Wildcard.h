#pragma once
#include <string_view>
namespace delprofils {
bool wildcardMatch(std::wstring_view pattern, std::wstring_view value);
}
