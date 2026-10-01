#pragma once
#include <string_view>
namespace delprofils {
class Console {
public:
    explicit Console(bool quiet) : quiet_(quiet) {}
    void out(std::wstring_view text) const;
    void err(std::wstring_view text) const;
private:
    void write(bool error, std::wstring_view text) const;
    bool quiet_ = false;
};
}
