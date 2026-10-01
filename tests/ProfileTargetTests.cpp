#include "../src/ProfileTarget.h"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

} // namespace

int main() {
    const auto local = delprofils::ProfileTarget::fromComputer(L"localhost");
    require(local.valid(), "localhost must be valid");
    require(local.isLocal(), "localhost must be local");

    const auto remote = delprofils::ProfileTarget::fromComputer(L"\\\\vm-profils");
    require(remote.valid(), "UNC host name must be valid");
    require(!remote.isLocal(), "named host must not become local");
    require(remote.computer() == L"vm-profils", "UNC prefix must be removed");
    require(remote.wmiNamespace() == L"\\\\vm-profils\\ROOT\\CIMV2",
            "remote WMI namespace must target the host");

    const auto selfHost = delprofils::ProfileTarget::fromComputer(L"\\\\VM-PROFILS", L"vm-profils");
    require(selfHost.valid(), "the local computer name must be valid");
    require(selfHost.isLocal(), "a case-insensitive match to the local host must use local paths");

    const auto otherHost = delprofils::ProfileTarget::fromComputer(L"vm-profils", L"workstation");
    require(otherHost.valid(), "a distinct host name must be valid");
    require(!otherHost.isLocal(), "a distinct host must remain remote");

    const auto invalid = delprofils::ProfileTarget::fromComputer(L"host/name");
    require(!invalid.valid(), "slash-containing host must be rejected");
    std::cout << "ProfileTargetTests: PASS\n";
    return 0;
}
