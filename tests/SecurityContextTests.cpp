#include "../src/SecurityContext.h"

#include <cstdlib>
#include <iostream>

int main() {
    const delprofils::PrivilegeEnableResult result = delprofils::enableProfileDeletionPrivileges();
#ifndef _WIN32
    if (result.status != delprofils::PrivilegeEnableStatus::Unavailable) {
        std::cerr << "FAIL: non-Windows privilege activation must be unavailable\n";
        return 1;
    }
#endif
    std::cout << "SecurityContextTests: PASS\n";
    return 0;
}
