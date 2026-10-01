#include "ExecutionLock.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <utility>

namespace delprofils {

ExecutionLock::ExecutionLock(void* handle, bool ownsMutex, unsigned long error) noexcept
    : handle_(handle), ownsMutex_(ownsMutex), win32Error_(error) {}

ExecutionLock::ExecutionLock(ExecutionLock&& other) noexcept
    : handle_(other.handle_), ownsMutex_(other.ownsMutex_), win32Error_(other.win32Error_) {
    other.handle_ = nullptr;
    other.ownsMutex_ = false;
    other.win32Error_ = 0;
}

ExecutionLock& ExecutionLock::operator=(ExecutionLock&& other) noexcept {
    if (this != &other) {
        reset();
        handle_ = other.handle_;
        ownsMutex_ = other.ownsMutex_;
        win32Error_ = other.win32Error_;
        other.handle_ = nullptr;
        other.ownsMutex_ = false;
        other.win32Error_ = 0;
    }
    return *this;
}

ExecutionLock::~ExecutionLock() {
    reset();
}

ExecutionLock ExecutionLock::tryAcquire() {
#ifndef _WIN32
    return ExecutionLock(nullptr, false, 50U); // ERROR_NOT_SUPPORTED
#else
    SetLastError(ERROR_SUCCESS);
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"Local\\DelProfils.1.0.Execution");
    if (mutex == nullptr) return ExecutionLock(nullptr, false, GetLastError());

    // A second in-process acquisition would recurse if we waited on this mutex.
    // Treat every pre-existing object as busy: only this RAII object creates it.
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return ExecutionLock(nullptr, false, ERROR_BUSY);
    }

    const DWORD wait = WaitForSingleObject(mutex, 0);
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
        return ExecutionLock(mutex, true, wait == WAIT_ABANDONED ? ERROR_ABANDONED_WAIT_0 : ERROR_SUCCESS);
    }
    const DWORD error = wait == WAIT_TIMEOUT ? ERROR_BUSY : GetLastError();
    CloseHandle(mutex);
    return ExecutionLock(nullptr, false, error);
#endif
}

bool ExecutionLock::acquired() const noexcept {
    return handle_ != nullptr && ownsMutex_;
}

unsigned long ExecutionLock::win32Error() const noexcept {
    return win32Error_;
}

void ExecutionLock::reset() noexcept {
#ifdef _WIN32
    if (handle_ != nullptr) {
        if (ownsMutex_) ReleaseMutex(static_cast<HANDLE>(handle_));
        CloseHandle(static_cast<HANDLE>(handle_));
    }
#endif
    handle_ = nullptr;
    ownsMutex_ = false;
}

} // namespace delprofils
