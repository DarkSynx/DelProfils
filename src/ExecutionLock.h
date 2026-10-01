#pragma once

namespace delprofils {

class ExecutionLock {
public:
    static ExecutionLock tryAcquire();

    ExecutionLock(const ExecutionLock&) = delete;
    ExecutionLock& operator=(const ExecutionLock&) = delete;
    ExecutionLock(ExecutionLock&& other) noexcept;
    ExecutionLock& operator=(ExecutionLock&& other) noexcept;
    ~ExecutionLock();

    [[nodiscard]] bool acquired() const noexcept;
    [[nodiscard]] unsigned long win32Error() const noexcept;

private:
    explicit ExecutionLock(void* handle, bool ownsMutex, unsigned long error) noexcept;
    void reset() noexcept;

    void* handle_ = nullptr;
    bool ownsMutex_ = false;
    unsigned long win32Error_ = 0;
};

} // namespace delprofils
