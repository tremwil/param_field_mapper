#pragma once
#include "utils.h"
#include <concepts>
#include <thread>

namespace pfm
{
    /// Simple timer owning a std::thread. Executes provided function until stopped or destroyed.
    class Timer {
        std::function<void()> routine;
        std::atomic_bool request_stop_thread = false;
        std::atomic_bool running = false;
        uint32_t interval_ms = 1000;
        std::thread thread;
        std::mutex mutex;

    public:
        /// Creates an empty timer with a firing interval of 1 second.
        Timer() = default;

        /// Creates an empty timer given a firing interval in milliseconds.
        Timer(uint32_t interval_ms) : interval_ms(interval_ms) {}

        /// Creates a timer given a firing interval in milliseconds and a callback, 
        /// immediately starting it.
        template<std::invocable<> R>
        Timer(uint32_t interval_ms, R routine) : 
            routine(routine),
            interval_ms(interval_ms)
        {
            start();
        }


        /// True if the timer is currently running, false otherwise.
        bool is_running() { return running; }

        /// Obtains a reference to the interval of this timer in milliseconds. 
        uint32_t& interval() { return interval_ms; }

        /// Start the timer, optionally providing a new routine. Returns true on success, false
        /// if the timer is already running.
        bool start(std::optional<std::function<void()>> routine = std::nullopt) {
            std::lock_guard lock(mutex);
            if (running.exchange(true)) return false;

            if (routine.has_value()) {
                this->routine = routine.value();
            }

            request_stop_thread = false;
            thread = std::thread([this]() {
                SPDLOG_TRACE("Timer thread (id = {}) started", GetCurrentThreadId());
                while (!utils::atomic_wait(request_stop_thread, std::atomic_bool { false }, interval_ms)) {
                    this->routine();
                }
                SPDLOG_TRACE("Timer thread (id = {}) stopped", GetCurrentThreadId());
            });

            return true;
        }

        /// Stops the timer, blocking until the thread has exited. Returns false if the
        /// timer was not running in the first place. 
        bool stop() {
            std::lock_guard lock(mutex);
            if (!running) return false;

            request_stop_thread = true;
            utils::atomic_wake(request_stop_thread);
            thread.join();

            running = false;
            return true;
        }

        ~Timer() {
            stop();
        }
    };
}