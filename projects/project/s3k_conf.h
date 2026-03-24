#pragma once

#define PLATFORM_VIRT
#include "plat/config.h"

// Number of user-space processes managed by the monitor.
#define S3K_PROC_CNT 2

// Capability table size per process.
#define S3K_CAP_CNT 32

// Number of hardware-backed IPC channels.
#define S3K_CHAN_CNT 2

// Scheduling slots per round-robin period.
#define S3K_SLOT_CNT 32ull

// Slot duration in timer ticks.
#define S3K_SLOT_LEN (S3K_RTC_HZ / S3K_SLOT_CNT)

// Scheduler execution budget per slot.
#define S3K_SCHED_TIME (S3K_SLOT_LEN / 10)

// Define NDEBUG to disable assertions in production builds.
//#define NDEBUG
#define VERBOSITY 0
