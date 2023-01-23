// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2023, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <Particle.h>

#include "quic.h"

SYSTEM_MODE(MANUAL);
// SYSTEM_THREAD(ENABLED);

#if !defined(NDEBUG)
SerialLogHandler logHandler(LOG_LEVEL_TRACE);
#endif

static const int led = D7;

// don't use entropy from cloud
void random_seed_from_cloud(unsigned int seed)
{
}

static ApplicationWatchdog wd(60000, System.reset);

extern "C" void ping(void)
{
    wd.checkin();
}

void button_action()
{
    digitalWrite(led, HIGH);

    LOG_PRINTF(INFO, "Particle Device OS: %lu.%lu.%lu\n", (System.versionNumber() & 0xff000000) >> 24,
               (System.versionNumber() & 0x00ff0000) >> 16, (System.versionNumber() & 0x0000ff00) >> 8);

    quic_transaction("quant.eggert.org", "4433", "/2000");

    // WiFi.off();
    delay(1s);
    digitalWrite(led, LOW);
}

void setup()
{
    Serial.begin(9600);
    delay(1000);

    WiFi.on();
    WiFi.connect(WIFI_CONNECT_SKIP_LISTEN);
    waitUntil(WiFi.ready);

    // let's gather some weak entropy and seed the RNG
    const int temp = analogRead(A0);
    const int volt = analogRead(BATT);
    randomSeed(((temp << 12) | volt));

    pinMode(led, OUTPUT);
    // button_action();
}

void loop()
{
    button_action();
    delay(1s);
    // System.sleep(BTN, FALLING);
    // if (System.sleepResult().reason() == WAKEUP_REASON_PIN)
    //     button_action();
}

static uint32_t stack_lim = 0;
static uint32_t max_stack = 0;
static uint32_t heap_lim = 0;
static uint32_t dstack_depth = 0;

extern "C" void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *, void *)
{
    static const char *stack_start = 0;
    dstack_depth++;
    const char *const frame = (const char *)__builtin_frame_address(0);
    if (stack_lim == 0) {
        stack_start = frame;

        stack_lim = 6144; // TODO: can this be determined dynamically?
    }

    uint32_t heap = 0;
    runtime_info_t info = {.size = sizeof(info)};
    HAL_Core_Runtime_Info(&info, NULL);
    heap = info.freeheap;
    heap_lim = info.total_init_heap;

    const uint32_t stack = (uint32_t)(stack_start - frame);

    LOG_PRINTF(INFO, "s=%" PRIu32 " h=%" PRIu32 " l=%" PRIu32 "\n", stack, heap, dstack_depth);

    if (stack < UINT16_MAX)
        max_stack = MAX(max_stack, stack);
}

extern "C" void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void *, void *)
{
    dstack_depth--;
}
