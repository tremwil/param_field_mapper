#pragma once
#include "fst/fd4_singleton.h"
#include "fst/dlut.h"
#include "fst/param_file.h"
#include "fst/res_cap.h"

#include <chrono>
#include <thread>

namespace pfm
{
    struct SoloParamRepository : public FD4Singleton<SoloParamRepository, "SoloParamRepository"> {
        void** vtable;
        FD4ResHashString resource_name_empty;
        uint8_t unk_zero[0x38];

        struct {
            uint64_t num_in_bucket;
            ParamResCap* res_caps[8];  
        } param_buckets[];

        // TODO: Replace with hook
        static SoloParamRepository* wait_until_loaded() {
            // TODO: Something less cursed

            using namespace std::chrono_literals;

            auto param_buckets = SoloParamRepository::wait_for_instance()->param_buckets;
            while (!param_buckets[0].res_caps[0]) {
                std::this_thread::sleep_for(5ms);
            }
            std::this_thread::sleep_for(100ms);
            return SoloParamRepository::instance_unchecked();
        }
    };

    struct FD4ParamRepository : public FD4Singleton<FD4ParamRepository, "FD4ParamRepository"> 
    {
        void** vtable;
        FD4ResHashString resource_name;
        uint8_t unk_48[0x30];
        ResRepository<ParamFileCap> param_container;
    };
}