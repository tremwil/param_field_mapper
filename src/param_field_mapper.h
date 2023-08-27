#pragma once

#include "core/singleton.h"
#include <winnt.h>

namespace pfm
{
    class ParamFieldMapper : public Singleton<ParamFieldMapper> {

    public:
        bool init();

    protected: 
        ParamFieldMapper() = default;

    private:
        LONG veh(EXCEPTION_POINTERS* ex);

        static LONG veh_thunk(EXCEPTION_POINTERS* ex) {
            return ParamFieldMapper::get().veh(ex);
        }
    };
}