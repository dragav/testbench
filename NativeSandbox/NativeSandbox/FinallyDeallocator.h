#pragma once

namespace FinallyDeallocator
{
    template <class T>
    struct __Finally
    {
        T _Lam;

        __Finally(T&& Src) : _Lam(Src) {}

        ~__Finally()
        {
            _Lam(); // when the auto goes out of scope, invoke the lambda via pointer
        }
    };

    class FinallyDeallocatorRepro
    {
        static void Repro() {}
    };
}
