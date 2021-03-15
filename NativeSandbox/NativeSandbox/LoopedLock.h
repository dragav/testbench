#pragma once

namespace LoopedLock
{
    class Lock
    {
    public:
        Lock() { std::cout << "acquiring lock"; }
        virtual ~Lock() { std::cout << "releasing lock"; }

        static void Repro()
        {
            for (int i = 0; i < 5; ++i)
            {
                std::cout << "start of iteration " << i;
                Lock lock;
            }
        }
    };
}