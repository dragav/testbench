// NativeSandbox.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

int main()
{
    SpecializedDtor::SpecializedDtorTest::Repro();

    //SysTypes::FileTime::Repro();
    //std::vector<int> myvec;
    //myvec.emplace_back(1);
    //myvec.emplace_back(2);
    //myvec.emplace_back(3);

    //for (auto it = myvec.begin(); it != myvec.end(); it++)
    //{
    //    if (*it == 3)
    //    {
    //        auto testEnd = myvec.erase(it);
    //        if (testEnd == myvec.end())
    //            break;
    //    }
    //}

    //Certs::CertExplorer::Repro();
    /*bool flag = false;
    printf("testing formatted printing: \nflag is %son; !flag is %son", flag ? "" : "not ", flag ? "not " : "");*/

    //LoopedLock::Lock::Repro();

    //::LocalFree(nullptr);
    //MemLeak::MemLeakRepro::Repro();
    //std::cout << "end";
}
