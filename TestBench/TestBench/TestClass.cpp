#pragma once
#include "pch.h"
#include <iostream>
#include <xstring>
#include "TestClasses.h"

namespace testBench
{

    void AbstractBase::Print()
    {
        std::wprintf(L"num: %d; str: %ls", this->GetNum(), this->GetStr().c_str());
    }

    int A::GetNum()
    {
        return num_ * 10;
    }

    std::wstring A::GetStr()
    {
        return std::wstring(L"A: " + str_);
    }

}