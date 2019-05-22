#pragma once

#include <xstring>

namespace testBench
{
    class AbstractBase
    {
    protected: 
        int num_;
        std::wstring    str_;

    public :
        AbstractBase()
            : num_(0)
            , str_()
        {}

        AbstractBase(int num, std::wstring str)
            : num_(num)
            , str_(str)
        {}

        virtual ~AbstractBase()
        {}

        virtual void Print();

        virtual int GetNum() = 0;
        virtual std::wstring GetStr() = 0;
    };

    class A : public AbstractBase
    {
    public:
        A()
            : AbstractBase()
        {}

        A(int num, std::wstring str)
            : AbstractBase(num, str)
        {}

        virtual ~A() {}

        virtual int GetNum();
        virtual std::wstring GetStr();
    };
}

