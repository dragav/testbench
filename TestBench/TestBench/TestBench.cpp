#include "pch.h"
#include <iostream>
#include <xstring>
#include "TestClasses.h"

using namespace testBench;

int main()
{
    std::cout << "Hello World!\n"; 

    CertExport::Run();
    //AbstractBase* pObj = new A(4, L"mental");
    //pObj->Print();
}
