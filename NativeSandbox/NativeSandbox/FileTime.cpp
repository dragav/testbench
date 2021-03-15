#include "pch.h"
using namespace SysTypes;

void FileTime::Repro()
{
    FILETIME ft = { 0 };
    ft.dwLowDateTime = 0x4cbbd200;
    ft.dwHighDateTime = 0x01d8a39d;

    SYSTEMTIME st = { 0 };
    if (!FileTimeToSystemTime(&ft, &st))
    {
        DWORD dwErr = GetLastError();
        std::cout << "Failed; err: " << dwErr;
    }
    else
    {
        std::cout << "DateTime: " << st.wYear << ":" << st.wMonth << ":" << st.wDay << ":" << st.wHour << ":" << st.wMinute << ":" << st.wSecond;
    }
}
