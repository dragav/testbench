#include "pch.h"

using namespace ApiLoader;

void ApiLoaderRepro::ResolveHttpServiceConfigurationUpdateMethod(_Out_ HttpServiceConfigurationUpdateFnType* pConfigUpdater)
{
    *pConfigUpdater = nullptr;

    HMODULE hHttpApi = LoadLibrary(TEXT("HttpApi.dll"));

    auto procAddr = GetProcAddress(
        hHttpApi,
        "HttpUpdateServiceConfiguration");

    if (procAddr)
    {
        *pConfigUpdater = (HttpServiceConfigurationUpdateFnType)procAddr;
    }

    FreeLibrary(hHttpApi);
}

void ApiLoaderRepro::Repro()
{
    HttpServiceConfigurationUpdateFnType updater = nullptr;
    ResolveHttpServiceConfigurationUpdateMethod(&updater);
}

