#pragma once

namespace ApiLoader
{
    typedef ULONG(WINAPI* HttpServiceConfigurationUpdateFnType)(
        HANDLE,
        HTTP_SERVICE_CONFIG_ID,
        PVOID,
        ULONG ConfigInfoLength,
        LPOVERLAPPED);

    class ApiLoaderRepro
    {
        static void ResolveHttpServiceConfigurationUpdateMethod(_Out_ HttpServiceConfigurationUpdateFnType* pConfigUpdater);

        static void Repro();
    };
};