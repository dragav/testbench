// CertTool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

using namespace x509;

int main()
{
    std::vector<X509CertificateSPtr> arr;

    auto ptrA = X509CertificateSPtr(new X509Certificate("C", 1, 10));
    auto ptrB = X509CertificateSPtr(new X509Certificate("B", 2, 12));
    auto ptrC = X509CertificateSPtr(new X509Certificate("A", 5, 6));
    auto ptrD = X509CertificateSPtr(new X509Certificate("D", 0, 15));
    auto ptrE = X509CertificateSPtr(new X509Certificate("E", 5, 18));
    auto ptrF = X509CertificateSPtr(new X509Certificate("F", 4, 6));

    arr.emplace_back(ptrA);
    arr.emplace_back(ptrB);
    arr.emplace_back(ptrC);
    arr.emplace_back(ptrD);
    arr.emplace_back(ptrE);
    arr.emplace_back(ptrF);

    std::cout << "unsorted\n";
    PrintX509CertificateArray(arr);

    // sort by nbf
    std::cout << "\nsort by NotBefore ascending..\n";
    SortX509Vector(&arr, true, X509SortType::ByNotBefore);
    PrintX509CertificateArray(arr);

    std::cout << "\nsort by NotBefore descending..\n";
    SortX509Vector(&arr, false, X509SortType::ByNotBefore);
    PrintX509CertificateArray(arr);

    // sort by na
    std::cout << "\nsort by NotAfter ascending..\n";
    SortX509Vector(&arr, true, X509SortType::ByNotAfter);
    PrintX509CertificateArray(arr);

    std::cout << "\nsort by NotAfter descending..\n";
    SortX509Vector(&arr, false, X509SortType::ByNotAfter);
    PrintX509CertificateArray(arr);

    // sort by name
    std::cout << "\nsort by Name ascending..\n";
    SortX509Vector(&arr, true, X509SortType::ByName);
    PrintX509CertificateArray(arr);

    std::cout << "\nsort by Name descending..\n";
    SortX509Vector(&arr, false, X509SortType::ByName);
    PrintX509CertificateArray(arr);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
