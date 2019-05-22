#include "pch.h"

namespace x509
{

    X509Certificate::X509Certificate()
    {
    }

    X509Certificate::X509Certificate(std::string name, ULONG nbf, ULONG na)
    {
        if (name.empty()) throw std::invalid_argument("'name' may not be empty");
        if (nbf > na) throw std::invalid_argument("NotBefore may not be greater than NotAfter");

        name_ = name;
        nbf_ = nbf;
        na_ = na;
    }

    X509Certificate::X509Certificate(const X509Certificate& model)
    {
        name_ = model.Name();
        na_ = model.NotAfter();
        nbf_ = model.NotBefore();
    }

    X509Certificate& X509Certificate::operator = (const X509Certificate& rhs)
    {
        if (this == &rhs) return *this;

        name_ = rhs.Name();
        na_ = rhs.NotAfter();
        nbf_ = rhs.NotBefore();

        return *this;
    }

    bool X509Certificate::operator ==(const X509Certificate& rhs)
    {
        return this == &rhs
            || (name_ == rhs.Name()
                && na_ == rhs.NotAfter()
                && nbf_ == rhs.NotBefore());
    }

    X509Certificate::~X509Certificate()
    {
    }

    void PrintX509Certificate(const X509CertificateSPtr x509CertPtr)
    {
        std::cout << "name: " << x509CertPtr->Name().c_str()
            << "; nbf: " << x509CertPtr->NotBefore()
            << "; na: " << x509CertPtr->NotAfter();
    }

    void PrintX509CertificateArray(std::vector<X509CertificateSPtr> x509CertArray)
    {
        int idx = 0;
        for (auto certIt = x509CertArray.begin();
            certIt != x509CertArray.end();
            certIt++)
        {
            std::cout << idx++ << ": ";
            PrintX509Certificate(*certIt);
            std::cout << "\n";
        }
    }

    void SortX509Vector(std::vector<X509CertificateSPtr>* pArray, bool ascending, X509SortType type)
    {
        if (!pArray) throw std::invalid_argument("pArray may not be null");

        bool (*compare)(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs);

        switch (type)
        {
        case X509SortType::ByName:
            compare = ascending ? CompareX509CertificatePtrAscByName : CompareX509CertificatePtrDescByName;
            break;

        case X509SortType::ByNotBefore:
            compare = ascending ? CompareX509CertificatePtrAscByNotBefore : CompareX509CertificatePtrDescByNotBefore;
            break;

        case X509SortType::ByNotAfter:
            compare = ascending ? CompareX509CertificatePtrAscByNotAfter : CompareX509CertificatePtrDescByNotAfter;
            break;

        default:
            throw std::invalid_argument("unexpected comparison type");
        }

        std::sort(pArray->begin(), pArray->end(), compare);
    }
}