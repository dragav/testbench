#pragma once

#include <wincrypt.h>

namespace x509
{
    class X509Certificate
    {
    public:
        X509Certificate();
        //X509Certificate(PCERT_CONTEXT);
        X509Certificate(std::string name,ULONG nbf, ULONG na);
        X509Certificate(const X509Certificate& model);
        virtual ~X509Certificate();

        X509Certificate& operator =(const X509Certificate& rhs);
        bool operator ==(const X509Certificate& rhs);

        ULONG NotBefore() const { return nbf_; }
        ULONG NotAfter() const { return na_; }
        std::string Name() const { return name_; }

        /// comparison
        inline bool IsLessByNotBefore(const X509Certificate& rhs) const
        {
            // favor longest valid to break ties
            return this->nbf_ < rhs.NotBefore()
                || (this->nbf_ == rhs.NotBefore()
                    && this->na_ >= rhs.NotAfter());
        }

        inline bool IsGreaterByNotBefore(const X509Certificate& rhs) const
        {
            // favor longest valid to break ties
            return this->nbf_ > rhs.NotBefore()
                || (this->nbf_ == rhs.NotBefore()
                    && this->na_ >= rhs.NotAfter());
        }

        inline bool IsLessByNotAfter(const X509Certificate& rhs) const
        {
            // favor most recent to break ties
            return this->na_ < rhs.NotAfter()
                || (this->na_ == rhs.NotAfter()
                    && this->nbf_ >= rhs.NotBefore());
        }

        inline bool IsGreaterByNotAfter(const X509Certificate& rhs) const
        {
            // favor most recent to break ties
            return this->na_ > rhs.NotAfter()
                || (this->na_ == rhs.NotAfter()
                    && this->nbf_ >= rhs.NotBefore());
        }

        inline bool IsLessByName(const X509Certificate& rhs) const
        {
            return this->name_ < rhs.Name();
        }

        inline bool IsGreaterByName(const X509Certificate& rhs) const
        {
            return this->name_ > rhs.Name();
        }

    private:
        std::string name_;
        ULONG nbf_;
        ULONG na_;
    };

    typedef std::shared_ptr<X509Certificate> X509CertificateSPtr;
    typedef bool (*CompareX509Certificates)(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs);

    inline bool CompareX509CertificateAscByNotBefore(const X509Certificate& lhs, const X509Certificate& rhs) 
    {
        return lhs.IsLessByNotBefore(rhs);
    }

    inline bool CompareX509CertificatePtrAscByNotBefore(X509CertificateSPtr const & lhs, X509CertificateSPtr const & rhs)
    {
        return CompareX509CertificateAscByNotBefore(*lhs, *rhs);
    }

    inline bool CompareX509CertificateDescByNotBefore(const X509Certificate& lhs, const X509Certificate& rhs)
    {
        return lhs.IsGreaterByNotBefore(rhs);
    }

    inline bool CompareX509CertificatePtrDescByNotBefore(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs)
    {
        return CompareX509CertificateDescByNotBefore(*lhs, *rhs);
    }

    inline bool CompareX509CertificateAscByNotAfter(const X509Certificate& lhs, const X509Certificate& rhs)
    {
        return lhs.IsLessByNotAfter(rhs);
    }

    inline bool CompareX509CertificatePtrAscByNotAfter(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs)
    {
        return CompareX509CertificateAscByNotAfter(*lhs, *rhs);
    }

    inline bool CompareX509CertificateDescByNotAfter(const X509Certificate& lhs, const X509Certificate& rhs)
    {
        return lhs.IsGreaterByNotAfter(rhs);
    }

    inline bool CompareX509CertificatePtrDescByNotAfter(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs)
    {
        return CompareX509CertificateDescByNotAfter(*lhs, *rhs);
    }

    inline bool CompareX509CertificateAscByName(const X509Certificate& lhs, const X509Certificate& rhs)
    {
        return lhs.IsLessByName(rhs);
    }

    inline bool CompareX509CertificatePtrAscByName(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs)
    {
        return CompareX509CertificateAscByName(*lhs, *rhs);
    }

    inline bool CompareX509CertificateDescByName(const X509Certificate& lhs, const X509Certificate& rhs)
    {
        return lhs.IsGreaterByName(rhs);
    }

    inline bool CompareX509CertificatePtrDescByName(X509CertificateSPtr const& lhs, X509CertificateSPtr const& rhs)
    {
        return CompareX509CertificateDescByName(*lhs, *rhs);
    }

    void PrintX509Certificate(const X509CertificateSPtr x509CertPtr);
    void PrintX509CertificateArray(std::vector<X509CertificateSPtr> array);

    typedef enum _X509SortType
    {
        ByNotBefore = 0,
        ByNotAfter,
        ByName
    } X509SortType;

    void SortX509Vector(std::vector<X509CertificateSPtr>* pArray, bool ascending, X509SortType type);

    //bool operator ==(const X509Certificate& lhs, const X509Certificate& rhs);
}