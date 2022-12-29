using System;
using System.Collections.Generic;
using System.Text;

namespace CertExplorer
{
    // cert info classes cloned from https://msazure.visualstudio.com/One/_git/AD-CertificateAuthorization?path=/src/GetIssuersClientLib/Schema/CertInfo.cs&_a=contents&version=GBmaster
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security.Cryptography.X509Certificates;

    [DataContract]
    public abstract class CertInfo
    {
        /// <summary>
        /// Gets or sets the application type of the root certificate
        /// </summary>
        [DataMember]
        public string Usage { get; set; }

        /// <summary>
        /// Gets or sets the distributed point of crl prop of the root certificate
        /// </summary>
        [DataMember]
        public string Cdp { get; set; }

        /// <summary>
        /// Gets or sets the store location where the root certificate is saved
        /// </summary>
        [DataMember]
        public string StoreLocation { get; set; }

        /// <summary>
        /// Gets or sets the name of the cert store where the root certificate is saved
        /// </summary>
        [DataMember]
        public string StoreName { get; set; }

        /// <summary>
        /// Gets or sets the body of the root certificate
        /// </summary>
        public byte[] Body { get; set; }

        public X509Certificate2 Certificate
        {
            get { return new X509Certificate2(this.Body); }
        }
    }

    public static class ObjectExtension
    {
        public static bool Equals<T>(this ICollection<T> x, ICollection<T> y)
        {
            if (x == null)
            {
                return y == null;
            }
            else if (y == null)
            {
                return false;
            }
            else
            {
                if (object.ReferenceEquals(x, y))
                {
                    return true;
                }

                if (x.Count != y.Count)
                {
                    return false;
                }

                return x.SequenceEqual(y);
            }
        }

        public static int GetHashCode(object s)
        {
            if (s != null)
            {
                return s.GetHashCode();
            }
            else
            {
                return 0;
            }
        }
    }
    /// <summary>
    /// The infomation of Intermeidate Cert from the GetIssuers client lib
    /// The field of this class should keep in sync with IntermediateCertInfo
    /// defined in src/service/core/dSMSProxy.core/Models/IntermediateCertInfo.cs
    /// </summary>
    [DataContract]
    public class IntermediateCertInfo : CertInfo, IEquatable<IntermediateCertInfo>
    {
        /// <summary>
        /// Base64encoded cert pub key
        /// </summary>
        private string encodedBody;

        /// <summary>
        /// Gets or sets the name of the intermediate cert
        /// </summary>
        [DataMember]
        public string IntermediateName { get; set; }

        /// <summary>
        /// Gets or sets the application type of the intermediate certificate
        /// </summary>
        /// <remarks>Use for deserialization of server contract</remarks>
        [DataMember(EmitDefaultValue = false)]
        private string AppType
        {
            get
            {
                return null;
            }

            set
            {
                this.Usage = value;
            }
        }

        /// <summary>
        /// Gets or sets the base64encoded body
        /// </summary>
        /// <remarks>
        /// Used for handling the difference of newtonsoft json and system runtime json work with byte array
        /// </remarks>
        [DataMember(Name = "Body")]
        private string EncodedBody
        {
            get
            {
                return this.encodedBody;
            }

            set
            {
                this.encodedBody = value;
                if (value != null)
                {
                    this.Body = Convert.FromBase64String(value);
                }
            }
        }

        public bool Equals(IntermediateCertInfo other)
        {
            return string.Equals(this.IntermediateName, other.IntermediateName, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.Usage, other.Usage, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.Cdp, other.Cdp, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.StoreLocation, other.StoreLocation, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.StoreName, other.StoreName, StringComparison.OrdinalIgnoreCase) &&
                   ObjectExtension.Equals(this.Body, other.Body);
        }

        public override int GetHashCode()
        {
            return ObjectExtension.GetHashCode(this.IntermediateName) ^
                   ObjectExtension.GetHashCode(this.Usage) ^
                   ObjectExtension.GetHashCode(this.Cdp) ^
                   ObjectExtension.GetHashCode(this.StoreLocation) ^
                   ObjectExtension.GetHashCode(this.StoreName) ^
                   ObjectExtension.GetHashCode(this.Body);
        }
    }
    /// <summary>
    /// The information of root certificate returned from GetIssuersHelper client lib
    /// The field of this class should keep in sync with RootCertInfo
    /// defined in src/service/core/dSMSProxy.core/Models/RootCertInfo.cs
    /// </summary>
    [DataContract]
    public class RootCertInfo : CertInfo, IEquatable<RootCertInfo>
    {
        /// <summary>
        /// Base64encoded cert pub key
        /// </summary>
        private string encodedBody;

        /// <summary>
        /// Gets or sets the name of the root certificate that issues some intermediate certs
        /// </summary>
        [DataMember]
        public string RootName { get; set; }

        /// <summary>
        /// Gets or sets the ca Name of the root certificate
        /// </summary>
        [DataMember]
        public string CaName { get; set; }

        /// <summary>
        /// Gets or sets the informations of the intermedaite certificates which is issued by the root certificate
        /// </summary>
        [DataMember]
        public List<IntermediateCertInfo> Intermediates { get; set; }

        /// <summary>
        /// Gets or sets the name of the root certificate that issues some intermediate certs
        /// </summary>
        /// <remarks>Use for deserialization of server contract</remarks>
        [DataMember(EmitDefaultValue = false)]
        private string rootName
        {
            get
            {
                return null;
            }

            set
            {
                this.RootName = value;
            }
        }

        /// <summary>
        /// Gets or sets the application type of the root certificate
        /// </summary>
        /// <remarks>Use for deserialization of server contract</remarks>
        [DataMember(EmitDefaultValue = false)]
        private string AppType
        {
            get
            {
                return null;
            }

            set
            {
                this.Usage = value;
            }
        }

        /// <summary>
        /// Gets or sets the base64encoded body
        /// </summary>
        /// <remarks>
        /// Used for handling the difference of newtonsoft json and system runtime json work with byte array
        /// </remarks>
        [DataMember(Name = "Body")]
        private string EncodedBody
        {
            get
            {
                {
                    return this.encodedBody;
                }
            }

            set
            {
                this.encodedBody = value;
                if (value != null)
                {
                    this.Body = Convert.FromBase64String(value);
                }
            }
        }

        public bool Equals(RootCertInfo other)
        {
            return string.Equals(this.RootName, other.RootName, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.CaName, other.CaName, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.Usage, other.Usage, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.StoreLocation, other.StoreLocation, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(this.StoreName, other.StoreName, StringComparison.OrdinalIgnoreCase) &&
                   ObjectExtension.Equals(this.Body, other.Body);
        }

        public override int GetHashCode()
        {
            return ObjectExtension.GetHashCode(this.RootName) ^
                   ObjectExtension.GetHashCode(this.CaName) ^
                   ObjectExtension.GetHashCode(this.Usage) ^
                   ObjectExtension.GetHashCode(this.StoreLocation) ^
                   ObjectExtension.GetHashCode(this.StoreName) ^
                   ObjectExtension.GetHashCode(this.Body) ^
                   ObjectExtension.GetHashCode(this.Intermediates);
        }
    }

    public class IssuerCertificatesTree : IEquatable<IssuerCertificatesTree>
    {
        public List<RootCertInfo> RootsInfos { get; set; }

        public bool Equals(IssuerCertificatesTree other)
        {
            return ObjectExtension.Equals(this.RootsInfos, other.RootsInfos);
        }

        public override int GetHashCode()
        {
            return ObjectExtension.GetHashCode(this.RootsInfos);
        }
    }
}
