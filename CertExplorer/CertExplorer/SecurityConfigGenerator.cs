using System;
using System.Collections.Generic;
using System.Text;

namespace CertExplorer
{
    public enum Role
    {
        Cluster = 0, 
        Server,
        Client
    }

    public enum X509CredDeclarationType
    {
        TP = 0,
        CN
    };

    public sealed class CredentialDescriptor
    {
        private static readonly Dictionary<X509CredDeclarationType, string> Desc = new Dictionary<X509CredDeclarationType, string>
        {
            [X509CredDeclarationType.CN] = SecurityConfigGenerator.CredValueCN,
            [X509CredDeclarationType.TP] = SecurityConfigGenerator.CredValueTP
        };

        public string this[X509CredDeclarationType type]
        {
            get { return Desc[type]; }
        }
    }

    public sealed class CredDeclaration
    {
        public X509CredDeclarationType FindType { get; set; }
        public string FindValue { get; set; }

        public override string ToString()
        {
            return String.Format($"Type: {FindType}; Value: {FindValue}");
        }
    }

    public sealed class SecurityConfiguration
    {
        private readonly Dictionary<Role, CredDeclaration> Declarations = new Dictionary<Role, CredDeclaration>
        {
            [Role.Cluster] = { },
            [Role.Server] = { },
            [Role.Client] = { }
        };

        public SecurityConfiguration(Dictionary<Role, CredDeclaration> rules)
        {
            foreach (var entry in rules)
            {
                Declarations[entry.Key] = entry.Value;
            }
        }

        public void SetDeclaration(Role role, CredDeclaration declaration)
        {
            Declarations[role] = declaration;
        }

        public void Print()
        {
            foreach (var roleDecl in Declarations)
            {
                Console.Write($"{roleDecl.Key}:{roleDecl.Value}-");
            }
            Console.WriteLine();
        }

        public override string ToString()
        {
            StringBuilder str = new StringBuilder();
            foreach (var entry in Declarations)
            {
                str.AppendFormat($"{entry.Key}: {entry.Value.FindValue}({entry.Value.FindType}), ");
            }

            return str.ToString();
        }

        public string ToShortString()
        {
            StringBuilder str = new StringBuilder();
            foreach (var entry in Declarations)
            {
                str.AppendFormat($"{entry.Value.FindValue}-");
            }

            return str.ToString();
        }
    }

    public sealed class SecurityConfigGenerator
    {
        internal static readonly string CredValueTP = "1234";
        internal static readonly string CredValueCN = "blah";

        private static readonly List<Role> Roles = new List<Role> { Role.Cluster, Role.Server, Role.Client };
        private static readonly List<X509CredDeclarationType> DeclTypes = new List<X509CredDeclarationType> { X509CredDeclarationType.TP, X509CredDeclarationType.CN };
        private static readonly List<CredDeclaration> credDeclarations = new List<CredDeclaration>
        {
            new CredDeclaration { FindType = X509CredDeclarationType.CN, FindValue = CredValueCN },
            new CredDeclaration { FindType = X509CredDeclarationType.TP, FindValue = CredValueTP }
        };

        public static List<SecurityConfiguration> GenerateConfigurations()
        {
            List<SecurityConfiguration> presentationRules = new List<SecurityConfiguration>();
            Dictionary<Role, CredDeclaration> presentationRulesMap = new Dictionary<Role, CredDeclaration>();

            GeneratePresentationRuleSetsForCredentialRec(credDeclarations, presentationRulesMap, presentationRules, 0);

            return presentationRules;
        }

        private static void GeneratePresentationRuleSetsForCredentialRec(
            List<CredDeclaration> credDeclarations,
            Dictionary<Role, CredDeclaration> presentationRulesMap,
            List<SecurityConfiguration> presentationRules,
            int level)
        {
            if (level < Roles.Count)
            {
                foreach (var credDecl in credDeclarations)
                {
                    presentationRulesMap[(Role)level] = credDecl;
                    GeneratePresentationRuleSetsForCredentialRec(credDeclarations, presentationRulesMap, presentationRules, level + 1);
                }
            }
            else
            { 
                var config = new SecurityConfiguration(presentationRulesMap);

                presentationRules.Add(config);

                presentationRulesMap = new Dictionary<Role, CredDeclaration>();

                level = 0;
                return;
            }
        }
    }
}
