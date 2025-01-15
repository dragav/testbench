namespace TokenTool
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    public class AccessPolicy
    {
        public string Name { get; set; }
        public string Resource { get; set; }
        public string Action { get; set; }
        public AttributeAssignmentItem[] RequiredAttributes 
        { 
            get
            {
                return ExtractDenormalizedAttributes();
            } 
            set 
            {
                _attributesMap = [];
                foreach (var attribute in value)
                {
                    if (!_attributesMap.ContainsKey(attribute.Name))
                    {
                        _attributesMap[attribute.Name] = [];
                    }

                    foreach (var attrVal in attribute.Values)
                    {
                        _attributesMap[attribute.Name].Add(attrVal);
                    }
                }
            }
        }

        private AttributeAssignmentItem[] ExtractDenormalizedAttributes()
        {
            if (_attributesMap == null)
            {
                return null;
            }

            var result = new List<AttributeAssignmentItem>();
            foreach (var attr in _attributesMap)
            {
                result.Add(new AttributeAssignmentItem
                {
                    Set = AttributeSets.AMLAccess.ToString(),
                    Name = attr.Key,
                    Values = [.. attr.Value],
                    AllowMultiple = attr.Value.Count > 1
                });
            }

            return [.. result];
        }

        public static readonly AccessPolicy CrescoBinAccessPolicy = new AccessPolicyBuilder()
            .WithName("CrescoBinAccessPolicy")
            .WithResource("MIR endpoint")
            .WithAction("read")
            .WithRequiredTents([Tents.CrescoBin.ToString(), Tents.CrescoDevault.ToString(), Tents.Mumford.ToString()])
            .Build();

        public static readonly AccessPolicy MimcoAccessPolicy = new AccessPolicyBuilder()
            .WithName("MimcoAccessPolicy")
            .WithResource("MIR endpoint")
            .WithAction("read")
            .WithRequiredTents([Tents.Mumford.ToString(), Tents.Mimco.ToString()])
            .Build();

        public static readonly AccessPolicy HyenaAccessPolicy = new AccessPolicyBuilder()
            .WithName("HyenaAccessPolicy")
            .WithResource("MIR endpoint")
            .WithAction("read")
            .WithRequiredEnvironment(Environments.Hyena.ToString())
            .Build();

        public static readonly AccessPolicy HybridAccessPolicy = new AccessPolicyBuilder()
            .WithName("HybridAccessPolicy")
            .WithResource("MIR endpoint")
            .WithAction("read")
            .WithRequiredEnvironment(Environments.Hyena.ToString())
            .WithRequiredTents([Tents.Mumford.ToString(), Tents.Mimco.ToString()])
            .Build();


        public bool IsMatch(string resource, string action, AttributeAssignmentItem[] attributes)
        {
            if (Resource != resource || Action != action)
            {
                return false;
            }

            bool hasAllRequiredAttributes = false;
            bool hasAllRequiredValues = true;
            int countMatchedAttributes = 0;
            foreach (var actualAttribute in attributes)
            {
                // a matching attribute must have at least one required value for all required attribute names.
                // an attribute holder may have other attribute assignments.
                if (!_attributesMap.ContainsKey(actualAttribute.Name))
                {
                    continue;
                }
                countMatchedAttributes++;

                bool hasAnyRequiredValues = false;

                foreach (var requiredAttrVal in _attributesMap[actualAttribute.Name])
                {
                    if (actualAttribute.HasValue(requiredAttrVal))
                    {
                        hasAnyRequiredValues = true;
                        break;
                    }
                }

                hasAllRequiredValues &= hasAnyRequiredValues;
            }

            hasAllRequiredAttributes = countMatchedAttributes == _attributesMap.Count;

            return hasAllRequiredAttributes 
                && hasAllRequiredValues;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            foreach (var key in _attributesMap.Keys)
            {
                sb.Append($"{key}: ");
                foreach (var val in _attributesMap[key])
                {
                    sb.Append($"{val}, ");
                }
                _ = sb.Append("\t");
            }

            return $"AccessPolicy: Name = {Name}, Resource = {Resource}, Action = {Action}, RequiredAttributes = {sb.ToString()}";
        }

        private Dictionary<string, HashSet<string>> _attributesMap;
    };

    public class AccessPolicyBuilder
    {
        private AccessPolicy _accessPolicy = new AccessPolicy();

        public AccessPolicyBuilder WithResource(string resource)
        {
            _accessPolicy.Resource = resource;
            return this;
        }

        public AccessPolicyBuilder WithAction(string action)
        {
            _accessPolicy.Action = action;
            return this;
        }

        public AccessPolicyBuilder WithRequiredAttributes(AttributeAssignmentItem[] requiredAttributes)
        {
            _accessPolicy.RequiredAttributes = requiredAttributes;
            return this;
        }

        public AccessPolicyBuilder WithRequiredTents(string[] tents)
        {
            var requiredAttributes = new AttributeAssignmentItem[] {
                new AttributeAssignmentItem {
                    Set = AttributeSets.AMLAccess.ToString(),
                    Name = AccessAttributes.AMLAccessTent.ToString(),
                    AllowMultiple = true,
                    Values = tents
                }};

            if (_accessPolicy.RequiredAttributes == null)
            {
                _accessPolicy.RequiredAttributes = requiredAttributes;
            }
            else
            {
                var newRequiredAttributes = new AttributeAssignmentItem[_accessPolicy.RequiredAttributes.Length + requiredAttributes.Length];
                _accessPolicy.RequiredAttributes.CopyTo(newRequiredAttributes, 0);
                requiredAttributes.CopyTo(newRequiredAttributes, _accessPolicy.RequiredAttributes.Length);
                _accessPolicy.RequiredAttributes = newRequiredAttributes;
            }

            return this;
        }

        public AccessPolicyBuilder WithRequiredEnvironment(string environment)
        {
            var requiredAttributes = new AttributeAssignmentItem[] {
                new AttributeAssignmentItem {
                    Set = AttributeSets.AMLAccess.ToString(),
                    Name = AccessAttributes.AMLHostingEnv.ToString(),
                    AllowMultiple = false,
                    Values = new string[] { environment }
                }};

            if (_accessPolicy.RequiredAttributes == null)
            {
                _accessPolicy.RequiredAttributes = requiredAttributes;
            }
            else
            {
                var newRequiredAttributes = new AttributeAssignmentItem[_accessPolicy.RequiredAttributes.Length + requiredAttributes.Length];
                _accessPolicy.RequiredAttributes.CopyTo(newRequiredAttributes, 0);
                requiredAttributes.CopyTo(newRequiredAttributes, _accessPolicy.RequiredAttributes.Length);
                _accessPolicy.RequiredAttributes = newRequiredAttributes;
            }

            return this;
        }

        public AccessPolicyBuilder WithName(string name)
        {
            _accessPolicy.Name = name;
            return this;
        }

        public AccessPolicy Build()
        {
            return _accessPolicy;
        }
    }
}