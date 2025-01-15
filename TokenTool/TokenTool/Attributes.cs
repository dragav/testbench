namespace TokenTool
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Graph.Models.TermStore;

    public enum AttributeSets
    {
        AMLAccess,
        AMLOperation,
    };

    public enum AccessAttributes
    {
        AMLAccessTent,
        AMLHostingEnv,
    };

    public enum Tents
    {
        MimcoDevault,
        Mimco,
        CrescoDevault,
        CrescoBin,
        Sorento,
        Cresco,
        Mumford,
    };

    public enum Environments
    {
        Other,
        Singularity,
        Sienna,
        Hyena,
        Vienna
    };

    public class AttributeAssignmentItem
    {
        /// <summary>
        /// The name of the attribute set to which this attribute belongs. In principle, different sets may contain attributes with the same name.
        /// For simplicity, we assume that the name of the attribute is unique across all sets.
        /// </summary>
        public string Set { get; set; }
        public string Name { get; set; }
        public bool AllowMultiple { get; set; }

        /// <summary>
        /// The values of this attribute assigned to the attribute holder.
        /// For matching purposes, any value in this set is sufficient; value comparison is case-sensitive.
        /// </summary>
        public string[] Values 
        { 
            get
            {
                if (_valueSet == null) return null;
                var result = new string[_valueSet.Count];
                var idx = 0;
                foreach (var val in _valueSet)
                {
                    result[idx++] = val;
                } 
                return result;
            } 
            set
            {
                if (!AllowMultiple && value.Length > 1)
                {
                    throw new ArgumentException("Attribute does not allow multiple values.");
                }

                _valueSet = [.. value];
            }
        }

        public bool IsPartialMatchFor(AttributeAssignmentItem other)
        {
            if (other == null) return false;
            if (Set != other.Set || Name != other.Name) return false;

            foreach (var value in Values)
            {
                if (other.HasValue(value)) return true;
            }

            return false;
        }

        public bool HasValue(string value)
        {
            return _valueSet != null
                && _valueSet.Contains(value);
        }

        public static AttributeAssignmentItem[] FromGraphResult(Microsoft.Graph.Models.CustomSecurityAttributeValue csa)
        {
            ArgumentNullException.ThrowIfNull(csa);
            if (csa.AdditionalData == null) return null;

            var result = new List<AttributeAssignmentItem>();
            foreach (var key in csa.AdditionalData.Keys)
            {
                var csaValue = csa.AdditionalData[key] as Microsoft.Kiota.Abstractions.Serialization.UntypedObject;
                result.AddRange(ParseAttributeAssignment(key, csaValue));
            }

            return [.. result];
        }

        private static List<AttributeAssignmentItem> ParseAttributeAssignment(string key, Microsoft.Kiota.Abstractions.Serialization.UntypedObject csaEntry)
        {
            var result = new List<AttributeAssignmentItem>();

            foreach (var field in csaEntry.GetValue())
            {
                if (field.Key.Contains("@odata.type"))
                {
                    continue;
                }

                var attr = new AttributeAssignmentItem { Set = key, Name = field.Key };
                if (field.Value is Microsoft.Kiota.Abstractions.Serialization.UntypedString stringValue)
                {
                    attr.Values = [stringValue.GetValue()];
                    attr.AllowMultiple = false;
                }
                else if (field.Value is Microsoft.Kiota.Abstractions.Serialization.UntypedArray stringArrayValue)
                {
                    attr.AllowMultiple = true;
                    var temp = new List<string>();
                    foreach (var item in stringArrayValue.GetValue())
                    {
                        if (item is Microsoft.Kiota.Abstractions.Serialization.UntypedString)
                        {
                            temp.Add((item as Microsoft.Kiota.Abstractions.Serialization.UntypedString).GetValue() ?? string.Empty);
                        }
                    }
                    attr.Values = [.. temp];
                }
                else
                {
                    throw new ArgumentException("Unexpected type for attribute value.");
                }

                result.Add(attr);
            }

            return result;
        }

        private HashSet<string> _valueSet;

        public override string ToString()
        {
            return $"{Set}:{Name}={string.Join(", ", Values)}";
        }
    }
}