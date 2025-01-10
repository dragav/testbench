namespace TokenTool
{
    using System;
    using System.Collections.Generic;

    public enum AttributeSets
    {
        AMLAccess,
        AMLOperation,
    };

    public enum AccessAttributes
    {
        Tent,
        Environment,
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
            get; 
            set
            {
                if (!AllowMultiple && value.Length > 1)
                {
                    throw new ArgumentException("Attribute does not allow multiple values.");
                }

                _valueSet = new HashSet<string>();
                foreach (var val in value)
                {
                    _valueSet.Add(val);
                }
            }
        }

        public bool HasValue(string value)
        {
            return _valueSet != null
                && _valueSet.Contains(value);
        }

        private HashSet<string> _valueSet;
    }
}