namespace TokenTool
{
    public class Config
    {
        public string ClientId { get; set; }
        public string ClientCredentialTP { get; set; }
        public string TenantId { get; set; }
        public string TokenAudience { get; set; }
        public bool SendX5c { get; set; } = false;
    }
}