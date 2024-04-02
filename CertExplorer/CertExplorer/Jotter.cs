using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace CertExplorer
{
    public class Jotter
    {
        public string Token { get; set; }
        public static void Validate(string token, SecurityToken jwtToken)
        {

            var issuers = new string[]
            {
                "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47",
                "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0/",
                "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47",
                "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0/"
            };

            SecurityToken jwtoken;
            var tokenParams = new TokenValidationParameters
            {
                ValidIssuers = issuers,
                ValidateLifetime = false,
                IssuerValidator = CustomIssuerValidator,
                IssuerValidatorUsingConfiguration = null
            };
            try
            {
                var handler = new JwtSecurityTokenHandler().ValidateToken(token, tokenParams, out jwtoken);
            }
            catch (Exception ex)
            { Console.WriteLine(ex); }
        }

        public static string CustomIssuerValidator(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            ;

            return String.Empty;
        }

        public static void Validate(string token)
        {
            var tokenParams = new TokenValidationParameters();
            var claims = new JwtSecurityTokenHandler().ValidateToken(token, tokenParams, out var jwtToken);
        }
    }
}
