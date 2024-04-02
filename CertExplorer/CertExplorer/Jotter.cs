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
        public static void Validate(string token)
        {
            var tokenParams = new TokenValidationParameters();
            var claims = new JwtSecurityTokenHandler().ValidateToken(token, tokenParams, out var jwtToken);
        }
    }
}
