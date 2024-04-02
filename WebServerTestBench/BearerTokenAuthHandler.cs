// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace WebServerTestBench
{
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.Extensions.Primitives;
    using System;
using System.Security.AccessControl;
    using System.Security.Claims;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;

    public static class BearerTokenAuthenticationDefaults
    {
        public const string AuthenticationScheme = "BearerToken";
        public const string BearerTokenHeaderName = "Secret";
    }

    public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string AuthenticationScheme { get; set; } = BearerTokenAuthenticationDefaults.AuthenticationScheme;

        public string BearerTokenHeaderName { get; set; } = BearerTokenAuthenticationDefaults.BearerTokenHeaderName;

        public string BearerToken { get; set; }
    }

    public static class BearerTokenAuthenticationExtensions
    {
        public static AuthenticationBuilder AddBearerTokenAuthentication(this AuthenticationBuilder builder, Action<BearerTokenAuthenticationOptions> configureOptions)
        {
            builder.AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
                BearerTokenAuthenticationDefaults.AuthenticationScheme,
                "SF custom bearer token authentication",
                configureOptions);

            return builder;
        }
    }

    public sealed class BearerTokenAuthenticationHandler : AuthenticationHandler<BearerTokenAuthenticationOptions>
    {
        public BearerTokenAuthenticationHandler(
            IOptionsMonitor<BearerTokenAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
//            string correlationId = String.Empty;
//            if (Context.Request.Headers.TryGetValue(Consts.Headers.CorrelationIdParent, out StringValues values))
//            {
//                correlationId = values[0];
//            }
//            if (String.IsNullOrWhiteSpace(correlationId))
//            {
//                correlationId = Guid.NewGuid().ToString();
//                Context.Request.Headers.Add(Consts.Headers.CorrelationIdParent, new StringValues(correlationId));
//}

//            var traceType = new TraceType(nameof(BearerTokenAuthenticationHandler) + "@" + correlationId);

//            if (!Context.Request.Headers.TryGetValue(Consts.Headers.Secret, out StringValues secrets)
//                || secrets.Count < 1)
//            {
//                return Task.FromResult(AuthenticateResult.NoResult());
//            }

//            if (secrets.Count > 1)
//            {
//                return Task.FromResult(AuthenticateResult.Fail($"expected a single token for header '{Consts.Headers.Secret}'; multiple values were found."));
//            }

//            string token = secrets[0];
//            if (String.IsNullOrWhiteSpace(token))
//            {
//                return Task.FromResult(AuthenticateResult.Fail($"expected a single token for header '{Consts.Headers.Secret}'; multiple values were found."));
//            }

//            if (!_tokenValidator.TryValidateToken(token, out string appHostId, out string description))
//            {
//                return Task.FromResult(AuthenticateResult.Fail($"token validation failed: {description}"));
//            }


            var id = new ClaimsIdentity(BearerTokenAuthenticationDefaults.AuthenticationScheme);
            id.AddClaim(new Claim("role", "user"));
            id.AddClaim(new Claim("sub", "blah"));
            var principal = new ClaimsPrincipal(id);
            var ticket = new AuthenticationTicket(principal, Options.AuthenticationScheme);

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
