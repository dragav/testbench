using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebServerTestBench
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var defaultSchemes = new[]
            {
                CertificateAuthenticationDefaults.AuthenticationScheme,
                BearerTokenAuthenticationDefaults.AuthenticationScheme
            };
            var defaultPolicy = new AuthorizationPolicyBuilder(defaultSchemes)
                .RequireAuthenticatedUser()
                .Build();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApi(Configuration.GetSection("AzureAd"));

            services.AddControllers();

            services.AddMvc(x =>
            {
                x.EnableEndpointRouting = false;
                x.Filters.Add(new AuthorizeFilter(defaultPolicy));
            });

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CertificateAuthenticationDefaults.AuthenticationScheme;
                options.DefaultScheme = BearerTokenAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCertificate(options =>
                {
                    options.AllowedCertificateTypes = CertificateTypes.All;
                    options.RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.ExcludeRoot;
                    options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline;
                    options.Events = new CertificateAuthenticationEvents
                    {
                        OnCertificateValidated = context =>
                        {
                            //var validationService = context.HttpContext.RequestServices
                            //                        .GetRequiredService<ClientCertificateValidationService>();

                            //if (validationService.TryAuthenticateClient(context))
                            {
                                context.Success();
                            }

                            //context.Fail("the presented certificate is not authorized according to the cluster definition");

                            return Task.CompletedTask;
                        }
                    };
                })
                .AddBearerTokenAuthentication(options => { }
                );
            ;
            services.AddAuthorization();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseExceptionHandler(c => c.Run(async context => {
                var exception = context.Features
                    .Get<IExceptionHandlerPathFeature>()
                    .Error;

                var response = JsonConvert.SerializeObject(new { error = exception.Message });
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(response);
            }));

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(builder => builder.MapControllers().RequireAuthorization());
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
