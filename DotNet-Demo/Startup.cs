using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using RingCentral;
using Newtonsoft.Json;
using RingCentral.Net.AuthorizeUri;

namespace DotNet_Demo
{
    public class Startup
    {
        static RestClient restClient;
        private const string SESSION_TOKEN_KEY = "rc-token";
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().AddSessionStateTempDataProvider();
            services.AddSession();
        }

        private static string Html(string body)
        {
            return $@"<!doctype html><html><body>{body}</body></html>";
        }

        public void Configure(IApplicationBuilder app, Microsoft.AspNetCore.Hosting.IHostingEnvironment env)
        {
            if (env.IsDevelopment()) app.UseDeveloperExceptionPage();
            app.UseSession();
            var clientId = Environment.GetEnvironmentVariable("RC_CLIENT_ID");
            var clientSecret = Environment.GetEnvironmentVariable("RC_CLIENT_SECRET");
            var serverUrl = Environment.GetEnvironmentVariable("RC_SERVER_URL");
            var redirectUrl = Environment.GetEnvironmentVariable("RC_REDIRECT_URL");
            restClient = new RestClient(clientId, clientSecret, serverUrl);
            var authorizeUriExtension = new AuthorizeUriExtension(null);
            app.Run(async (context) =>
            {
                var tokenString = context.Session.GetString(SESSION_TOKEN_KEY);
                await restClient.InstallExtension(authorizeUriExtension);
                if (tokenString != null)
            {
                restClient.token = JsonConvert.DeserializeObject<TokenInfo>(tokenString);
            }
            else if (context.Request.Path != "/oauth2callback")
            {
                var authRequest = new AuthorizeRequest();
                authRequest.redirect_uri = redirectUrl;
                //authRequest.code_challenge_method = "S256";
                var oauthUri = authorizeUriExtension.BuildUri(authRequest);
                await context.Response.WriteAsync(Html($"<h2>RingCentral Authorization Code Flow Authentication</h2><a href=\"{oauthUri}\">Login RingCentral Account</a>"));
                return;
            }

            switch (context.Request.Path)
            {
                case "/":
                    await context.Response.WriteAsync(Html(@"<b><a href=""logout"">Logout</a></b>
                            <h2> Call APIs </h2>
                            <ul>
                                <li><a href =""/test?api=extension"" target=""_blank"">Read Extension Info</a></li>
                                <li><a href =""/test?api=extension-call-log"" target=""_blank"">Read Extension Call Log</a></li>
                                <li><a href =""/test?api=account-call-log"" target=""_blank"">Read Account Call Log</a></li>
                            </ul>"
                    ));
                    break;
                case "/oauth2callback":
                    context.Request.Query.TryGetValue("code", out var codes);
                    var code = codes.First();
                    //var tokenReuest = new GetTokenRequest();
                    //tokenReuest.code_verifier = authorizeUriExtension.CodeVerifier;
                    //tokenReuest.code = code;
                    //tokenReuest.redirect_uri = redirectUrl;
                    //tokenReuest.client_id = clientId;
                    //tokenReuest.grant_type = "authorization_code";
                    //await restClient.Authorize(tokenReuest);
                    await restClient.Authorize(code, redirectUrl);
                    context.Session.SetString(SESSION_TOKEN_KEY, JsonConvert.SerializeObject(restClient.token));
                    context.Response.Redirect("/");
                    break;
                case "/test":
                    context.Request.Query.TryGetValue("api", out var apis);
                    var api = apis.First();
                    var result = "";
                    switch (api)
                    {
                        case "extension":
                            result = await restClient.Get<string>("/restapi/v1.0/account/~/extension");
                            break;
                        case "extension-call-log":
                            result = await restClient.Get<string>("/restapi/v1.0/account/~/extension/~/call-log");
                            break;
                        case "account-call-log":
                            result = await restClient.Get<string>("/restapi/v1.0/account/~/call-log");
                            break;
                    }

                    await context.Response.WriteAsync(Html($"<pre>{result}</pre>"));
                    break;
                case "/logout":
                    await restClient.Revoke();
                    context.Session.Remove(SESSION_TOKEN_KEY);
                    context.Response.Redirect("/");
                    break;
                default:
                    context.Response.StatusCode = 404;
                    break;
            }
            });
        }
    }
}
