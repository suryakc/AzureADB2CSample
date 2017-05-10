using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web;
using System.Web.Http;

namespace AADB2C.Api
{
    public class Startup
    {
        // These values are pulled from web.config
        public static string AadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string SignUpPolicy = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        public static string SignInPolicy = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string EditProfilePolicy = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();

            // web api routes...
            config.MapHttpAttributeRoutes();

            ConfigureOAuth(app);

            app.UseWebApi(config);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            app.UseOAuthBearerAuthentication(CreateBearerOptionsFromPolicy(SignUpPolicy));
            app.UseOAuthBearerAuthentication(CreateBearerOptionsFromPolicy(SignInPolicy));
            app.UseOAuthBearerAuthentication(CreateBearerOptionsFromPolicy(EditProfilePolicy));
        }

        private OAuthBearerAuthenticationOptions CreateBearerOptionsFromPolicy(string policy)
        {
            var metadataEndpoint = string.Format(AadInstance, Tenant, policy);

            TokenValidationParameters tvps = new TokenValidationParameters
            {
                // This is where you specify that your API only accepts tokens from its own clients
                ValidAudience = ClientId,
                AuthenticationType = policy,
                NameClaimType = "http://schemas.microsoft.com/identity/claims/objectidentifier"
            };

            return new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(tvps, new OpenIdConnectCachingSecurityTokenProvider(metadataEndpoint))
            };
        }
    }
}