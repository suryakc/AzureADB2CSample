using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AADB2C.WebClientMvc
{
    public class Startup
    {
        // These values are pulled from web.config
        public static string AadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string RedirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        public static string SignUpPolicyId = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        public static string SignInPolicyId = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // Configure OpenID Connect middleware for each policy
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignUpPolicyId));
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(ProfilePolicyId));
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignInPolicyId));
        }

        // Used for avoiding yellow-screen-of-death
        private Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }

        private OpenIdConnectAuthenticationOptions CreateOptionsFromPolicy(string policy)
        {
            return new OpenIdConnectAuthenticationOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = String.Format(AadInstance, Tenant, policy),
                AuthenticationType = policy,

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = ClientId,
                RedirectUri = RedirectUri,
                PostLogoutRedirectUri = RedirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = (context) =>
                    {

                        //string uiLocales = context.OwinContext.Get<string>(OpenIdConnectParameterNames.UiLocales);
                        //if (!string.IsNullOrEmpty(uiLocales))
                        //{
                        //    context.ProtocolMessage.Parameters.Add(OpenIdConnectParameterNames.UiLocales, uiLocales);
                        //}
                        context.ProtocolMessage.Parameters.Add(OpenIdConnectParameterNames.UiLocales, "en");
                        Debug.WriteLine("*** RedirectToIdentityProvider");
                        return Task.FromResult(0);
                    },
                    MessageReceived = (context) =>
                    {
                        Debug.WriteLine("*** MessageReceived");
                        return Task.FromResult(0);
                    },
                    SecurityTokenReceived = (context) =>
                    {
                        Debug.WriteLine("*** SecurityTokenReceived");
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = (context) =>
                    {
                        Debug.WriteLine("*** SecurityTokenValidated");
                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = (context) =>
                    {
                        Debug.WriteLine("*** AuthorizationCodeReceived");
                        return Task.FromResult(0);
                    },
                    AuthenticationFailed = AuthenticationFailed
                    //AuthorizationCodeReceived = AuthorizationCodeReceived
                },
                Scope = "openid",
                ResponseType = "id_token",

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    SaveSigninToken = true //important to save the token in boostrapcontext
                }
            };
        }

        private Task AuthorizationCodeReceived(AuthorizationCodeReceivedNotification authorizationCodeReceivedNotification)
        {
            throw new NotImplementedException();
        }
    }
}