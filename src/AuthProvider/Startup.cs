using AuthProvider.Core;
using AuthProvider.Core.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Web.Http;

[assembly: OwinStartup(typeof(AuthProvider.Startup))]
namespace AuthProvider
{
    /// <summary>
    /// OwinStartup class
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="app"></param>
        public virtual void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();
            ConfigureOAuth(app);
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(config);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="app"></param>
        public void ConfigureOAuth(IAppBuilder app)
        {
            var authenticator = Authenticator.GetAuthenticator();
            var minutes = authenticator.Configuration.TokenExpirationInterval;
            var path = authenticator.Configuration.TokenGeneratorUrlPath;
            var allowInsecure = authenticator.Configuration.AllowInsecureConnection;

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = allowInsecure,
                TokenEndpointPath = new PathString(path),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(minutes),
                Provider = new AuthorizationProvider(),
                RefreshTokenProvider = new RefreshTokenProvider()
            };

            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

        }
    }
}
