using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthProvider.Core.Provider
{
    /// <summary>
    /// Authorization Provider
    /// </summary>
    public class AuthorizationProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            return base.GrantRefreshToken(context);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            //a port to pt_BR login and password names
            var data = await context.Request.ReadFormAsync();
            var userName = string.IsNullOrWhiteSpace(data["usuario"]) ? context.UserName : data["usuario"];
            var password = string.IsNullOrWhiteSpace(data["senha"]) ? context.Password : data["senha"];

            var authenticator = Authenticator.GetAuthenticator();
            var authenticatedUser = authenticator.TryAuthenticate(userName, password);

            if (authenticatedUser == null)
            {
                context.SetError("Error", "Invalid login");
                return;
            }

            authenticator.AddUser(authenticatedUser);

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);

            identity.AddClaim(new Claim("ClientID", authenticatedUser.ClientID));
            identity.AddClaim(new Claim("UserID", authenticatedUser.UserID));
            identity.AddClaim(new Claim("User", authenticatedUser.UserName));

            context.Validated(identity);
        }
    }
}