using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProvider.Core.Provider
{
    /// <summary>
    /// Refresh token provider
    /// source: http://www.c-sharpcorner.com/UploadFile/ff2f08/angularjs-enable-owin-refresh-tokens-using-asp-net-web-api/
    /// </summary>
    public class RefreshTokenProvider : IAuthenticationTokenProvider
    {
        private static ConcurrentDictionary<string, AuthenticationTicket> _refreshTokens = new ConcurrentDictionary<string, AuthenticationTicket>();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var authenticator = Authenticator.GetAuthenticator();
            var minutes = authenticator.Configuration.TokenExpirationInterval;

            var user = context.Ticket.Identity;
            var clientID = user.Claims.Where(w => w.Type == "ClientID").FirstOrDefault().Value;
            var userID = user.Claims.Where(w => w.Type == "UserID").FirstOrDefault().Value;
            var userName = user.Claims.Where(w => w.Type == "User").FirstOrDefault().Value;

            try
            {
                var authenticatedUser = await Task.Run(() => { return authenticator.GetUser(clientID, userID, userName); });
            }
            catch (Exception ex)
            {
                throw new Exception($"Could not authenticate. Details: {ex.Message}"); ;
            }

            var guid = Guid.NewGuid().ToString();

            // copy all properties and set the desired lifetime of refresh token  
            var refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary)
            {
                IssuedUtc = context.Ticket.Properties.IssuedUtc,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(minutes)
            };

            var refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);

            _refreshTokens.TryAdd(guid, refreshTokenTicket);

            // consider storing only the hash of the handle  
            context.SetToken(guid);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            AuthenticationTicket ticket;
            await Task.Run(() =>
            {
                string header = context.OwinContext.Request.Headers["Authorization"];

                context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

                if (_refreshTokens.TryRemove(context.Token, out ticket))
                {
                    context.SetTicket(ticket);
                }
            });
        }
    }
}
