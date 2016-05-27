using AuthProvider.Core.Credential;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace AuthProvider.Core.Filters.WebAPI
{
    /// <summary>
    /// Web API filter to provide authorization
    /// </summary>
    public class WebAPIAuthorize : AuthorizeAttribute
    {
        /// <summary>
        /// Default error message
        /// </summary>
        private string message = "Access is denied";

        /// <summary>
        /// Default error code
        /// </summary>
        private HttpStatusCode statusCode = HttpStatusCode.Forbidden;

        /// <summary>
        /// Groups allowed to access
        /// </summary>
        public string Groups { get; set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="actionContext"></param>
        /// <returns></returns>
        private bool IsApiPageRequested(HttpActionContext actionContext)
        {
            var apiAttributes = GetApiAuthorizeAttributes(actionContext.ActionDescriptor);
            if (apiAttributes != null && apiAttributes.Any())
                return true;
            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="descriptor"></param>
        /// <returns></returns>
        private IEnumerable<WebAPIAuthorize> GetApiAuthorizeAttributes(HttpActionDescriptor descriptor)
        {
            return descriptor.GetCustomAttributes<WebAPIAuthorize>(true)
                .Concat(descriptor.ControllerDescriptor.GetCustomAttributes<WebAPIAuthorize>(true));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="actionContext"></param>
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="actionContext"></param>
        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            actionContext.Response = actionContext.Request.CreateResponse(statusCode, message);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="actionContext"></param>
        /// <returns></returns>
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            try
            {
                var user = GetRequestUser(actionContext);
                var authenticator = Authenticator.GetAuthenticator();

                if (user != null)
                {
                    if (user.IsAuthenticated)
                    {
                        authenticator.Configuration.AuthorizationFunction = CreateAuthorizationFunction(user, actionContext);

                        var accessAllowed = authenticator.CanAuthorize();

                        if (!accessAllowed)
                        {
                            message = "Access is denied";
                            statusCode = HttpStatusCode.Unauthorized;
                            HandleUnauthorizedRequest(actionContext);
                            return false;
                        }

                        if (actionContext.Request.Headers.Authorization.Scheme == "bearer")
                        {
                            var authorizationToken = actionContext.Request.Headers.Authorization.Parameter;
                            user.Token = authorizationToken;
                        }

                        authenticator.CurrentUser = user;
                        return true;
                    }
                }

                var windowsIdentity = actionContext.RequestContext.Principal.Identity as WindowsIdentity;

                if (windowsIdentity.IsAnonymous)
                    message = "Login is required";

                if (windowsIdentity.Token == null)
                    message = "Token is null or expired";

                statusCode = HttpStatusCode.Forbidden;

                if (actionContext.Request.Headers.Authorization != null)
                    if (actionContext.Request.Headers.Authorization.Scheme == "bearer")
                    {
                        var authorizationToken = actionContext.Request.Headers.Authorization.Parameter;
                        var userToExclude = authenticator.CredentialHandler.UserStorage.FirstOrDefault(w => w.Token == authorizationToken);
                        if (userToExclude != null)
                            authenticator.RemoveUser(userToExclude);
                    }

                return false;

            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Creates the authorization function based on the AuthenticationType
        /// </summary>
        /// <param name="user">Authenticated user</param>
        /// <param name="actionContext">ActionContext</param>
        /// <returns>Bool function</returns>
        internal Func<bool> CreateAuthorizationFunction(User user, HttpActionContext actionContext)
        {
            var authenticator = Authenticator.GetAuthenticator();
            var apiAttributes = GetApiAuthorizeAttributes(actionContext.ActionDescriptor);
            var result = false;

            if (apiAttributes != null && apiAttributes.Any())
            {
                switch (authenticator.Configuration.AuthorizationType)
                {
                    case AuthorizationTypeEnum.Group:
                        var groups = apiAttributes.Select(w => w.Groups).FirstOrDefault();
                        if (groups != null)
                            foreach (var group in groups.Split(','))
                            {
                                if (user.Profile != null)
                                    if (user.Profile.Groups.Contains(group.Trim()))
                                    {
                                        result = true;
                                        break;
                                    };
                            }
                        break;
                    case AuthorizationTypeEnum.Resources:
                        throw new NotImplementedException("Not implemented");
                    //break;
                    case AuthorizationTypeEnum.Roles:
                        result = apiAttributes.FirstOrDefault(w => w.Roles != null && w.Roles == (user.Profile != null ? user.Profile.Role : string.Empty)) != null;
                        break;
                    default:
                        throw new ArgumentException("Invalid argument: AuthorizationType not found");
                }
            }

            return () => { return result; };
        }

        /// <summary>
        /// Gets the requested user by context
        /// </summary>
        /// <param name="actionContext">ActionContext</param>
        /// <returns>Authenticated user</returns>
        protected User GetRequestUser(HttpActionContext actionContext)
        {
            var authenticator = Authenticator.GetAuthenticator();
            try
            {
                var user = actionContext.RequestContext.Principal as ClaimsPrincipal;

                if (user.Identity.IsAuthenticated)
                {
                    var clientID = user.Claims.Where(w => w.Type == "ClientID").FirstOrDefault().Value;
                    var userID = user.Claims.Where(w => w.Type == "UserID").FirstOrDefault().Value;
                    var userName = user.Claims.Where(w => w.Type == "User").FirstOrDefault().Value;
                    var authenticatedUser = authenticator.GetUser(clientID, userID, userName);

                    return authenticatedUser;
                }

                return null;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}

