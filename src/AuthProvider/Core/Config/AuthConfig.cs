using AuthProvider.Core.Credential;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthProvider.Core.Config
{
    /// <summary>
    /// Authenticator configuration
    /// </summary>
    public class AuthConfig
    {
        /// <summary>
        /// Application Client ID
        /// </summary>
        public string ClientID { get; set; }

        /// <summary>
        /// Allow insecure connections (default: false)
        /// </summary>
        public bool AllowInsecureConnection { get; set; } = false;

        /// <summary>
        /// URL to authenticate and provide token
        /// </summary>
        public string TokenGeneratorUrlPath { get; set; } = "/token";

        /// <summary>
        /// Time interval (in minutes) for the token life
        /// </summary>
        public int TokenExpirationInterval { get; set; }

        /// <summary>
        /// Function for authentication
        /// </summary>
        public Func<string, string, string, User> AuthenticationFunction { get; set; }

        /// <summary>
        /// Function for async authentication
        /// </summary>
        public Func<string, string, string, Task<User>> AuthenticationFunctionAsync { get; set; }

        /// <summary>
        /// Function for authorization
        /// </summary>
        internal Func<bool> AuthorizationFunction { get; set; }

        /// <summary>
        /// Type of authorizations to use on controller filter
        /// </summary>
        public AuthorizationTypeEnum AuthorizationType { get; set; } = AuthorizationTypeEnum.Roles;

        /// <summary>
        /// External function to authorize depending on client's logic
        /// </summary>
        public Func<string, User, bool> ExternalAuthorizationFunction { get; set; }

        /// <summary>
        /// External dictionary to be added to token endpoint
        /// </summary>
        public Func<Dictionary<string, object>> ExternalResponseParametersFunction { get; set; }
    }
}
