using AuthProvider.Core.Config;
using AuthProvider.Core.Credential;
using System;
using System.Linq;
using System.Threading;

namespace AuthProvider.Core
{
    /// <summary>
    /// Type of authorizations
    /// </summary>
    public enum AuthorizationTypeEnum {
        /// <summary>
        /// Group policy
        /// </summary>
        Group,
        /// <summary>
        /// Resources policy
        /// </summary>
        Resources,
        /// <summary>
        /// Role policy
        /// </summary>
        Roles
    }

    /// <summary>
    /// Authenticator
    /// </summary>
    public class Authenticator
    {

        /// <summary>
        /// Activity checker
        /// </summary>
        private Thread activityChecker;

        /// <summary>
        /// Flush Users from credential storage with no recent activities
        /// </summary>
        private void FlushStatus()
        {
            if (CredentialHandler.UserStorage.Count > 0)
            {
                CredentialHandler.UserStorage.ForEach(w =>
                {
                    if (w.LastActivity.Minute - DateTime.Now.Minute < Configuration.TokenExpirationInterval)
                        RemoveUser(w);
                });
            }
            Thread.Sleep(TimeSpan.FromMinutes(1));
        }

        /// <summary>
        /// Credential Handler
        /// </summary>
        internal CredentialHandler CredentialHandler { get; set; }

        /// <summary>
        /// Singleton instance
        /// </summary>
        private static volatile Authenticator _instance;
        private static object syncRoot = new Object();

        /// <summary>
        /// Authenticator configuration
        /// </summary>
        public AuthConfig Configuration { get; set; }

        /// <summary>
        /// Current user authenticated and authorized by filter
        /// </summary>
        public User CurrentUser { get; set; }

        /// <summary>
        /// Singleton
        /// </summary>
        private Authenticator()
        {
            CredentialHandler = new CredentialHandler();
            activityChecker = new Thread(FlushStatus);
            activityChecker.Start();
        }

        /// <summary>
        /// Add a authenticated user to the credential handler
        /// </summary>
        /// <param name="user">Authenticated user</param>
        public void AddUser(User user)
        {
            user.IsAuthenticated = true;

            var userTmp = CredentialHandler.UserStorage.FirstOrDefault(w => w.ClientID == user.ClientID && w.UserID == user.UserID && w.UserName == user.UserName);

            if (userTmp != null)
                CredentialHandler.UserStorage.Remove(userTmp);

            CredentialHandler.UserStorage.Add(user);
        }

        /// <summary>
        /// Remove a authenticated user to the credential handler
        /// </summary>
        /// <param name="user">Authenticated user</param>
        public void RemoveUser(User user)
        {
            user.IsAuthenticated = false;
            CredentialHandler.UserStorage.Remove(user);
        }

        /// <summary>
        /// Singleton
        /// </summary>
        /// <returns>Default Authenticator instance</returns>
        public static Authenticator GetAuthenticator()
        {
            if (_instance == null)
                lock (syncRoot)
                    _instance = _instance ?? new Authenticator();

            return _instance;
        }

        /// <summary>
        /// If the authenticator can authorize based upon authorize function
        /// </summary>
        /// <returns></returns>
        public bool CanAuthorize()
        {
            return Configuration.AuthorizationFunction();
        }

        /// <summary>
        /// Try to authenticate based upon the authentication function previously provided
        /// </summary>
        /// <param name="user">User name / Login</param>
        /// <param name="password">Password</param>
        /// <returns>Authenticated user</returns>
        public User TryAuthenticate(string user, string password)
        {
            if (Configuration == null)
                throw new NullReferenceException("Invalid or null configuration");

            return Configuration.AuthenticationFunction(user, password);
        }

        /// <summary>
        /// Gets the user from the credential handler
        /// </summary>
        /// <param name="clientID">Application Client ID</param>
        /// <param name="userID">User ID</param>
        /// <param name="userName">User name</param>
        /// <returns></returns>
        internal User GetUser(string clientID, string userID, string userName)
        {
            if (Configuration.ClientID != clientID)
                throw new ArgumentException("Invalid Client ID");

            return CredentialHandler.UserStorage.FirstOrDefault(w => w.ClientID == clientID && w.UserID == userID && w.UserName == userName);
        }
    }
}

