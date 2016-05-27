namespace AuthProvider.Core.Credential
{
    /// <summary>
    /// Authenticated user credential
    /// </summary>
    public class User
    {
        /// <summary>
        /// Token of the last request
        /// </summary>
        internal string Token { get; set; }

        /// <summary>
        /// The authenticate state of the user
        /// </summary>
        internal bool IsAuthenticated { get; set; }

        /// <summary>
        /// User name
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// User ID
        /// </summary>
        public string UserID { get; set; }

        /// <summary>
        /// Application ID
        /// </summary>
        public string ClientID { get; set; }

        /// <summary>
        /// User profile
        /// </summary>
        public UserProfile Profile { get; set; }
    }
}
