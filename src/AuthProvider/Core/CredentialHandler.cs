using AuthProvider.Core.Credential;
using System.Collections.Generic;

namespace AuthProvider.Core
{
    /// <summary>
    /// Credential handler
    /// </summary>
    public class CredentialHandler
    {
        /// <summary>
        /// User storage
        /// </summary>
        public List<User> UserStorage { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public CredentialHandler()
        {
            UserStorage = new List<User>();
        }
    }
}