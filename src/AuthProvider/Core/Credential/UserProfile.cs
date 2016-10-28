using System.Collections.Generic;

namespace AuthProvider.Core.Credential
{
    /// <summary>
    /// The user profile definitions
    /// </summary>
    public class UserProfile
    {
        /// <summary>
        /// Roles
        /// </summary>
        public string Role { get; set; }

        /// <summary>
        /// Groups
        /// </summary>
        public IEnumerable<string> Groups { get; set; }

        /// <summary>
        /// Resources
        /// </summary>
        public IEnumerable<Dictionary<string, Dictionary<string, string>>> Resources { get; set; }
    }
}
