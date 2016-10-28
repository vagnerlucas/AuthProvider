using System;
using System.Web;
using System.Web.Mvc;

namespace AuthProvider.Core.Filters.MVC
{
    /// <summary>
    /// MVC Filter to provide authorization
    /// </summary>
    public class MVCAuthorize : AuthorizeAttribute
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="filterContext"></param>
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            throw new NotImplementedException("Need implementation");
            //base.OnAuthorization(filterContext);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="httpContext"></param>
        /// <returns></returns>
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            throw new NotImplementedException("Need implementation");
            //return base.AuthorizeCore(httpContext);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filterContext"></param>
        protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
        {
            throw new NotImplementedException("Need implementation");
            //base.HandleUnauthorizedRequest(filterContext);
        }
    }
}