# AuthProvider
WEB API/MVC Authenticator provider 
Owin and Oauth provider for C# .NET web applications

# Usage:

**Packages needed**:

Microsoft.AspNet.Cors

Microsoft.AspNet.WebApi.Owin

Microsoft.Owin.Host.SystemWeb

Microsoft.Owin.Cors


**Configure the authenticator in Global.asax.cs**
```C#
// Global.asax.cs
//...

protected void Application_Start()
        {
            GlobalConfiguration.Configure(WebApiConfig.Register);
            var autenticador = Authenticator.GetAuthenticator();
            autenticador.Configuration = new AuthConfig()
            {
                AllowInsecureConnection = true, //Allows clients to connect through simple http connections
                TokenExpirationInterval = 30, //Expiration token interval (in minutes)
                TokenGeneratorUrlPath = "/token", //Token generator URL
                ClientID = "MyApplicationID", //Application ID
                AuthorizationType = AuthorizationTypeEnum.Group, //Authorization type
                AuthenticationFunction = Authenticate // Authentication Function
            };
        }

        // Use your own authentication logic here
        // On this case, I'm using my DbContext (EF) to verify the credentials

        private User Authenticate(string login, string passwd)
        {
           if (String.IsNullOrWhiteSpace(login) || String.IsNullOrWhiteSpace(passwd))
                return null;

            //Using my context 
            using (var entities = new Entities())
            {
                UnitOfWork<Entities> unitOfWork = new UnitOfWork<Entities>(entities);
                var eUser = unitOfWork.GetRepository<USER>().List().FirstOrDefault(w => w.LOGIN == login && w.PASSWD == passwd);

                if (eUser == null)
                    return null;

                User user = new User();
                user.ClientID = "MyApplicationID";
                user.UserID = eUser.ID_USER.ToString();
                user.UserName = eUser.USER_NAME;
                user.Profile = new UserProfile() { Groups = new String[] { eUser.PROFILE.CODE_NAME } };
                return user;
            }
        }

```

Now use its WEBAPI Filter 
```C#
  [WebAPIAuthorize]
  public class MyController: ApiController { 
  
    [HttpGet]
    //Considering the CODE_NAME of the groups
    [WebAPIAuthorize(Groups = "ADM, CLI")] 
    public IHttpActionResult Test() {
      var autenticador = Authenticator.GetAuthenticator();
      //The authenticated and authorized user
      var user = authenticator.CurrentUser; 
      //... code
    }
  
  }
```
