using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace PasswordManager.Controllers
{
    public class CheckLoginStateAttribute : System.Web.Mvc.ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {

            string actionName = filterContext.ActionDescriptor.ActionName;
            string controllerName = filterContext.ActionDescriptor.ControllerDescriptor.ControllerName;

            if (actionName == "Login" || actionName== "LogInUser" || actionName== "RegisterNewUser" || actionName== "GetSalt")
            {

            }
            else
            {
                if (filterContext.HttpContext.Session.Keys.Count == 0)
                {
                    var controller = (HomeController)filterContext.Controller;
                    filterContext.Result = controller.Login();
                }
            }
            
        }
    }
}