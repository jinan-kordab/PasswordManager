using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace PasswordManager.Views.Home
{
    public partial class GetSalt : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string ReturnSalt = "";

            if (Request["query"] != null)
            {
                var q = Request["query"].ToString();
                if (q == "getmysalt")
                {
                    ReturnSalt = "DEEA7503-EEA7-46D3-8396-11BC701BC70C";
                }
            }

            Response.Write(ReturnSalt);
        }
    }
}