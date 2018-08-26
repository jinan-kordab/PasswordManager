using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace PasswordManager.Models
{
    public class DecodedPassword
    {
        public int ID { get; set; }
        public int UserID { get; set; }
        public string Website { get; set; }
        public string UserName { get; set; }
        public string Password1 { get; set; }
        public string PasswordHash { get; set; }
        public byte[] PasswordIVHash { get; set; }
    }
}