using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using PasswordManager.Models;

namespace PasswordManager.Controllers
{
    [CheckLoginState]
    public class HomeController : Controller
    {
        public ActionResult Login()
        {
            return View("Index");
        }


        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult GetSalt()
        {
            string ReturnSalt = "";

            if (Request["query"] != null)
            {
                var q = Request["query"].ToString();
                if (q == "getmysalt")
                {
                    ReturnSalt = "A83E64C9-8612-4CEE-91C1-08594C1D4B0B";
                }
            }

            return Content(ReturnSalt);
        }

        public ActionResult RedirectToLoginForm()
        { 
            return View("Index");        
        }

        public ActionResult RedirectToLandingPage()
        {
            return View("Landing");
        }

        public string DecodePassword(byte[] dbPassword, string uPasswordhash, byte[] pIVhash)
        {
            using (Aes myAes = Aes.Create())
            {
                byte[] arrayk = Encoding.ASCII.GetBytes(uPasswordhash);
                var decodedPassword = DecryptStringFromBytes_Aes(dbPassword, arrayk, pIVhash);
                return decodedPassword;
            }
        }

        [HttpPost]
        public JsonResult Logout()
        {
            string loggedout = "false";

            Session.RemoveAll();

            loggedout = "true";

            return Json(new { lout = loggedout });
        }

        [HttpPost]
        public JsonResult DeleteRow(string r)
        {
            string rowDeleted = "false";

            if (Session["userid"] != null)
            {
                if (Session["userid"].ToString().Trim() != "")
                {
                    using (var ctx = new PasswordManagerEntities())
                    {
                        var recordToDelete = ctx.Password.SingleOrDefault(x => x.ID.ToString() == r);
                        if (recordToDelete != null)
                        {
                            ctx.Password.Remove(recordToDelete);
                            ctx.SaveChanges();
                            rowDeleted = "true";
                        }
                        else
                        {
                            rowDeleted = "false";
                        }
                    }
                }
            }
            return Json(new { rowisdeleted = rowDeleted });
        }

        [HttpPost]
        public JsonResult UpdateRow(string w,string u, string p, string r, string h)
        {
            string rowUpdated = "false";

            if (Session["userid"] != null)
            {
                if (Session["userid"].ToString().Trim() != "")
                {
                    string original = p;

                    // Create a new instance of the Aes
                    // class.  This generates a new key and initialization 
                    // vector (IV).
                    using (Aes myAes = Aes.Create())
                    {
                        byte[] arrayk = Encoding.ASCII.GetBytes(h);
                        myAes.Key = arrayk;

                        byte[] IVmy = myAes.IV;
                        // Encrypt the string to an array of bytes.
                        byte[] encrypted = EncryptStringToBytes_Aes(original, arrayk, IVmy);

                        // var encryptedPwd = System.Text.Encoding.Default.GetString(encrypted);
                        var strpwdIV = System.Text.Encoding.Default.GetString(IVmy);
                        try
                        {

                            using (PasswordManagerEntities PasswordManagerEntities = new PasswordManagerEntities())
                            {
                                var ur = (from q in PasswordManagerEntities.Password
                                          where (q.ID.ToString() == r.Trim())
                                          select q).SingleOrDefault();

                                ur.Website = w.Trim();
                                ur.UserName = u.Trim();
                                ur.Password1 = encrypted;
                                ur.PasswordHash = h.Trim();
                                ur.PasswordIVHash = IVmy;

                                PasswordManagerEntities.SaveChanges();

                                rowUpdated = "true";
                            }
                        }
                        catch (Exception exp)
                        {
                        }
                        // Decrypt the bytes to a string.
                        //string roundtrip = DecryptStringFromBytes_Aes(encrypted,myAes.Key, myAes.IV);
                    }
                }
            }

            return Json(new { rowisupdated = rowUpdated });
        }

        [HttpPost]
        public JsonResult Search(string sf)
        {
            int userID = Convert.ToInt32(Session["userid"].ToString());
            PasswordManagerEntities PasswordManagerEntities = new PasswordManagerEntities();
            var plist = PasswordManagerEntities.Password.Where(f=>f.Website.Contains(sf.Trim())&&(f.UserID == userID)).Select(x => new Models.StoredPassword
            {
                ID = x.ID,
                UserID = x.UserID,
                Website = x.Website,
                UserName = x.UserName,
                Password1 = x.Password1,
                PasswordHash = x.PasswordHash,
                PasswordIVHash = x.PasswordIVHash
            }).ToList();


            List<DecodedPassword> decodedPasswordList = new List<DecodedPassword>();

            foreach (var i in plist)
            {
                decodedPasswordList.Add(new DecodedPassword
                {
                    ID = i.ID,
                    UserID = i.UserID,
                    Website = i.Website,
                    UserName = i.UserName,
                    Password1 = new string(DecodePassword(i.Password1, i.PasswordHash, i.PasswordIVHash).Where(c => !char.IsControl(c)).ToArray()),
                    PasswordHash = i.PasswordHash,
                    PasswordIVHash = i.PasswordIVHash
                });
            }

            return Json(decodedPasswordList, JsonRequestBehavior.AllowGet);
        }

        [HttpPost]
        public JsonResult GetAllStoredPasswords()
        {
            int userID = Convert.ToInt32(Session["userid"].ToString());

            PasswordManagerEntities PasswordManagerEntities = new PasswordManagerEntities();
            var plist = PasswordManagerEntities.Password.Where(g=>g.UserID == userID).Select(x => new Models.StoredPassword
            {
                ID = x.ID,
                UserID = x.UserID,
                Website = x.Website,
                UserName = x.UserName,
                Password1 = x.Password1,
                 PasswordHash = x.PasswordHash,
                 PasswordIVHash = x.PasswordIVHash
            }).ToList();


            List<DecodedPassword> decodedPasswordList = new List<DecodedPassword>();

            foreach (var i in plist)
            {
                decodedPasswordList.Add(new DecodedPassword {
                    ID =i.ID,
                    UserID =i.UserID,
                    Website =i.Website,
                    UserName =i.UserName,
                    Password1 = new string(DecodePassword(i.Password1, i.PasswordHash, i.PasswordIVHash).Where(c => !char.IsControl(c)).ToArray()),
                    PasswordHash =i.PasswordHash,
                    PasswordIVHash =i.PasswordIVHash });
            }

            return Json(decodedPasswordList, JsonRequestBehavior.AllowGet);
        }

        [HttpPost]
        public JsonResult AddNewPassword(string w, string u, string p,string h )
        {
            string addnewpwdsuccess = "false";

            try
            {
                string original = p;

                // Create a new instance of the Aes
                // class.  This generates a new key and initialization 
                // vector (IV).
                using (Aes myAes = Aes.Create())
                {
                    byte[] arrayk = Encoding.ASCII.GetBytes(h);
                    myAes.Key = arrayk;

                    byte[] IVmy = myAes.IV;
                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes_Aes(original, arrayk, IVmy);

                    // var encryptedPwd = System.Text.Encoding.Default.GetString(encrypted);
                    var strpwdIV = System.Text.Encoding.Default.GetString(IVmy);
                    try
                    {
                        PasswordManagerEntities db = new PasswordManagerEntities();
                        PasswordManager.Password passwd = new PasswordManager.Password
                        {
                            UserID = Convert.ToInt32(Session["userid"].ToString()),
                            Website = w.Trim(),
                            UserName = u.Trim(),
                            Password1 = encrypted,
                            PasswordHash  = h.Trim(),
                            PasswordIVHash= IVmy
                        };

                        db.Password.Add(passwd);
                        db.SaveChanges();
                        addnewpwdsuccess = "true";
                    }
                    catch (Exception exp)
                    {
                    }
                    // Decrypt the bytes to a string.
                    //string roundtrip = DecryptStringFromBytes_Aes(encrypted,myAes.Key, myAes.IV);
                }
            }
            catch (Exception e)
            {
            }
            return Json(new { addnewpasswordstatus = addnewpwdsuccess });
        }

        [HttpPost]
        public JsonResult LogInUser(string userName, string password)
        {
            PasswordManagerEntities PasswordManagerEntities = new PasswordManagerEntities();

            var user = (from u in PasswordManagerEntities.User
                              where ((u.UserName == userName))
                              select u).SingleOrDefault();

            string authsuccess = "f";

            if (user != null)
            {
                //check password
                using (Aes myAes = Aes.Create())
                {
                    byte[] arrayk = Encoding.ASCII.GetBytes(user.UPassHash);

                    // Decrypt the bytes to a string.
                    var roundtrip = DecryptStringFromBytes_Aes(user.UPasswrd, arrayk, user.UPassIVHash);
                    string output = new string(roundtrip.Where(c => !char.IsControl(c)).ToArray());

                    if (output.Trim() == password.Trim())
                    {
                        authsuccess = "t";
                        Session["userid"] = user.ID.ToString();
                    }
                    else
                    {
                        authsuccess = "f";
                    }
                }
                
                
            }
        
            return Json(new { loginsuccess = authsuccess });
        }

        [HttpPost]
        public JsonResult RegisterNewUser(string firstname, string lastname, string username,string upassword, string pHash)
        {

            //https://msdn.microsoft.com/en-us/library/system.security.cryptography.aes(v=vs.110).aspx
            string authsuccess = "false";
            try
            {
                string original = upassword;

                // Create a new instance of the Aes
                // class.  This generates a new key and initialization 
                // vector (IV).
                using (Aes myAes = Aes.Create())
                {
                    byte[] arrayk = Encoding.ASCII.GetBytes(pHash);
                    myAes.Key = arrayk;

                    byte[] IVmy = myAes.IV;
                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes_Aes(original, arrayk, IVmy);

                   // var encryptedPwd = System.Text.Encoding.Default.GetString(encrypted);
                    var strpwdIV = System.Text.Encoding.Default.GetString(IVmy);
                    try
                    {
                        PasswordManagerEntities db = new PasswordManagerEntities();
                        PasswordManager.User user = new PasswordManager.User
                        {
                            FirstName = firstname.Trim(),
                            LastName = lastname.Trim(),
                            UserName = username.Trim(),
                            UPasswrd = encrypted,
                            UPassHash = pHash.Trim(),
                            UPassIVHash = IVmy

                        };

                        db.User.Add(user);
                        db.SaveChanges();
                        authsuccess = "true";
                    }
                    catch (Exception exp)
                    {

                    }

                    // Decrypt the bytes to a string.
                    //string roundtrip = DecryptStringFromBytes_Aes(encrypted,myAes.Key, myAes.IV);
                }
            }
            catch (Exception e)
            {
                
            }

            return Json(new { regsuccess = authsuccess });
        }




        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key,byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting 
                            //stream
                            // and place them in a string.
                                                        plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}