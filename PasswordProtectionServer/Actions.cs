using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace PasswordProtectionServer
{
    class Actions
    {

        public static string PCSwitch(string Username, string Password)
        {
            if (DbAction.IsUsernameInDatabase(Username))
            {
                if (Password == Crypto.Decrypt(DbAction.GetPasswordByUser(Username), Username))
                {
                    return Crypto.MakeHash(Password);
                }
            }

            return string.Empty;
        }

        public static bool PWChange(string Username, string PasswordOld, string PasswordNew)
        {
            if (DbAction.IsUsernameInDatabase(Username))
            {
                if (Crypto.Encrypt(PasswordOld, Username) == Crypto.Decrypt(DbAction.GetPasswordByUser(Username), Username))
                {
                    DbAction.ChangePassword(Username, Crypto.Encrypt(PasswordOld, Username));
                    Email(Username, "Password Changed to: " + PasswordNew);
                    return true;
                }
            }

            return false;
        }

        public static void PWRecovery(string Username)
        {
            if (DbAction.IsUsernameInDatabase(Username))
            {
                var dbPassword = DbAction.GetPasswordByUser(Username);
                Email(Username, Crypto.Decrypt(dbPassword, Username));
            }
        }

        public static bool Registration(string Username, string Password)
        {
            if (!DbAction.IsUsernameInDatabase(Username))
            {
                try { DbAction.AddNewUser(Username, Crypto.Encrypt(Password, Username)); }
                catch { return false; }
            }
            else
                return false;

            return true;
        }

        public static void Email(string Email, string password)
        {
            try
            {
                MailMessage message = new MailMessage();
                SmtpClient smtp = new SmtpClient();
                message.From = new MailAddress("FromMailAddress");//Removed Actual Email for safety reasons
                message.To.Add(new MailAddress(Email));
                message.Subject = "Test";
                message.IsBodyHtml = true; //to make message body as html  
                message.Body = password;
                smtp.Port = 587;
                smtp.Host = "smtp.gmail.com"; //for gmail host  
                smtp.EnableSsl = true;
                smtp.UseDefaultCredentials = false;
                smtp.Credentials = new NetworkCredential("FromMailAddress", "password");//Removed Actual Email for safety reasons
                smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
                smtp.Send(message);
            }
            catch (Exception) { }
        }
    }
}