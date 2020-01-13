using System;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace PasswordProtectionServer
{
    class Program
    {
        static void Main(string[] args)
        {
            string certificate = "F:\\C#_Projects\\Crypto\\TestCerts\\localhost.cer";

            serverCertificate = X509Certificate.CreateFromCertFile(certificate);
            // Create a TCP/IP (IPv4) socket and listen for incoming connections.
            TcpListener listener = new TcpListener(IPAddress.Any, 8080);
            listener.Start();
            while (true)
            {
                Console.WriteLine("Waiting for a client to connect...");
                // Application blocks while waiting for an incoming connection.
                // Type CNTL-C to terminate the server.
                TcpClient client = listener.AcceptTcpClient();
                ProcessClient(client);
            }
        }

        static X509Certificate serverCertificate = null;
        // The certificate parameter specifies the name of the file 
        // containing the machine certificate.

        static bool checkOccurance(string pattern, string data)
        {
            Regex obj = new Regex(pattern);
            return obj.IsMatch(data);
        }

        /// <summary>
        /// Utility function that creates a regex object and matches the given pattern to the given data.
        /// </summary>
        /// <param name="pattern">Regex pattern to be matched</param>
        /// <param name="data">Data/Message to be matched against the regex pattern</param>
        /// <returns>Match object returned by Regex.Match(string)</returns>
        static Match getMatches(string pattern, string data)
        {
            Regex obj = new Regex(pattern);
            return obj.Match(data);
        }

        /// <summary>
        /// Simple interface that sends a given message through the given ssl stream.
        /// </summary>
        /// <exception cref="AuthenticationException">SSL Stream not initialized properly</exception>
        /// <param name="stream"><para>SslStream Object that will be used to send the message.</para><para>It is assumed that it is already initialized.</para></param>
        /// <param name="message">String that will be passed, "EOF" flag will be appended at the end</param>
        static void sendMessage(ref SslStream stream, string messageString)
        {
            messageString += "<EOF>";
            byte[] message = Encoding.Unicode.GetBytes(messageString);
            stream.Write(message);
        }

        static void ProcessClient(TcpClient client)
        {
            // A client has connected. Create the 
            // SslStream using the client's network stream.
            SslStream sslStream = new SslStream(
                client.GetStream(), false);
            // Authenticate the server but don't require the client to authenticate.
            try
            {
                sslStream.AuthenticateAsServer(serverCertificate);

                // Set timeouts for the read and write to 5 seconds.
                sslStream.ReadTimeout = 5000;
                sslStream.WriteTimeout = 5000;
                // Read a message from the client.

                string messageData = ReadMessage(sslStream); // -----------Read the message
                
                string eOFPattern = "<EOF>$";
                if (!checkOccurance(eOFPattern, messageData)) // This check may be obsolete due to ReadMessage check
                {
                    sendMessage(ref sslStream, serverFalseResponse + "<ERR>No <EOF> flag in message!</ERR>"); // REMOVE IF NOT NECESSARY
                }

                string commandPattern = "^\\<COMMAND\\>\\s*(?<word>\\d{2})\\s*\\</COMMAND\\>";
                Match m = getMatches(commandPattern, messageData);

                string response;
                switch(m.Groups["word"].Value)
                {
                    case "01"://Request Server Side Password
                        {
                            // Get needed data
                            Match matchUsername = getMatches(usernamePattern, messageData);
                            string username = matchUsername.Groups["user"].Value;
                            Match matchPassword = getMatches(passwordPattern, messageData);
                            string pass = matchPassword.Groups["pwd"].Value;

                            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(pass))// check for presence of data
                            {
                                //prepare response
                                response = "<HSHPWD>";
                                string passwordHash = Actions.PCSwitch(username, pass);
                                response += passwordHash + "</HSHPWD>";

                                //answer
                                if (!string.IsNullOrEmpty(passwordHash))
                                    sendMessage(ref sslStream, serverTrueResponse + response);
                            }
                            else
                                sendMessage(ref sslStream, serverFalseResponse);
                        }
                        break;
                    case "02"://Check if user is in the serverside DB
                        {
                            Match matchUsername = getMatches(usernamePattern, messageData);
                            string username = matchUsername.Groups["user"].Value;

                            if (string.IsNullOrEmpty(username))
                            {
                                if (DbAction.IsUsernameInDatabase(username))
                                    sendMessage(ref sslStream, serverTrueResponse);
                            }
                            else
                                sendMessage(ref sslStream, serverFalseResponse);
                        }
                        break;
                    case "03"://Register new User
                        {
                            Match matchUsername = getMatches(usernamePattern, messageData);
                            string username = matchUsername.Groups["user"].Value;
                            Match matchPassword = getMatches(passwordPattern, messageData);
                            string pass = matchPassword.Groups["pwd"].Value;

                            // Need pattern for username and for password
                            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(pass))// check for presence of data
                            {
                                if (Actions.Registration(username, pass))
                                    sendMessage(ref sslStream, serverTrueResponse);
                            }
                            else
                                sendMessage(ref sslStream, serverFalseResponse);
                        }
                        break;
                    case "04"://Password reset request
                        {
                            Match matchUsername = getMatches(usernamePattern, messageData);
                            string username = matchUsername.Groups["user"].Value;

                            if (string.IsNullOrEmpty(username))
                            {
                                Actions.PWRecovery(username);
                                sendMessage(ref sslStream, serverTrueResponse);
                            }
                            else
                                sendMessage(ref sslStream, serverFalseResponse);
                        }
                        break;
                    case "05"://Password change request
                        {
                            Match matchUsername = getMatches(usernamePattern, messageData);
                            string username = matchUsername.Groups["user"].Value;
                            Match matchOldPassword = getMatches(oldPasswordPattern, messageData);
                            string oldPass = matchOldPassword.Groups["oldpwd"].Value;
                            Match matchNewPassword = getMatches(newPasswordPattern, messageData);
                            string newPass = matchOldPassword.Groups["newpwd"].Value;

                            // Need pattern for username and for password
                            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(oldPass) && !string.IsNullOrEmpty(newPass))// check for presence of data
                            {
                                if (Actions.PWChange(username, oldPass, newPass))
                                    sendMessage(ref sslStream, serverTrueResponse);
                            }
                            else
                                sendMessage(ref sslStream, serverFalseResponse);
                        }
                        break;
                    default:
                        //unrecognized code/behaviour, send fail message
                        sendMessage(ref sslStream, serverFalseResponse + "<ERR>Server did not recognize the given code!</ERR>");
                        break;
                }
                // Write a message to the client.
                sendMessage(ref sslStream, "Hello from the server.");
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                sslStream.Close();
                client.Close();
                return;
            }
            finally
            {
                // The client stream will be closed with the sslStream
                // because we specified this behavior when creating
                // the sslStream.
                sslStream.Close();
                client.Close();
            }
        }
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the client.
            // The client signals the end of the message using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                // Read the client's test message.
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.Unicode.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF or an empty message.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }

        const string serverFalseResponse = "\\<SERVER\\>FALSE\\</SERVER\\>";
        const string serverTrueResponse = "\\<SERVER\\>TRUE\\</SERVER\\>";
        const string usernamePattern = "\\<USR\\>(?<user>.*)\\</USR\\>";
        const string oldPasswordPattern = "\\<OLDPWD\\>(?<oldpwd>.*)\\</OLDPWD\\>";
        const string newPasswordPattern = "\\<NEWPWD\\>(?<newpwd>.*)\\</NEWPWD\\>";
        const string passwordPattern = "\\<PWD\\>(?<pwd>.*)\\</PWD\\>";
    }
}
