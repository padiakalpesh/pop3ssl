using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;


namespace pop3SSL
{
    /// <summary>
    /// Class for POP3 functionality using SSL
    /// This class doesn't support unsecured connection
    /// 
    /// This class implements the following commands:
    /// Minimal POP3 Commands:
    /// USER
    /// PASS
    /// QUIT
    /// STAT
    /// LIST
    /// RETR
    /// DELE
    /// NOOP
    /// RSET
    /// 
    /// This Class does NOT support the optional POP3 commands:
    /// APOP
    /// TOP
    /// UIDL
    /// </summary>
    public class pop3C
    {
        #region data members
        private int port;
        private string host;
        private string userName;
        private string password;
        private TcpClient client;
        private SslStream instream;
        private ArrayList response;

        private int numMessages;
        private int sizeOctet;
        private int msgId;
        private int msgSize;

        #endregion

        #region constructors
        /// <summary>
        /// Iniatilize a new instance of pop3SSL.pop3C and create a new response list
        /// </summary>
        public pop3C()
        {
            userName = null;
            password = null;
            port = 0;
            host = null;
            response = new ArrayList();
        }

        /// <summary>
        /// Iniatilize a new instance of pop3SSL.pop3C using the host name supplied and create a new response list
        /// </summary>
        /// <param name="host">Host name to connect ex: pop.gmail.com</param>
        public pop3C(string host)
        {
            userName = null;
            password = null;
            port = 0;
            this.host = host;
            response = new ArrayList();
        }

        /// <summary>
        /// Iniatilize a new instance of pop3SSL.pop3C using the host name and port supplied and create a new response list
        /// </summary>
        /// <param name="host">Host name to connect ex: pop.gmail.com</param>
        /// <param name="port">Port to connect to ex:995</param>
        public pop3C(string host, int port)
        {
            userName = null;
            password = null;
            this.host = host;
            this.port = port;
            response = new ArrayList();
        }
        #endregion

        #region get-set methods for different members
        /// <summary>
        /// Gets or sets the port to connect
        /// </summary>
        public int Port
        {
            get
            {
                return port;
            }
            set
            {
                port = value;
            }
        }

        /// <summary>
        /// Gets or sets the host to connect 
        /// </summary>
        public string Host
        {
            get
            {
                return host;
            }

            set
            {
                host = value;
            }
        }

        /// <summary>
        /// Gets or sets the username to use for login
        /// </summary>
        public string UserName
        {
            get
            {
                return userName;
            }

            set
            {
                userName = value;
            }
        }

        /// <summary>
        /// Gets or sets the password to use for login
        /// </summary>
        public string Password
        {
            get
            {
                return password;
            }

            set
            {
                password = value;
            }
        }

        /// <summary>
        /// Gets the number of messages in the mailbox
        /// </summary>
        public int NumMessages
        {
            get
            {
                return numMessages;
            }
        }

        /// <summary>
        /// Gets the size of mailbox in octets
        /// </summary>
        public int SizeOctet
        {
            get
            {
                return sizeOctet;
            }
        }

        /// <summary>
        /// Gets the size of message/mailbox  in octets as observed by the last call to list command
        /// </summary>
        public int MsgSize
        {
            get
            {
                return msgSize;
            }
        }

        /// <summary>
        /// Gets the message ID of the email queried using the latest call to list or retr command
        /// </summary>
        public int MsgId
        {
            get
            {
                return msgId;
            }
        }
        #endregion

        #region response handling methods
        /// <summary>
        /// Determine the number of strings present in the response.
        /// Useful when constructing a response string
        /// </summary>
        /// <returns>Number of strings in the response</returns>
        public int responseLength()
        {
            return response.Count;
        }

        /// <summary>
        /// Fetch a particular string stored in response
        /// </summary>
        /// <param name="index">The index of the response string to fetch</param>
        /// <returns>The response string</returns>
        public string responseString(int index)
        {
            return response[index].ToString();
        }
        #endregion

        #region certificate methods
        /// <summary>
        /// Verifies the remote Secure Sockets Layer (SSL) certificate used for authentication
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation</param>
        /// <param name="certificate">The certificate used to authenticate the remote party</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate</param>
        /// <returns>A System.Boolean value that determines whether the specified certificate is accepted for authentication</returns>
        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            return false;
        }

        /// <summary>
        /// Selects the local Secure Sockets Layer (SSL) certificate used for authentication
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation</param>
        /// <param name="targetHost">The host server specified by the client</param>
        /// <param name="localCertificates">An System.Security.Cryptography.X509Certificates.X509CertificateCollection containing local certificates</param>
        /// <param name="remoteCertificate">The certificate used to authenticate the remote party</param>
        /// <param name="acceptableIssuers">A System.String array of certificate issuers acceptable to the remote party</param>
        /// <returns>An System.Security.Cryptography.X509Certificates.X509Certificate used for establishing an SSL connection</returns>
        private X509Certificate SelectLocalCertificate(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            if (acceptableIssuers != null && acceptableIssuers.Length > 0 && localCertificates != null && localCertificates.Count > 0)
            {
                foreach (X509Certificate certificate in localCertificates)
                {
                    string issuer = certificate.Issuer;
                    if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                        return certificate;
                }
            }

            if (localCertificates != null && localCertificates.Count > 0)
                return localCertificates[0];
            return null;
        }
        #endregion

        #region login methods
        /// <summary>
        /// Login to the pop3 host on the specified port
        /// </summary>
        /// <returns>True if successful else false</returns>
        public bool login()
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK")==false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
                
                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            
            return true;
        }

        /// <summary>
        /// Login to the pop3 host on the specified port
        /// </summary>
        /// <param name="userName">The username to use for login</param>
        /// <param name="password">The password to use for login</param>
        /// <returns>True if successful else false</returns>
        public bool login(string userName, string password)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }
            
            if (response.Count != 0)
                response.Clear();
            
            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;
        }

        /// <summary>
        /// Login to the pop3 host on the port specified here
        /// </summary>
        /// <param name="port">Port number to connect</param>
        /// <returns>True if successful else false</returns>
        public bool login(int port)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;
        }

        /// <summary>
        /// Login to the pop3 host on the port specified here
        /// </summary>
        /// <param name="port">Port number to connect</param>
        /// <param name="userName">The username to use for login</param>
        /// <param name="password">The password to use for login</param>
        /// <returns>True if successful else false</returns>
        public bool login(int port, string userName, string password)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;
        }

        /// <summary>
        /// Login to the pop3 host specified here
        /// </summary>
        /// <param name="host">Host name to connect</param>
        /// <returns>True if successful else false</returns>
        public bool login(string host)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;
        }

        /// <summary>
        /// Login to the pop3 host specified here
        /// </summary>
        /// <param name="host">Host name to connect</param>
        /// <param name="userName">The username to use for login</param>
        /// <param name="password">The password to use for login</param>
        /// <returns>True if successful else false</returns>
        public bool login(string host, string userName, string password)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;          
        }

        /// <summary>
        /// Login to the pop3 host and port specified here
        /// </summary>
        /// <param name="host">Host name to connect</param>
        /// <param name="port">Port number to connect</param>
        /// <returns>True if successful else false</returns>
        public bool login(string host, int port)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;
        }

        /// <summary>
        /// Login to the pop3 host ansd port specified here
        /// </summary>
        /// <param name="host">Host name to connect</param>
        /// <param name="port">Port number to connect</param>
        /// <param name="userName">The username to use for login</param>
        /// <param name="password">The password to use for login</param>
        /// <returns>True if successful else false</returns>
        public bool login(string host, int port, string userName, string password)
        {
            int res;
            byte[] bytes;
            if (host == null || port == 0 || userName == null || password == null)
            {
                return false;
            }

            if (response.Count != 0)
                response.Clear();

            try
            {
                client = new TcpClient(host, port);
                instream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), new LocalCertificateSelectionCallback(SelectLocalCertificate));

                instream.AuthenticateAsClient(host);
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("USER " + userName + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }

                instream.Write(Encoding.ASCII.GetBytes("PASS " + password + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }

            return true;
        }
        #endregion 

        #region quit method
        /// <summary>
        /// Logout from the session
        /// </summary>
        /// <returns>True if successful else false</returns>
        public bool logout()
        {
            int res;
            byte[] bytes;

            if (response.Count != 0)
                response.Clear();

            try
            {
                instream.Write(Encoding.ASCII.GetBytes("QUIT \r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }
        #endregion

        #region stat method
        /// <summary>
        /// Send the STAT command to know statistics of the mailbox
        /// </summary>
        /// <returns>True if successful else false. If successful, sets the numMessages and sizeOctet field
        /// to the number of number of messages in the inbox and total size in octets</returns>
        public bool stat()
        {
            int res;
            byte[] bytes;
            char[] separator = new char[1];
            separator[0] = ' ';

            if (response.Count != 0)
                response.Clear();

            try
            {
                instream.Write(Encoding.ASCII.GetBytes("STAT \r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
                this.numMessages = int.Parse(response[response.Count - 1].ToString().Split(separator)[1]);
                this.sizeOctet = int.Parse(response[response.Count - 1].ToString().Split(separator)[2]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }
        #endregion

        #region list methods
        /*
        /// <summary>
        /// Send the LIST command
        /// </summary>
        /// <returns>True if successful else false. If successful, sets the numMessages and sizeOctet field
        /// to the number of number of messages in the inbox and total size in octets</returns>
        public bool list()
        {
            int res;
            byte[] bytes;
            char[] separator = new char[1];
            separator[0] = ' ';
         
            if (response.Count != 0)
                response.Clear();
            
            try
            {
                instream.Write(Encoding.ASCII.GetBytes("LIST \r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
                string[] subStr = response[response.Count - 1].ToString().Split(separator,3);
                numMessages = int.Parse(subStr[1]);
                sizeOctet = int.Parse(subStr[2]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }
        */

        /// <summary>
        /// Send the LIST nn command
        /// </summary>
        /// <param name="nn">The message number to list info about</param>
        /// <returns>True if successful else false. If successful, sets the msgId and msgSize field
        /// to the message ID of the message being listed and size of email in octets. 
        /// If unsuccessful, sets msgID to -1 and </returns>
        public bool list(int nn)
        {
            int res;
            byte[] bytes;
            char[] separator = new char[1];
            separator[0] = ' ';

            if (response.Count != 0)
                response.Clear();

            try
            {
                instream.Write(Encoding.ASCII.GetBytes("LIST " + nn + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
                msgId = int.Parse(response[response.Count - 1].ToString().Split(separator)[1]);
                msgSize = int.Parse(response[response.Count - 1].ToString().Split(separator)[2]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }

        #endregion

        #region retrieve method
        /// <summary>
        /// Send the RETR nn command
        /// </summary>
        /// <param name="nn">The message number to retrieve</param>
        /// <returns>True if successful else false</returns>
        public bool retr(int nn)
        {
            int res, len = 0;
            int lines = 0;
            byte[] bytes;
            char[] separator = new char[1];
            separator[0] = ' ';

            response.Clear();
            
            if (list(nn))
            {
                do
                {
                    len = 0;
                    try
                    {
                        instream.Write(Encoding.ASCII.GetBytes("RETR " + nn.ToString() + "\r\n"));
                        bytes = new byte[1024];
                        res = instream.Read(bytes, 0, bytes.Length);
                        len += res;
                        lines++;
                        String lastRead;
                        lastRead = Encoding.ASCII.GetString(bytes, 0, res);
                        do
                        {
                            try
                            {
                                if (response.Count + 1 >= response.Capacity)
                                    response.Capacity += 100;
                            }
                            catch (Exception ex)
                            {
                                System.Windows.Forms.MessageBox.Show("Cant add more capacity");
                                return false;
                            }

                            response.Add(lastRead);
                            bytes = null;
                            bytes = new byte[1024];
                            res = instream.Read(bytes, 0, bytes.Length);
                            len += res;
                            lines++;
                            lastRead = Encoding.ASCII.GetString(bytes, 0, res);

                        } while (lastRead.EndsWith("\r\n.\r\n") == false);
                        response.Add(lastRead);
                        if (response.Count < lines)
                            throw new SystemException("Not enough space in response array");
                        if (response[response.Count - 1].ToString().EndsWith("\r\n.\r\n"))
                            break;
                        else
                        {
                            Console.WriteLine("Trying to retrieve again. len = " + len + "msgSize = " + msgSize + "\n\n" + response[response.Count - 1].ToString());
                            response.Clear();
                            len = 0;
                            lines = 0;
                            bytes = null;
                            lastRead = null;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Exception occurred: {0}", ex.ToString());
                        System.Windows.Forms.MessageBox.Show("Exception Occurred " + ex.ToString());
                        return false;
                    }
                } while (true);
                return true;
            }
            else
                return false;
        }
        #endregion

        #region delete method
        /// <summary>
        /// Send the DELE nn command
        /// </summary>
        /// <param name="nn">The message to delete</param>
        /// <returns>True if successful else false</returns>
        public bool dele(int nn)
        {
            int res;
            byte[] bytes;

            if (response.Count != 0)
                response.Clear();

            try
            {
                instream.Write(Encoding.ASCII.GetBytes("DELE " + nn + "\r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }
        #endregion

        #region noop method
        /// <summary>
        /// Send the NOOP command
        /// </summary>
        /// <returns>True if successful else false</returns>
        public bool noop()
        {
            int res;
            byte[] bytes;

            if (response.Count != 0)
                response.Clear();

            try
            {
                instream.Write(Encoding.ASCII.GetBytes("NOOP \r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }
        #endregion

        #region reset method
        /// <summary>
        /// Send the RSET command
        /// </summary>
        /// <returns>True if successful else false</returns>
        public bool rset()
        {
            int res;
            byte[] bytes;

            if (response.Count != 0)
                response.Clear();
            
            try
            {
                instream.Write(Encoding.ASCII.GetBytes("RSET \r\n"));
                bytes = new byte[1024];
                res = instream.Read(bytes, 0, bytes.Length);
                response.Add(Encoding.ASCII.GetString(bytes, 0, res));
                if (response[response.Count - 1].ToString().StartsWith("+OK") == false)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred: {0}", ex.ToString());
                return false;
            }
            return true;
        }
        #endregion
    }
}
