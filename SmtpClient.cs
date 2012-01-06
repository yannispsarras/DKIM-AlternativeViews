using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Mail;
using System.Net.Security;
using System.Net.Sockets;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace DKIM
{
    public class SmtpClient
    {
        public int Timeout
        {
            get
            {
                return Math.Min(stream.ReadTimeout, stream.WriteTimeout);
            }
            set
            {
                stream.ReadTimeout = stream.WriteTimeout = value;
            }
        }

        public NetworkCredential Credentials { get; private set; }

        private Stream stream;
        private StreamReader reader;
        public readonly string Host;
        public readonly bool UseSsl;
        private bool authenticated;

        public SmtpClient(string host, Stream stream) : this(host, stream, true, null) { }

        public SmtpClient(string host, Stream stream, bool useSsl) : this(host, stream, useSsl, null) { }

        public SmtpClient(string host, Stream stream, NetworkCredential credentials) : this(host, stream, true, credentials) { }

        public SmtpClient(string host, Stream stream, bool useSsl, NetworkCredential credentials)
        {
            Host = host;
            this.stream = stream;
            UseSsl = useSsl;
            Credentials = credentials;
            Timeout = 10000;

            if (useSsl)
            {
                //for ssl servers we must use SslStream
                var ssl = new SslStream(stream);
                ssl.AuthenticateAsClient(Host, null, System.Security.Authentication.SslProtocols.Ssl3 | System.Security.Authentication.SslProtocols.Tls, false);
                this.stream = ssl;
                reader = new StreamReader(ssl);
                var t = reader.ReadLine();
            }
            else
                reader = new StreamReader(stream);
        }

        public void Send(MailMessage message)
        {
            Send(new[] { message });
        }

        public void Send(IEnumerable<MailMessage> messages)
        {
            if (!authenticated)
            {
                //before sending we need make authentication
                Ehlo();

                if (Credentials != null)
                    Authenticate();

                authenticated = true;
            }

            foreach (var message in messages)
            {
                if (message.From != null && !string.IsNullOrWhiteSpace(message.From.Address))
                    From(message.From.Address);
                else if (message.Sender != null)
                    From(message.Sender.Address);
                else
                    throw new SmtpException("'From' wasn't specifaied.");

                RcptTo(message.To);
                RcptTo(message.CC);
                RcptTo(message.Bcc);
                Data(message.GetMessageData());
            }
        }


        private void Ehlo()
        {
            SendCommand("ehlo " + Dns.GetHostName(), 250);
        }

        private void Authenticate()
        {
            try
            {
                SendCommand("auth login ", 334);
                SendCommand(System.Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(Credentials.UserName)), 334);
                SendCommand(System.Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(Credentials.Password)), 235);
            }
            catch (Exception ex)
            {
                throw new SmtpException(string.Format("Autentication failed for user {0}.", Credentials.UserName), ex);
            }
        }

        private void From(string from)
        {
            SendCommand(string.Format("mail from: <{0}>", from), 250);
        }

        private void RcptTo(MailAddressCollection recipients)
        {
            foreach (var email in recipients)
                SendCommand(string.Format("rcpt to: <{0}>", email), 250);
        }

        private void Data(string data)
        {
            SendCommand("data", 354);
            SendCommand(data.ToString() + "\r\n.", 250);
        }

        private string SendCommand(string command, int expectedCode)
        {
            var bytes = Encoding.ASCII.GetBytes(command + Environment.NewLine);
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
            string result = "";
            string line = "";
            while (true)
            {
                try
                {
                    line = reader.ReadLine();
                }
                catch (Exception ex)
                {
                    throw new SmtpReadingException(Host, ex);
                }
                if (line.StartsWith(expectedCode + "-"))
                {
                    result += line + Environment.NewLine;
                    continue;
                }
                if (line.StartsWith(expectedCode + " "))
                {
                    result += line + Environment.NewLine;
                    break;
                }
                throw new SmtpCommandException(command, line);
            }
            return result;
        }
    }
}
