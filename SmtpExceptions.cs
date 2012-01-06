using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DKIM
{
    public class SmtpException : Exception
    {
        public SmtpException() : base("Smtp exception was thrown.") { }
        public SmtpException(string message) : base(message) { }
        public SmtpException(string message, Exception innerException) : base(message, innerException) { }
        public SmtpException(Exception innerException) : base("Smtp exception was thrown.", innerException) { }
    }

    public class SmtpReadingException : SmtpException
    {
        public SmtpReadingException() : base("Could not read response from the server.") { }
        public SmtpReadingException(string host) : base(string.Format("Could not read response from the server({0}).", host)) { }
        public SmtpReadingException(string host, Exception innerException) : base(string.Format("Could not read response from the server({0}:{1}).", host), innerException) { }
    }

    public class SmtpCommandException : SmtpException
    {
        public SmtpCommandException() : base("Command exception.") { }
        public SmtpCommandException(string command, string line) : base(string.Format("Command {0} failed:{1}.", command, line)) { }
        public SmtpCommandException(string command, string line, Exception innerException) : base(string.Format("Command {0} failed:{1}.", command, line),  innerException) { }
        public SmtpCommandException(string message) : base(message) { }
        public SmtpCommandException(string message, Exception innerException) : base(message, innerException) { }
    }
}
