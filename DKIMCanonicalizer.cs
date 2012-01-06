using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Specialized;

namespace DKIM
{
    public enum CanonicalizationType
    {
        Simple,
        Relaxed
    }

    public class DKIMCanonicalizer
    {
        CanonicalizationType type;
        public DKIMCanonicalizer(CanonicalizationType type)
        {
            this.type = type;
        }

        //public string CanonicalizeHeader(string header)
        //{
        //    return CanonicalizeHeader(type, header);
        //}

        public string CanonicalizeBody(string body)
        {
            return CanonicalizeBody(type, body);
        }

        public static string CanonicalizeHeader(CanonicalizationType type, NameValueCollection headers)
        {
            if (headers == null)
                return string.Empty;
            switch (type)
            {
                case CanonicalizationType.Simple:
                    return SimpleHeaderCanonicalization(headers);
                case CanonicalizationType.Relaxed:
                    return RelaxedHeaderCanonicalization(headers);
            }
            return null;
        }

        public static string CanonicalizeBody(CanonicalizationType type, string body)
        {
            if (body == null)
                return string.Empty;
            switch (type)
            {
                case CanonicalizationType.Simple:
                    return SimpleBodyCanonicalization(body);
                case CanonicalizationType.Relaxed:
                    return RelaxedBodyCanonicalization(body);
            }
            return null;
        }

        private static string SimpleHeaderCanonicalization(NameValueCollection headers)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string header in headers)
                foreach (string value in headers.GetValues(header))
                    sb.AppendFormat("{0}:{1}", header, value).AppendLine();
            return sb.ToString();
        }

        private static string RelaxedHeaderCanonicalization(NameValueCollection headers)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string header in headers)
                foreach (string value in headers.GetValues(header))
                    sb.AppendFormat("{0}:{1}", header.ToLower(), Regex.Replace(Regex.Replace(value, @"\s+", " "), "\r\n", " ")).AppendLine();
            return sb.ToString();
        }

        private static string SimpleBodyCanonicalization(string body)
        {
            if (body.Length < 1)
                return Environment.NewLine;
            var lines = Regex.Split(body, Environment.NewLine).ToList();
            int last = lines.FindLastIndex(s => !s.Equals(string.Empty));
            lines = lines.GetRange(0, last + 1);
            return string.Join(Environment.NewLine, lines) + Environment.NewLine;
        }

        private static string RelaxedBodyCanonicalization(string body)
        {
            if (body.Length < 1)
                return string.Empty;
            var lines = Regex.Split(body, Environment.NewLine).ToList();
            int last = lines.FindLastIndex(s => !s.Equals(string.Empty));
            lines = lines.GetRange(0, last + 1);
            return string.Join(Environment.NewLine, lines.Select(l => Regex.Replace(l, @"\s+", " ").TrimEnd())) + Environment.NewLine;
        }
    }
}
