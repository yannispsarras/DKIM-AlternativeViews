using System;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Mail;
using System.Security.Cryptography;
using System.IO;
using System.Net.Mime;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace DKIM
{
    public enum HashingAlgorithm
    {
        RSASha1,
        RSASha256

    }

    public class MailMessage : System.Net.Mail.MailMessage
    {
        public bool IsSigned { get; private set; }
        public string MultipartBoundary { get; private set; }

        private void Init()
        {
            IsSigned = false;
            MultipartBoundary =
                //"---AU_MimePart_331611110703590652237121646";
                "--boundary_0_" + Guid.NewGuid().ToString();
        }

        public MailMessage() { Init(); }

        public MailMessage(MailAddress from, MailAddress to) : base(from, to) { Init(); }

        public MailMessage(string from, string to) : base(from, to) { Init(); }

        public MailMessage(string from, string to, string subject, string body) : base(from, to, subject, body) { Init(); }

        public void DKIMSign(ISigner signer, CanonicalizationType headerCanonicalization, CanonicalizationType bodyCanonicalization, HashingAlgorithm hashAlgorithm, string domain, string selector)
        {
            if (IsSigned)
                throw new InvalidOperationException("Message already have DKIM header.");
            IsSigned = true;

            string hashtype = hashAlgorithm == HashingAlgorithm.RSASha1 ? "sha1" : "sha256";

            StringBuilder dkim = new StringBuilder(300)
                .Append("v=1;") // version
                .Append("a=").Append("rsa-").Append(hashtype).Append(";") // hash algorithm
                .Append("c=").Append(string.Format("{0}/{1}", headerCanonicalization, bodyCanonicalization).ToLower()).Append(";") // canonicalization types headers/body
                .Append("d=").Append(domain).Append(";") // domain for diim check
                .Append("s=").Append(selector).Append(";") // TXT record selector
                .Append("t=").Append(Convert.ToInt64((DateTime.Now.ToUniversalTime() - DateTime.SpecifyKind(DateTime.Parse("00:00:00 January 1, 1970"), DateTimeKind.Utc)).TotalSeconds).ToString()).Append(";") // creation time
                .Append("bh=").Append(GetBodyHash(bodyCanonicalization, hashtype)).Append(";"); // body hash

            var headers = ComputedHeaders;

            List<string> h = new List<string>();
            foreach (string header in headers)
                foreach (string value in headers.GetValues(header))
                    h.Add(header);

            dkim.Append("h=").Append(string.Join(":", h)).Append(";") // headers for hashing
            .Append("b="); // signature data

            var canonialized = DKIMCanonicalizer.CanonicalizeHeader(headerCanonicalization, headers) + "dkim-signature:" + dkim.ToString();
            var bytes = (HeadersEncoding ?? Encoding.UTF8).GetBytes(canonialized);

            lock (signer)
            {
                signer.BlockUpdate(bytes, 0, bytes.Length);
                bytes = signer.GenerateSignature();//computing signature
                signer.Reset();
            }

            dkim.Append(Convert.ToBase64String(bytes));

            Headers.Add("dkim-signature", dkim.ToString());// adding DKIM header
        }

        public string ComputedBody
        {
            get
            {
                //check if we have only one body
                var views = AlternateViews.ToList();
                if (!string.IsNullOrEmpty(Body))
                    views.Insert(0, AlternateView.CreateAlternateViewFromString(Body, BodyEncoding, IsBodyHtml ? MediaTypeNames.Text.Html : MediaTypeNames.Text.Plain));

                if (views.Count < 2)// if single, just return it
                    return new StreamReader(views.First().ContentStream).ReadToEnd();

                //computing body
                StringBuilder sb = new StringBuilder((int)views.Sum(v => v.ContentStream.Length) + views.Count * 60 + (MultipartBoundary.Length + 2) * 3 + 50);
                sb.Append(Environment.NewLine);
                foreach (var view in views)
                {
                    sb.Append("--").AppendLine(MultipartBoundary)
                    .Append("Content-Type: ").Append(view.ContentType.MediaType).Append("; charset=").AppendLine(view.ContentType.CharSet)
                    .Append("Content-Transfer-Encoding: ").Append(GetTransferEncodingName(view.TransferEncoding)).AppendLine().AppendLine()
                    .AppendLine(GetTransferEncodedContent(view));
                }
                sb.Append("--").Append(MultipartBoundary).Append("--");

                return sb.ToString();
            }
        }

        public string GetBodyHash(CanonicalizationType type, string hashType)
        {
            var canonicalized = DKIMCanonicalizer.CanonicalizeBody(type, ComputedBody).TrimStart('\r', '\n');
            return Convert.ToBase64String(HashAlgorithm.Create(hashType).ComputeHash(Encoding.ASCII.GetBytes(canonicalized)));
        }

        public NameValueCollection ComputedHeaders
        {
            get
            {
                NameValueCollection headers = new NameValueCollection(Headers.Count + 7);
                // placing headers to new collection(with encoding if needed)
                if (HeadersEncoding != null)//checking if we have non standard encoding
                    foreach (string header in Headers)
                        foreach (var value in Headers.GetValues(header))
                        {
                            var bytes = HeadersEncoding.GetBytes(value);
                            var encoded = HeadersEncoding.GetString(bytes, 0, bytes.Length);
                            if (!encoded.Equals(value))//if not equals, put encoding
                                headers.Add(header, string.Format("=?{0}?Q?{1}?=", HeadersEncoding.BodyName, encoded));
                            else
                                headers.Add(header, value);
                        }
                else
                    foreach (string header in Headers)
                        foreach (var value in Headers.GetValues(header))
                            headers.Add(header, value);

                //adding other standard headers
                headers.Add("From", From.Address);
                headers.Add("To", string.Join(" ", To.Select(a => a.Address)));
                if (CC.Count > 0)
                    headers.Add("CC", string.Join(" ", CC.Select(a => a.Address)));

                //headers.Add("Date:",DateTime.Now.ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'"));

                if (SubjectEncoding != null)//checking for header encoding
                {
                    var bytes = SubjectEncoding.GetBytes(Subject);
                    var encoded = SubjectEncoding.GetString(bytes, 0, bytes.Length);
                    if (!encoded.Equals(Subject))//if not equals, put encoding
                        headers.Add("Subject", string.Format("=?{0}?Q?{1}?=", SubjectEncoding.BodyName, encoded));
                    else
                        headers.Add("Subject", Subject);
                }
                else
                    headers.Add("Subject", Subject);

                if (IsBodyMultipart)
                    headers.Add("Content-Type", "multipart/alternative; boundary=" + MultipartBoundary);//for multiple bodies
                else
                {
                    //for single body
                    AlternateView bodyView;
                    if (AlternateViews.Count < 1)
                        bodyView = AlternateView.CreateAlternateViewFromString(Body, BodyEncoding, IsBodyHtml ? MediaTypeNames.Text.Html : null);
                    else
                        bodyView = AlternateViews.First();

                    headers.Add("Content-Type", bodyView.ContentType.MediaType + "; charset=" + bodyView.ContentType.CharSet);
                    headers.Add("Content-Transfer-Encoding", GetTransferEncodingName(bodyView.TransferEncoding));
                }

                return headers;
            }
        }

        public bool IsBodyMultipart
        {
            get
            {
                if (string.IsNullOrEmpty(Body))
                    if (AlternateViews.Count > 1)
                        return true;
                    else
                        return false;
                else
                    if (AlternateViews.Count > 0)
                        return true;
                    else
                        return false;
            }
        }

        public static string GetTransferEncodingName(TransferEncoding type)
        {
            switch (type)
            {
                case TransferEncoding.Base64:
                    return "base64";
                case TransferEncoding.QuotedPrintable:
                    return "quoted-printable";
                case TransferEncoding.SevenBit:
                    return "7bit";
                default:
                    throw new NotSupportedException(string.Format("The MIME transfer encoding '{0}' is not supported.", type));
            }
        }

        public static string GetTransferEncodedContent(AlternateView view)
        {
            if (view == null)
                return null;

            view.ContentStream.Position = 0;
            switch (view.TransferEncoding)
            {
                case TransferEncoding.Base64:
                    return Convert.ToBase64String(view.ContentStream.ConvertToByteArray(), Base64FormattingOptions.InsertLineBreaks);
                case TransferEncoding.QuotedPrintable:
                    return new StreamReader(view.ContentStream).ReadToEnd();
                default:
                    throw new NotSupportedException(string.Format("The MIME transfer encoding '{0}' is not supported.", view.TransferEncoding));
            }
        }

        private string HeadersToString(NameValueCollection headers)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string header in headers)
                foreach (string value in headers.GetValues(header))
                    sb.AppendFormat("{0}:{1}", header, value).AppendLine();
            return sb.ToString();
        }

        public string GetMessageData()
        {
            return HeadersToString(ComputedHeaders) + ComputedBody;
        }
    }
}
