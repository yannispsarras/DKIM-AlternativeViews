using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DKIM
{
   public static class StreamExtensions
    {
        public static byte[] ConvertToByteArray(this System.IO.Stream stream)
        {
            var streamLength = Convert.ToInt32(stream.Length);
            byte[] data = new byte[streamLength + 1];
            stream.Read(data, 0, streamLength);
            stream.Position = 0;
            return data;
        }
    }
}
