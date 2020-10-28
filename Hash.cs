using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Hashing
{
    public class Hash
    {

        public static string GetStringSha256Hash(string text)
        {
            if (String.IsNullOrEmpty(text))
                return String.Empty;

            using (var sha = new SHA256Managed())
            {
                byte[] textData = Encoding.UTF8.GetBytes(text);
                byte[] hash = sha.ComputeHash(textData);
                return BitConverter.ToString(hash).Replace("-", String.Empty);
            }
        }
        public static byte[] ComputeHashSha512(byte[] toBeHashed)
        {
            using (var sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(toBeHashed);
            }
        }
        public static byte[] ComputeHashSha1(byte[] toBeHashed)
        {
            using (var sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(toBeHashed);
            }
        }
        public static byte[] ComputeHashSha384(byte[] toBeHashed)
        {
            using (var sha384 = SHA384.Create())
            {
                return sha384.ComputeHash(toBeHashed);
            }
        }
        public static byte[] ComputeHashMd5(byte[] toBeHashed)
        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(toBeHashed);
            }
        }
     
    }
}
