using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Hashing
{
    public class HMACHandler
    {
        private HMAC myMAC;

        public HMAC HMACDecider(string name)
        {
            if (name == "sha1")
            {
                  return myMAC = new HMACSHA1();

            }
            else if (name == "sha256")
            {
                return myMAC = new HMACSHA256();

            }
            else if (name == "sha384")
            {
                return myMAC = new HMACSHA384();
            }
            else if (name == "sha512")
            {
                return myMAC = new HMACSHA512();

            }
            else if (name == "md5")
            {
                return myMAC = new HMACMD5();


            }
            else if (name == "ripemd")
            {
                return myMAC = new HMACRIPEMD160();
            }
            else
            {
                return null;
            }
            
        }
        public byte[] ComputeMAC(byte[] mes, byte[] key)
        {
            myMAC.Key = key;
            return myMAC.ComputeHash(mes);
        }
        public bool CheckAuthenticity(byte[] mes, byte[] mac, byte[] key)
        {
            myMAC.Key = key;
            if (CompareByteArrays(myMAC.ComputeHash(mes), mac, myMAC.HashSize / 8) == true)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public int MACByteLength()
        {
            return myMAC.HashSize / 8;
        }
        private bool CompareByteArrays(byte[] a, byte[] b, int len)
        {
            for (int i = 0; i < len; i++)
                if (a[i] != b[i]) return false;
                 return true;   
        }
    }
}
