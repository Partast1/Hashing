using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Hashing
{
    public class Program
    {
        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();
            //skriv besked som skal kryperes
            Console.WriteLine("Type secret message");
            string messageInput = Console.ReadLine();
            //Vælg crypterings type
            Console.WriteLine("Hash or Hmac");
            string typeInput = Console.ReadLine();
            typeInput.ToLower();
            if (typeInput == "hash")
            {
                Console.WriteLine("Type SHA1, MD5, RIPEMD, SHA256, SHA384 or SHA512 to select cryptography");
                string hashInput = Console.ReadLine();
                hashInput.ToLower();

                switch (hashInput)
                {
                    case "sha1":
                        stopwatch.Start();
                       var sha1 = Hash.ComputeHashSha1(Encoding.UTF8.GetBytes(messageInput));
                        stopwatch.Stop();
                        Console.WriteLine("Message{0} Time spent {1}", Convert.ToBase64String(sha1), stopwatch.ElapsedMilliseconds);
                        break;
                    case "md5":
                        stopwatch.Start();
                        var md5 = Hash.ComputeHashMd5(Encoding.UTF8.GetBytes(messageInput));
                        stopwatch.Stop();
                        Console.WriteLine("Message{0} Time spent {1}", Convert.ToBase64String(md5), stopwatch.ElapsedMilliseconds);

                        break;
                    case "sha256":
                        stopwatch.Start();
                        string sha256 = Hash.GetStringSha256Hash(messageInput);
                        stopwatch.Stop();
                        Console.WriteLine(sha256);
                        break;
                    case "sha384":
                        stopwatch.Start();
                        var sha384 = Hash.ComputeHashSha384(Encoding.UTF8.GetBytes(messageInput));
                        stopwatch.Stop();
                        Console.WriteLine("Message{0} Time spent {1}", Convert.ToBase64String(sha384), stopwatch.ElapsedMilliseconds);

                        break;
                    case "sha512":
                        stopwatch.Start();
                        var sha512 = Hash.ComputeHashSha512(Encoding.UTF8.GetBytes(messageInput));
                        stopwatch.Stop();
                        Console.WriteLine("Message{0} Time spent {1}", Convert.ToBase64String(sha512), stopwatch.ElapsedMilliseconds);
                        break;
                }

            }
            else
            {
                HMACHandler hmac = new HMACHandler();
                Console.WriteLine("Type SHA1, MD5, RIPEMD, SHA256, SHA384 or SHA512 to select cryptography");
                string hmacInput = Console.ReadLine();
                hmacInput.ToLower();
                HMAC hMAC = hmac.HMACDecider(hmacInput);
                stopwatch.Start();
                var HMAC = hmac.ComputeMAC(Encoding.UTF8.GetBytes(messageInput), hMAC.Key);
                stopwatch.Stop();
                Console.WriteLine("Message{0} Time spent {1}", Convert.ToBase64String(HMAC), stopwatch.ElapsedMilliseconds);

                bool test = hmac.CheckAuthenticity(Encoding.UTF8.GetBytes(messageInput), HMAC,hMAC.Key);
                if (test == true)
                {
                    Console.WriteLine("Authenticity confirmed");
                }
                else 
                {
                    Console.WriteLine("Authenticity denied");
                }
            }


           
          

        }


    }
}
