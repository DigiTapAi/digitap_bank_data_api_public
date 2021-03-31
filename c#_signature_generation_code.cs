using System;
using System.Security.Cryptography;
using System.Text;

public class Program
    {
        public static void Main(string[] args)
        {
            string signature = EncryptionRSA(SHA256HexHashString(Newtonsoft.Json.JsonConvert.SerializeObject(new {client_name = "xyz_demo", institution_id = "1", client_ref_num = "abcd123", txn_completed_cburl = "https://mydomain.com/callback", start_month = "2021-01", end_month = "2021-02", acceptance_policy = "atLeastOneTransactionInRange"})));
            Console.WriteLine(signature);
        }

        private static string ToHex(byte[] bytes, bool upperCase)
        {
            StringBuilder result = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                result.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));
            return result.ToString();
        }

        private static string SHA256HexHashString(string StringIn)
        {
            string hashString;
            using (var sha256 = SHA256Managed.Create())
            {
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(StringIn));
                hashString = ToHex(hash, false);
            }

            return hashString;
        }
        
        public static string EncryptionRSA(string strText)
        {
	    // please convert the given public key to xml via this link https://superdry.apphb.com/tools/online-rsa-key-converter and assign it to the below publicKey variable as string.
            var publicKey = "";

            var testData = Encoding.UTF8.GetBytes(strText);

            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    // client encrypting data with public key issued by server                    
                    rsa.FromXmlString(publicKey.ToString());

                    var encryptedData = rsa.Encrypt(testData, true);

                    var hexString = ToHex(encryptedData, false);

                    return hexString;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
