using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Padding_Oracle_Attack
{
    class PaddingOracleAttack
    {
        public static void Main()
        {
            string hiddenMessage = "I'd just like to interject for a moment. What you’re referring to as Linux, is in fact, GNU/Linux, or as I’ve recently taken to calling it, GNU plus Linux.";

            using (Aes aes = Aes.Create())
            {
                byte[] encrypted = EncryptStringToBytes_Aes(hiddenMessage);
                var blocks = sliceBytesIntoBlocks(encrypted);

                Console.WriteLine("Plaintext:\n{0}", hiddenMessage);
                Console.WriteLine("\nCiphertext:\n{0}", String.Join("\n", blocks.ConvertAll(block => Convert.ToBase64String(block))));
                Console.WriteLine("\nAttack results:\nTODO");
            }
        }

        static List<byte[]> sliceBytesIntoBlocks(byte[] bytes, int blockSizeBytes = 16)
        {
            var blocks = new List<byte[]>();

            for (var i = 0; i < bytes.Length; i += blockSizeBytes)
            {
                byte[] block = new byte[blockSizeBytes];
                Array.Copy(bytes, i, block, 0, blockSizeBytes);
                blocks.Add(block);
            }

            return blocks;
        }
        static byte[] EncryptStringToBytes_Aes(string plainText)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }
    }
}
