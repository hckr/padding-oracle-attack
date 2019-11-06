using System.IO;
using System.Security.Cryptography;

namespace Padding_Oracle_Attack
{
    class RemoteServerMock
    {
        private Aes aesAlg = Aes.Create();

        public RemoteServerMock()
        {
            aesAlg.BlockSize = 128;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;
        }

        public byte[] Encrypt(string plaintext)
        {
            byte[] encrypted;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plaintext);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }

        public bool IsPaddingCorrect(byte[] ciphertext)
        {
            try
            {
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            srDecrypt.ReadToEnd();
                        }

                    }
                }
            }
            catch (CryptographicException)
            {
                return false;
            }

            return true;
        }
    }
}
