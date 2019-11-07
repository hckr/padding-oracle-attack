using System;
using System.Text;

namespace Padding_Oracle_Attack
{
    using static ByteUtils;

    class PaddingOracleAttack
    {
        private static RemoteServerMock server = new RemoteServerMock();

        public static void Main()
        {
            string hiddenMessage = "I'd just like to interject for a moment. What you’re referring to as Linux, is in fact, GNU/Linux, or as I’ve recently taken to calling it, GNU plus Linux.";

            byte[] encrypted = server.Encrypt(hiddenMessage);
            var blocks = sliceBytesIntoBlocks(encrypted);

            Console.WriteLine("Plaintext:\n{0}", hiddenMessage);
            Console.WriteLine("\nCiphertext:\n{0}", String.Join("\n", blocks.ConvertAll(block => Convert.ToBase64String(block))));
            Console.WriteLine("\nAttack results:");

            for (int blockIndex = 1; blockIndex < blocks.Count; ++blockIndex)
            {
                Console.WriteLine(DecryptBlock(blocks[blockIndex], blocks[blockIndex - 1]));
            }
        }

        private static string DecryptBlock(byte[] block, byte[] previousBlock)
        {
            byte[] decrypted = new byte[block.Length];
            byte[] manipulatedPrevious = new byte[16];

            // in case of PKCS7 padding value is same as padding length
            for (int paddingLength = 1; paddingLength <= block.Length; ++paddingLength)
            {
                for (int pos = block.Length - 1; pos >= block.Length - paddingLength; --pos)
                {
                    int previousPaddingLength = paddingLength - 1;
                    manipulatedPrevious[pos] ^= (byte)(previousPaddingLength ^ paddingLength);
                }
                var found = false;
                for (byte v = byte.MinValue; v <= byte.MaxValue; ++v)
                {
                    manipulatedPrevious[block.Length - paddingLength] = v;
                    if (server.IsPaddingCorrect(concat(manipulatedPrevious, block)))
                    {
                        found = true;
                        decrypted[block.Length - paddingLength] = (byte)(previousBlock[block.Length - paddingLength] ^ paddingLength ^ v);
                        break;
                    }
                }
                if (!found)
                {
                    throw new Exception("Decryption not possible. This function supports only AES/CBC/PKCS7");
                }
            }

            return Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);
        }
    }
}
