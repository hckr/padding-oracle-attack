using System;

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
            Console.WriteLine("\nAttack results:\nTODO");

            encrypted[encrypted.Length - 1] = 22;

            Console.WriteLine("\nPadding is {0}", server.IsPaddingCorrect(encrypted) ? "correct" : "incorrect");
        }
    }
}
