using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Mono.Options;

namespace Padding_Oracle_Attack
{
    class PaddingOracleAttack
    {
        // change the padding used by the oracle below (decryptor uses the same as the server/oracle)
        private const PaddingMode paddingMode = PaddingMode.PKCS7;
        private static RemoteServerMock oracle = new RemoteServerMock(paddingMode);
        private static PaddingOracleDecryptor decryptor = new PaddingOracleDecryptor(oracle);
        private static bool removePadding = true; // can be set to false by HandleConfigurationArguments

        public static void Main(String[] args)
        {
            Console.WriteLine("~~ Padding Oracle Attack Demo ~~");

            HandleConfigurationArguments(args);

            Console.WriteLine("Oracle response delay set to {0} ms.", oracle.OracleDelayMilliseconds);

            Console.WriteLine("\nEnter plaintext:");
            string plaintext = Console.ReadLine();

            byte[] encrypted = oracle.Encrypt(plaintext);
            var blocks = ByteUtils.SliceIntoBlocks(encrypted);

            Console.WriteLine("\nCiphertext blocks (base64):\n{0}", String.Join("\n", blocks.ConvertAll(block => Convert.ToBase64String(block))));

            Console.WriteLine("\nPadding oracle attack results:");
            Console.WriteLine("(first block cannot be decrypted)");

            var stopwatch = new Stopwatch();

            var lastBlockIndex = blocks.Count - 1;
            for (int blockIndex = 1; blockIndex <= lastBlockIndex; ++blockIndex)
            {
                stopwatch.Start();

                var decrypted = decryptor.DecryptBlock(blocks[blockIndex], blocks[blockIndex - 1]);

                stopwatch.Stop();

                if (removePadding && blockIndex == lastBlockIndex)
                {
                    decrypted = PaddingUtils.GetPaddingRemoverFromMode(oracle.Padding).Invoke(decrypted);
                }

                var decryptedPlaintext = Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);
                Console.WriteLine(decryptedPlaintext.Length > 0 ? decryptedPlaintext : "(padding-only block)");
            }

            var decodedBlocksCount = blocks.Count - 1;
            Console.WriteLine("\nDecoded {0} blocks.", decodedBlocksCount);

            if (decodedBlocksCount > 0)
            {
                var timeElapsed = stopwatch.Elapsed;
                Console.WriteLine("Time elapsed: {0}, avg {1:0.000} s per block", timeElapsed.ToString(), timeElapsed.Divide(decodedBlocksCount).TotalMilliseconds / 1000);
            }
        }

        private static void HandleConfigurationArguments(String[] args)
        {
            OptionSet arguments = new OptionSet();
            arguments.Add("d|delay=", "oracle delay in milliseconds for each padding request", (uint d) => oracle.OracleDelayMilliseconds = d);
            arguments.Add("p|preserve-padding", "don't remove padding from decoded string", _ => removePadding = false);
            arguments.Add("h|help", "displays this message", _ =>
            {
                arguments.WriteOptionDescriptions(Console.Out);
                Environment.Exit(0);
            });

            try
            {
                var rest = arguments.Parse(args);
                if (rest.Count == 0)
                {
                    return;
                }
                Console.WriteLine("Unrecognized arguments: {0}", String.Join(",", rest));
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            arguments.WriteOptionDescriptions(Console.Out);
            Environment.Exit(1);
        }
    }
}
