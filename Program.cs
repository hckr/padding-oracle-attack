using System.Security.Cryptography;
using System.Net.Mime;
using System.Linq;
using System.Diagnostics;
using System;
using System.Text;
using Mono.Options;

namespace Padding_Oracle_Attack
{
    class PaddingOracleAttack
    {
        private static RemoteServerMock server = new RemoteServerMock(PaddingMode.PKCS7);
        private static PaddingOracleDecryptor decryptor = new PaddingOracleDecryptor(server);

        public static void Main(String[] args)
        {
            Console.WriteLine("~~ Padding Oracle Attack Demo ~~");

            HandleConfigurationArguments(args);

            Console.WriteLine("Oracle response delay set to {0} ms.", server.OracleDelayMilliseconds);

            Console.WriteLine("\nEnter plaintext:");
            string plaintext = Console.ReadLine();

            byte[] encrypted = server.Encrypt(plaintext);
            var blocks = ByteUtils.SliceIntoBlocks(encrypted);

            Console.WriteLine("\nCiphertext blocks (base64):\n{0}", String.Join("\n", blocks.ConvertAll(block => Convert.ToBase64String(block))));

            Console.WriteLine("\nPadding oracle attack results:");
            Console.WriteLine("(first block cannot be decrypted)");

            var stopwatch = new Stopwatch();

            for (int blockIndex = 1; blockIndex < blocks.Count; ++blockIndex)
            {
                stopwatch.Start();

                string decryptedPlaintext = decryptor.DecryptBlock(blocks[blockIndex], blocks[blockIndex - 1]);

                stopwatch.Stop();

                Console.WriteLine(decryptedPlaintext[0] != 16 ? decryptedPlaintext : "(padding-only block)");
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
            arguments.Add("d|delay=", "oracle delay in milliseconds for each padding request", (uint d) => server.OracleDelayMilliseconds = d);
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
