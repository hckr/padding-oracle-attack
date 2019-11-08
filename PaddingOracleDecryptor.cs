using System;
using System.Text;

namespace Padding_Oracle_Attack
{
    class PaddingOracleDecryptor
    {
        private RemoteServerMock oracle;
        private PaddingValueProvider paddingValueProvider;

        public PaddingOracleDecryptor(RemoteServerMock oracle)
        {
            this.oracle = oracle;
            paddingValueProvider = PaddingValueProviders.GetFromMode(oracle.Padding);
        }

        public string DecryptBlock(byte[] block, byte[] previousBlock)
        {
            byte[] decrypted = new byte[block.Length];
            byte[] manipulatedPrevious = new byte[16];

            for (int currentPosition = block.Length - 1; currentPosition >= 0; --currentPosition)
            {
                var paddingLength = block.Length - currentPosition;

                for (int pos = block.Length - 1; pos > currentPosition; --pos)
                {
                    manipulatedPrevious[pos] ^= (byte)(paddingValueProvider(pos, paddingLength - 1, block.Length) ^ paddingValueProvider(pos, paddingLength, block.Length));
                }

                var found = false;

                for (byte v = byte.MinValue; v <= byte.MaxValue; ++v)
                {
                    manipulatedPrevious[currentPosition] = v;

                    if (oracle.IsPaddingCorrect(ByteUtils.Concatenate(manipulatedPrevious, block)))
                    {
                        found = true;
                        decrypted[currentPosition] = (byte)(previousBlock[currentPosition] ^ paddingValueProvider(currentPosition, paddingLength, block.Length) ^ v);
                        break;
                    }
                }

                if (!found)
                {
                    throw new Exception("Decryption not possible");
                }
            }

            return Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);
        }

    }
}
