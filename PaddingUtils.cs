using System;
using System.Security.Cryptography;

namespace Padding_Oracle_Attack
{
    public delegate byte PaddingValueProvider(int pos, int paddingLength, int blockLength);
    public delegate byte[] PaddingRemover(byte[] block);

    class PaddingUtils
    {
        public static PaddingValueProvider GetPaddingValueProviderFromMode(PaddingMode paddingMode)
        {
            switch (paddingMode)
            {
                case PaddingMode.PKCS7:
                    return PKCS7_ValueProvider;

                case PaddingMode.ANSIX923:
                    return ANSIX923_ValueProvider;
            }
            throw new NotImplementedException(Enum.GetName(typeof(PaddingMode), paddingMode) + " is not supported");
        }

        public static PaddingRemover GetPaddingRemoverFromMode(PaddingMode paddingMode)
        {
            switch (paddingMode)
            {
                case PaddingMode.PKCS7:
                    return PKCS7_Remover;

                case PaddingMode.ANSIX923:
                    return ANSIX923_Remover;
            }
            throw new NotImplementedException(Enum.GetName(typeof(PaddingMode), paddingMode) + " is not supported");
        }

        public static byte PKCS7_ValueProvider(int pos, int paddingLength, int blockLength)
        {
            return (byte)paddingLength;
        }

        public static byte[] PKCS7_Remover(byte[] block)
        {
            var paddingLength = block[block.Length - 1];

            if (paddingLength <= 1 && paddingLength >= block.Length)
            {
                throw new Exception("Incorrect padding");
            }

            var contentLength = block.Length - paddingLength;

            for (int i = block.Length - 2; i >= contentLength; --i)
            {
                if (block[i] != paddingLength)
                {
                    throw new Exception("Incorrect padding");
                }
            }

            var result = new byte[contentLength];

            Array.Copy(block, 0, result, 0, contentLength);

            return result;
        }

        public static byte ANSIX923_ValueProvider(int pos, int paddingLength, int blockLength)
        {
            return (byte)((pos == blockLength - 1) ? paddingLength : 0);
        }

        public static byte[] ANSIX923_Remover(byte[] block)
        {
            var paddingLength = block[block.Length - 1];

            if (paddingLength <= 1 && paddingLength >= block.Length)
            {
                throw new Exception("Incorrect padding");
            }

            var contentLength = block.Length - paddingLength;

            for (int i = block.Length - 2; i >= contentLength; --i)
            {
                if (block[i] != 0)
                {
                    throw new Exception("Incorrect padding");
                }
            }

            var result = new byte[contentLength];

            Array.Copy(block, 0, result, 0, contentLength);

            return result;
        }
    }
}
