using System;
using System.Security.Cryptography;

namespace Padding_Oracle_Attack
{
    public delegate byte PaddingValueProvider(int pos, int paddingLength, int blockLength);

    class PaddingValueProviders
    {
        public static PaddingValueProvider GetFromMode(PaddingMode paddingMode) {
            switch (paddingMode) {
                case PaddingMode.PKCS7:
                    return PKCS7;
                case PaddingMode.ANSIX923:
                    return ANSIX923;
            }
            throw new NotImplementedException(Enum.GetName(typeof(PaddingMode), paddingMode) + " is not supported.");
        }

        public static byte PKCS7(int pos, int paddingLength, int blockLength)
        {
            return (byte)paddingLength;
        }

        public static byte ANSIX923(int pos, int paddingLength, int blockLength)
        {
            return (byte)((pos == blockLength - 1) ? paddingLength : 0);
        }
    }
}
