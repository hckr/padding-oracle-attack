namespace Padding_Oracle_Attack
{
    public delegate byte PaddingValueProvider(int pos, int paddingLength, int blockLength);

    class PaddingValueProviders
    {
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
