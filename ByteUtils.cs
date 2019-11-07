using System;
using System.Collections.Generic;

namespace Padding_Oracle_Attack
{
    static class ByteUtils
    {
        public static List<byte[]> sliceBytesIntoBlocks(byte[] bytes, int blockSizeBytes = 16)
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

        public static byte[] concat(byte[] first, byte[] second)
        {
            var result = new byte[first.Length + second.Length];

            first.CopyTo(result, 0);
            second.CopyTo(result, first.Length);

            return result;
        }
    }
}
