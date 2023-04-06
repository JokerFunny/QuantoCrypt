using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace QuantoCrypt.Internal.Utilities
{
    /// <summary>
    /// Utilities to work with arrays.
    /// </summary>
    internal static class ArrayUtilities
    {
        /// <summary>
        /// Make a copy of a range of bytes from the passed in data array. The range can
        /// </summary>
        /// <param name="data">Target array from which the data should be copied.</param>
        /// <param name="from">Start index.</param>
        /// <param name="to">Final index.</param>
        /// <returns>
        ///     New byte array containing the range given
        /// </returns>
        public static byte[] CopyOfRange(byte[] data, int from, int to)
        {
            int newLength = _GetLength(from, to);

            byte[] tmp = new byte[newLength];
            Array.Copy(data, from, tmp, 0, Math.Min(newLength, data.Length - from));

            return tmp;
        }

        /// <summary>
        /// Determine the equality of two byte sequences in an amount of time which depends on the length of the sequences, but not the values.
        /// </summary>
        /// <param name="a">The first buffer to compare.</param>
        /// <param name="b">The second buffer to compare.</param>
        /// <returns>
        ///   True if <paramref name="a"/> and <paramref name="b"/> have the same values for <see cref="ReadOnlySpan{T}.Length"/> 
        ///   and the same contents, otherwise - false.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (null == a || null == b)
                return false;

            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Copy <paramref name="data"/> to the new array.
        /// </summary>
        /// <param name="data">Target array.</param>
        /// <param name="newLength">New length.</param>
        /// <returns>
        ///     New copy of the <paramref name="data"/>.
        /// </returns>
        public static byte[] CopyOf(byte[] data, int newLength)
        {
            byte[] tmp = new byte[newLength];
            Array.Copy(data, 0, tmp, 0, Math.Min(newLength, data.Length));

            return tmp;
        }

        /// <summary>
        /// Concatenate all <paramref name="arrays"/> to a single array.
        /// </summary>
        /// <param name="arrays">Target arrays to be codembined.</param>
        /// <returns>
        ///     A single array as a combination of <paramref name="arrays"/>.
        /// </returns>
        public static byte[] Combine(params byte[][] arrays)
        {
            byte[] result = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }

        private static int _GetLength(int from, int to)
        {
            int newLength = to - from;

            if (newLength < 0)
                throw new ArgumentException(from + " > " + to);

            return newLength;
        }
    }
}
