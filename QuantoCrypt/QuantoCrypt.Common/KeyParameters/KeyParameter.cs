namespace QuantoCrypt.Common.Parameters
{
    /// <summary>
    /// Represent the general key parameter.
    /// </summary>
    public class KeyParameter : ICipherParameter
    {
        private readonly byte[] _rKey;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="key">Target key.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="key"/> is null.</exception>
        public KeyParameter(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _rKey = (byte[])key.Clone();
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="key">Target key.</param>
        /// <param name="keyOff">Target key offset.</param>
        /// <param name="keyLen">Target key length.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="key"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <paramref name="keyLen"/> or <paramref name="keyOff"/> are out of range.</exception>
        public KeyParameter(byte[] key, int keyOff, int keyLen)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (keyOff < 0 || keyOff > key.Length)
                throw new ArgumentOutOfRangeException(nameof(keyOff));
            if (keyLen < 0 || keyLen > (key.Length - keyOff))
                throw new ArgumentOutOfRangeException(nameof(keyLen));

            _rKey = new byte[keyLen];
            Array.Copy(key, keyOff, _rKey, 0, keyLen);
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="key">Target key.</param>
        public KeyParameter(ReadOnlySpan<byte> key)
        {
            _rKey = key.ToArray();
        }

        /// <summary>
        /// Key length.
        /// </summary>
        public int KeyLength => _rKey.Length;

        /// <summary>
        /// Target key.
        /// </summary>
        internal ReadOnlySpan<byte> Key => _rKey;

        /// <summary>
        /// Get key.
        /// </summary>
        /// <returns>
        ///     Target key.
        /// </returns>
        public byte[] GetKey()
            => (byte[])_rKey.Clone();
    }
}
