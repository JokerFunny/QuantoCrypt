namespace QuantoCrypt.Common.Parameters
{
    /// <summary>
    /// Parameters that have an initialization vector (IV) associated with them.
    /// </summary>
    public class ParametersWithIV : ICipherParameter
    {
        private readonly ICipherParameter _rParameter;
        private readonly byte[] _rIV;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="ICipherParameter"/>.</param>
        /// <param name="iv">Target initialization vector (IV).</param>
        /// <exception cref="ArgumentNullException">If iv is null.</exception>
        public ParametersWithIV(ICipherParameter parameters, byte[] iv)
            : this(parameters, iv, 0, iv.Length)
        {
            // NOTE: 'parameter' may be null to imply key re-use
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            _rParameter = parameters;
            _rIV = (byte[])iv.Clone();
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="ICipherParameter"/>.</param>
        /// <param name="iv">Target initialization vector (IV).</param>
        /// <param name="ivOff">Target initialization vector (IV) offset.</param>
        /// <param name="ivLen">Target initialization vector (IV) length.</param>
        /// <exception cref="ArgumentNullException">If iv is null.</exception>
        public ParametersWithIV(ICipherParameter parameters, byte[] iv, int ivOff, int ivLen)
        {
            // NOTE: 'parameter' may be null to imply key re-use
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            _rParameter = parameters;
            _rIV = new byte[ivLen];
            Array.Copy(iv, ivOff, _rIV, 0, ivLen);
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="ICipherParameter"/>.</param>
        /// <param name="iv">Target initialization vector (IV).</param>
        public ParametersWithIV(ICipherParameter parameters, ReadOnlySpan<byte> iv)
        {
            // NOTE: 'parameter' may be null to imply key re-use
            _rParameter = parameters;
            _rIV = iv.ToArray();
        }

        /// <summary>
        /// Length of the target initialization vector (IV).
        /// </summary>
        public int IVLength => _rIV.Length;

        /// <summary>
        /// Target <see cref="ICipherParameter"/>.
        /// </summary>
        public ICipherParameter Parameters => _rParameter;

        /// <summary>
        /// Target initialization vector (IV).
        /// </summary>
        internal ReadOnlySpan<byte> IV => _rIV;
    }
}
