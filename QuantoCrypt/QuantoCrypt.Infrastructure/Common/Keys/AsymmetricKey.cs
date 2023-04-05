namespace QuantoCrypt.Infrastructure.Common
{
    /// <summary>
    /// Base abstraction to work with the assymetric keys.
    /// </summary>
    /// <remarks>
    ///     Should be used for any key as a base class.
    /// </remarks>
    public abstract class AsymmetricKey
    {
        private readonly bool _rIsPrivate;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="isPrivate">Determines if target key is private or not.</param>
        protected AsymmetricKey(bool isPrivate)
        {
            _rIsPrivate = isPrivate;
        }

        /// <summary>
        /// Determines if target key is private or not.
        /// </summary>
        public bool IsPrivate => _rIsPrivate;

        /// <summary>
        /// Return the encoded key.
        /// </summary>
        /// <returns>
        ///     The encoded version of the target key.
        /// </returns>
        /// <remarks>
        ///     IT SHOULD BE OVERRIDDEN BY THE END INHERITOR.
        /// </remarks>
        public virtual byte[] GetEncoded() => throw new NotImplementedException();

        public override bool Equals(object obj)
        {
            AsymmetricKey? other = obj as AsymmetricKey;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(AsymmetricKey other)
            => _rIsPrivate == other._rIsPrivate;

        public override int GetHashCode()
            => _rIsPrivate.GetHashCode();
    }
}
