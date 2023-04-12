namespace QuantoCrypt.Common.Random
{
    /// <remarks>
    /// Interface for [generators] that generating random bytes.
    /// </remarks>
	public interface IRandomGenerator
    {
        /// <summary>
        /// Add more seed material to the generator.
        /// </summary>
        /// <param name="seed">A byte array to be mixed into the generator's state.</param>
        void AddSeedMaterial(byte[] seed);

        /// <summary>
        /// Add more seed material to the generator.
        /// </summary>
        /// <param name="seed">A <see cref="ReadOnlySpan{byte}"/> to be mixed into the generator's state.</param>
        void AddSeedMaterial(ReadOnlySpan<byte> seed);

        /// <summary>
        /// Add more seed material to the generator.
        /// </summary>
        /// <param name="seed">A long value to be mixed into the generator's state.</param>
        void AddSeedMaterial(long seed);

        /// <summary>
        /// Fill byte array with random values.
        /// </summary>
        /// <param name="bytes">Array to be filled.</param>
        void NextBytes(byte[] bytes);


        /// <summary>
        /// Fill byte span with random values.
        /// </summary>
        /// <param name="bytes">Span to be filled.</param>
        void NextBytes(Span<byte> bytes);

        /// <summary>
        /// Fill byte array with random values.
        /// </summary>
        /// <param name="bytes">Array to receive bytes.</param>
        /// <param name="start">Index to start filling at.</param>
        /// <param name="len">Length of segment to fill.</param>
        void NextBytes(byte[] bytes, int start, int len);
    }
}
