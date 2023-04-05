using QuantoCrypt.Infrastructure.Common.Random;

namespace QuantoCrypt.Infrastructure.Common
{
    /// <summary>
    /// Interface to handle parameters of the key generators.
    /// </summary>
    public interface IKeyGenerationParameters
    {
        /// <summary>
        /// Random source associated with generator.
        /// </summary>
        public SecureRandom Random { get; }

        /// <summary>
        /// The bit strength for keys produced by this generator,
        /// </summary>
        public int KeyStrength { get; }
    }
}
