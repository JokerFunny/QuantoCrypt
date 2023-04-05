namespace QuantoCrypt.Infrastructure.Common.BlockCipher
{
    /// <summary>
    /// Utilities to work with AES.
    /// </summary>
    public static class AesUtilities
    {
        /// <summary>
        /// Checks if the hardware accelerated version is supported.
        /// </summary>
        public static bool IsHardwareAccelerated => AesEngine_X86.IsSupported;

        /// <summary>
        /// Create a proper AES engine.
        /// </summary>
        /// <returns>
        ///     <see cref="AesEngine_X86"/> if supported, otherwise - <see cref="AesEngine"/>.
        /// </returns>
        public static IBlockCipher CreateEngine()
        {
            if (AesEngine_X86.IsSupported)
                return new AesEngine_X86();

            return new AesEngine();
        }
    }
}
