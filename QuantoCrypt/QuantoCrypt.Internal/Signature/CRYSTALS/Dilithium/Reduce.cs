namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Algorithms that allows modular arithmetic to be performed efficiently when the modulus is large (typically several hundred bits).
    /// </summary>
    internal class Reduce
    {
        internal static int MontgomeryReduce(long a)
        {
            int t;

            t = (int)(a * DilithiumEngine.QInv);
            t = (int)((a - t * (long)DilithiumEngine.Q) >> 32);

            return t;
        }

        internal static int Reduce32(int a)
        {
            int t;

            t = (a + (1 << 22)) >> 23;
            t = a - t * DilithiumEngine.Q;

            return t;
        }

        internal static int ConditionalAddQ(int a)
        {
            a += (a >> 31) & DilithiumEngine.Q;

            return a;
        }
    }
}
