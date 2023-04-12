using QuantoCrypt.Common.Utilities;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Utility to perform packing operation needed for Dilithium.
    /// </summary>
    internal class PackingUtility
    {
        internal static byte[] PackPublicKey(PolyVecK t1, DilithiumEngine Engine)
        {
            byte[] output = new byte[Engine.CryptoPublicKeyBytes - DilithiumEngine.SeedBytes];

            for (int i = 0; i < Engine.K; i++)
                Array.Copy(t1.rVec[i].PolyT1Pack(), 0, output, i * DilithiumEngine.PolyT1PackedBytes, DilithiumEngine.PolyT1PackedBytes);

            return output;
        }

        internal static PolyVecK UnpackPublicKey(PolyVecK t1, byte[] pk, DilithiumEngine Engine)
        {
            int i;
            for (i = 0; i < Engine.K; ++i)
                t1.rVec[i].PolyT1Unpack(ArrayUtilities.CopyOfRange(pk, i * DilithiumEngine.PolyT1PackedBytes, DilithiumEngine.SeedBytes + (i + 1) * DilithiumEngine.PolyT1PackedBytes));

            return t1;
        }

        internal static void PackSecretKey(byte[] t0_, byte[] s1_, byte[] s2_, PolyVecK t0, PolyVecL s1, PolyVecK s2, DilithiumEngine Engine)
        {
            int i;
            for (i = 0; i < Engine.L; ++i)
                s1.rVec[i].PolyEtaPack(s1_, i * Engine.PolyEtaPackedBytes);

            for (i = 0; i < Engine.K; ++i)
                s2.rVec[i].PolyEtaPack(s2_, i * Engine.PolyEtaPackedBytes);

            for (i = 0; i < Engine.K; ++i)
                t0.rVec[i].PolyT0Pack(t0_, i * DilithiumEngine.PolyT0PackedBytes);
        }

        internal static void UnpackSecretKey(PolyVecK t0, PolyVecL s1, PolyVecK s2, byte[] t0Enc, byte[] s1Enc, byte[] s2Enc, DilithiumEngine Engine)
        {
            int i;
            for (i = 0; i < Engine.L; ++i)
                s1.rVec[i].PolyEtaUnpack(s1Enc, i * Engine.PolyEtaPackedBytes);

            for (i = 0; i < Engine.K; ++i)
                s2.rVec[i].PolyEtaUnpack(s2Enc, i * Engine.PolyEtaPackedBytes);

            for (i = 0; i < Engine.K; ++i)
                t0.rVec[i].PolyT0Unpack(t0Enc, i * DilithiumEngine.PolyT0PackedBytes);
        }

        internal static void PackSignature(byte[] sig, byte[] c, PolyVecL z, PolyVecK h, DilithiumEngine engine)
        {
            int i, j, k, end = 0;

            Array.Copy(c, 0, sig, 0, DilithiumEngine.SeedBytes);
            end += DilithiumEngine.SeedBytes;

            for (i = 0; i < engine.L; ++i)
                z.rVec[i].PackZ(sig, end + i * engine.PolyZPackedBytes);

            end += engine.L * engine.PolyZPackedBytes;

            for (i = 0; i < engine.Omega + engine.K; ++i)
                sig[end + i] = 0;

            k = 0;
            for (i = 0; i < engine.K; ++i)
            {
                for (j = 0; j < DilithiumEngine.N; ++j)
                {
                    if (h.rVec[i].rCoeffs[j] != 0)
                    {
                        sig[end + k++] = (byte)j;
                    }
                }

                sig[end + engine.Omega + i] = (byte)k;
            }
        }

        internal static bool UnpackSignature(PolyVecL z, PolyVecK h, byte[] sig, DilithiumEngine Engine)
        {
            int i, j, k;
            int end = DilithiumEngine.SeedBytes;

            for (i = 0; i < Engine.L; ++i)
                z.rVec[i].UnpackZ(ArrayUtilities.CopyOfRange(sig, end + i * Engine.PolyZPackedBytes, end + (i + 1) * Engine.PolyZPackedBytes));
            
            end += Engine.L * Engine.PolyZPackedBytes;

            k = 0;
            for (i = 0; i < Engine.K; ++i)
            {
                for (j = 0; j < DilithiumEngine.N; ++j)
                    h.rVec[i].rCoeffs[j] = 0;

                if ((sig[end + Engine.Omega + i] & 0xFF) < k || (sig[end + Engine.Omega + i] & 0xFF) > Engine.Omega)
                    return false;

                for (j = k; j < (sig[end + Engine.Omega + i] & 0xFF); ++j)
                {
                    if (j > k && (sig[end + j] & 0xFF) <= (sig[end + j - 1] & 0xFF))
                        return false;

                    h.rVec[i].rCoeffs[sig[end + j] & 0xFF] = 1;
                }

                k = sig[end + Engine.Omega + i];
            }
            for (j = k; j < Engine.Omega; ++j)
            {
                if ((sig[end + j] & 0xFF) != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
