using FluentAssertions;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;
using QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium;
using QuantoCrypt.Internal.Symmetric;
using System.Reflection;

namespace QuantoCrypt.Internal.Tests.CipherSuiteTests.Crystals
{
    public class CrystalsKyber_CrystalsDilithium_Aes_Tests
    {
        public const int KYBER_SECURITY_LEVEL = 4;
        public const int KYBER_SESSION_KEY_SIZE = 256;

        public const int DILITHIUM_SECURITY_LEVEL = 5;

        public const string KYBER1024_NAME = "kyber1024";
        public const string KYBER1024_AES_NAME = "kyber1024-aes";

        public const string DILITHIUM5_NAME = "dilithium5";
        public const string DILITHIUM5_AES_NAME = "dilithium5-aes";

        public static Type KYBER_ALGORITHM_TYPE = typeof(KyberAlgorithm);
        public static Type KYBER_SYMMETRIC_SHAKE_TYPE = typeof(Internal.KEM.CRYSTALS.Kyber.Symmetric.ShakeSymmetric);
        public static Type KYBER_SYMMETRIC_AES_TYPE = typeof(Internal.KEM.CRYSTALS.Kyber.Symmetric.AesSymmetric);

        public static Type DILITHIUM_ALGORITHM_TYPE = typeof(DilithiumAlgorithm);
        public static Type DILITHIUM_SYMMETRIC_SHAKE_TYPE = typeof(Internal.Signature.CRYSTALS.Dilithium.Symmetric.ShakeSymmetric);
        public static Type DILITHIUM_SYMMETRIC_AES_TYPE = typeof(Internal.Signature.CRYSTALS.Dilithium.Symmetric.AesSymmetric);

        public static Type AES_ALGORITHM_TYPE = typeof(AesAlgorithm);
        public static Type AES_GCM_ALGORITHM_TYPE = typeof(AesGcmAlgorithm);

        private static readonly FieldInfo _srKyberParamsKyberAlgorithmFieldInfo = KYBER_ALGORITHM_TYPE
                .GetField("_kyberParameters", BindingFlags.NonPublic | BindingFlags.Instance);
        private static readonly FieldInfo _srDilithiumParamsDilithiumAlgorithmFieldInfo = DILITHIUM_ALGORITHM_TYPE
                .GetField("_dilithiumParameters", BindingFlags.NonPublic | BindingFlags.Instance);

        [Fact]
        public void CrystalsKyber1024_CrystalsDilithium5_Aes()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024_CrystalsDilithium5_Aes();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_NAME, KYBER_SYMMETRIC_SHAKE_TYPE, 
                DILITHIUM5_NAME, DILITHIUM_SYMMETRIC_SHAKE_TYPE, AES_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024_CrystalsDilithium5_AesGcm()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024_CrystalsDilithium5_AesGcm();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_NAME, KYBER_SYMMETRIC_SHAKE_TYPE, 
                DILITHIUM5_NAME, DILITHIUM_SYMMETRIC_SHAKE_TYPE, AES_GCM_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024_CrystalsDilithium5Aes_Aes()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024_CrystalsDilithium5Aes_Aes();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_NAME, KYBER_SYMMETRIC_SHAKE_TYPE,
                DILITHIUM5_AES_NAME, DILITHIUM_SYMMETRIC_AES_TYPE, AES_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_NAME, KYBER_SYMMETRIC_SHAKE_TYPE,
                DILITHIUM5_AES_NAME, DILITHIUM_SYMMETRIC_AES_TYPE, AES_GCM_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024Aes_CrystalsDilithium5_Aes()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024Aes_CrystalsDilithium5_Aes();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_AES_NAME, KYBER_SYMMETRIC_AES_TYPE,
                DILITHIUM5_NAME, DILITHIUM_SYMMETRIC_SHAKE_TYPE, AES_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_AES_NAME, KYBER_SYMMETRIC_AES_TYPE,
                DILITHIUM5_NAME, DILITHIUM_SYMMETRIC_SHAKE_TYPE, AES_GCM_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024Aes_CrystalsDilithium5Aes_Aes()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024Aes_CrystalsDilithium5Aes_Aes();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_AES_NAME, KYBER_SYMMETRIC_AES_TYPE,
                DILITHIUM5_AES_NAME, DILITHIUM_SYMMETRIC_AES_TYPE, AES_ALGORITHM_TYPE);
        }

        [Fact]
        public void CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm()
        {
            ICipherSuite cipherSuite = new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm();

            _CheckCipherSuiteTest(cipherSuite, KYBER1024_AES_NAME, KYBER_SYMMETRIC_AES_TYPE,
                DILITHIUM5_AES_NAME, DILITHIUM_SYMMETRIC_AES_TYPE, AES_GCM_ALGORITHM_TYPE);
        }

        private void _CheckCipherSuiteTest(ICipherSuite targetCipherSuite, string kyberAlgoName, Type kyberSymmetricAlgoType,
            string dilithiumAlgoName, Type dilithiumSymmetricAlgoType, Type symmetricAlgoType)
        {
            // check KEM algorithm.
            IKEMAlgorithm kemAlgorithm = targetCipherSuite.GetKEMAlgorithm();

            kemAlgorithm.Should().BeOfType(KYBER_ALGORITHM_TYPE);

            KyberParameters targetKyberParameters = (KyberParameters)_srKyberParamsKyberAlgorithmFieldInfo.GetValue(kemAlgorithm);

            targetKyberParameters.Should().NotBeNull();
            targetKyberParameters.Name.Should().Be(kyberAlgoName);
            targetKyberParameters.K.Should().Be(KYBER_SECURITY_LEVEL);
            targetKyberParameters.SessionKeySize.Should().Be(KYBER_SESSION_KEY_SIZE);
            targetKyberParameters.Engine.Symmetric.Should().BeOfType(kyberSymmetricAlgoType);

            // check DSA signer.
            ISignatureAlgorithm signer = targetCipherSuite.GetSignatureAlgorithm(true);

            signer.Should().BeOfType(DILITHIUM_ALGORITHM_TYPE);

            DilithiumParameters signerDilithiumParameters = (DilithiumParameters)_srDilithiumParamsDilithiumAlgorithmFieldInfo.GetValue(signer);

            signerDilithiumParameters.Should().NotBeNull();
            signerDilithiumParameters.Name.Should().Be(dilithiumAlgoName);

            DilithiumEngine signerDilithiumEngine = signerDilithiumParameters.GetEngine(null);
            signerDilithiumEngine.Should().NotBeNull();
            signerDilithiumEngine.Mode.Should().Be(DILITHIUM_SECURITY_LEVEL);
            signerDilithiumEngine.Symmetric.Should().BeOfType(dilithiumSymmetricAlgoType);

            // check DSA verifier.
            ISignatureAlgorithm verifier = targetCipherSuite.GetSignatureAlgorithm(false);

            signer.Should().BeOfType(DILITHIUM_ALGORITHM_TYPE);

            DilithiumParameters verifierDilithiumParameters = (DilithiumParameters)_srDilithiumParamsDilithiumAlgorithmFieldInfo.GetValue(signer);

            verifierDilithiumParameters.Should().NotBeNull();
            verifierDilithiumParameters.Name.Should().Be(dilithiumAlgoName);

            DilithiumEngine verifierDilithiumEngine = verifierDilithiumParameters.GetEngine(null);
            verifierDilithiumEngine.Should().NotBeNull();
            verifierDilithiumEngine.Mode.Should().Be(DILITHIUM_SECURITY_LEVEL);
            verifierDilithiumEngine.Symmetric.Should().BeOfType(dilithiumSymmetricAlgoType);

            // check symmetric algo.
            byte[] key = new byte[32];

            ISymmetricAlgorithm symmetricAlgorithm = targetCipherSuite.GetSymmetricAlgorithm(key);

            symmetricAlgorithm.Should().BeOfType(symmetricAlgoType);

            Action incorrectKeySizeCreation1 = () => targetCipherSuite.GetSymmetricAlgorithm(new byte[16]);
            incorrectKeySizeCreation1.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*The key should be of 256-bit size!*");

            Action incorrectKeySizeCreation2 = () => targetCipherSuite.GetSymmetricAlgorithm(null);
            incorrectKeySizeCreation2.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*The key should be of 256-bit size!*");
        }
    }
}
