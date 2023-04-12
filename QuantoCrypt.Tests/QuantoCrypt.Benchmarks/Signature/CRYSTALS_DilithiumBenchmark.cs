using BenchmarkDotNet.Attributes;
using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using QuantoCrypt.Common;
using QuantoCrypt.Common.Utilities;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium;

namespace QuantoCrypt.Benchmarks.Signature
{
    [MemoryDiagnoser]
    public class CRYSTALS_DilithiumBenchmark
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(DilithiumInputParams))]
        public void DilithiumExecutor(string name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters dilithiumParameters)
        {
            for (int i = 0; i < 10; i++)
            {
                SecureRandom random = new SecureRandom();
                byte[] message = random.GenerateSeed((i+1) * 20);

                Internal.Signature.CRYSTALS.Dilithium.DilithiumKeyGenerationParameters keyGenerationParameters = new Internal.Signature.CRYSTALS.Dilithium.DilithiumKeyGenerationParameters(random, dilithiumParameters);
                Internal.Signature.CRYSTALS.Dilithium.DilithiumKeyPairGenerator keyPairGenerator = new Internal.Signature.CRYSTALS.Dilithium.DilithiumKeyPairGenerator(keyGenerationParameters);

                // Generate keys and test.
                AsymmetricKeyPair generatedKeyPair = keyPairGenerator.GenerateKeyPair();

                DilithiumPublicKey pubKey = (DilithiumPublicKey)generatedKeyPair.Public;
                DilithiumPrivateKey privKey = (DilithiumPrivateKey)generatedKeyPair.Private;

                // Generate signature.
                Internal.Signature.CRYSTALS.Dilithium.DilithiumSigner signer = new Internal.Signature.CRYSTALS.Dilithium.DilithiumSigner(true, privKey);
                byte[] generatedSignature = signer.GenerateSignature(message);
                byte[] generatedSignatureWithAttachedMessage = ArrayUtilities.Combine(generatedSignature, message);

                // Verify generated signature.
                Internal.Signature.CRYSTALS.Dilithium.DilithiumSigner verifier = new Internal.Signature.CRYSTALS.Dilithium.DilithiumSigner(false, pubKey);
                bool successfullyVerified = verifier.VerifySignature(message, generatedSignature);

                // changing the signature by 1 byte should cause it to fail.
                generatedSignature[3]++;
                bool failedToVerify = verifier.VerifySignature(message, generatedSignature);

                successfullyVerified.Should().BeTrue();
                failedToVerify.Should().BeFalse();
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(BouncyCastleDilithiumInputParams))]
        public void BouncyCastleDilithiumExecutor(string name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters dilithiumParameters)
        {
            for (int i = 0; i < 10; i++)
            {
                Org.BouncyCastle.Security.SecureRandom random = new Org.BouncyCastle.Security.SecureRandom();
                byte[] message = random.GenerateSeed((i + 1) * 20);


                Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyPairGenerator kpGen = new Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyPairGenerator();
                Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyGenerationParameters genParams = new Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyGenerationParameters(random, dilithiumParameters);

                // Generate keys and test.
                kpGen.Init(genParams);
                AsymmetricCipherKeyPair ackp = kpGen.GenerateKeyPair();

                DilithiumPublicKeyParameters pubParams = (DilithiumPublicKeyParameters)ackp.Public;
                DilithiumPrivateKeyParameters privParams = (DilithiumPrivateKeyParameters)ackp.Private;

                // Signature test
                Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner signer = new Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner();
                DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)ackp.Private;

                // Generate signature.
                signer.Init(true, skparam);
                byte[] sigGenerated = signer.GenerateSignature(message);
                byte[] attachedSig = ArrayUtilities.Combine(sigGenerated, message);

                // Verify generated signature.
                Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner verifier = new Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner();
                DilithiumPublicKeyParameters pkparam = pubParams;
                verifier.Init(false, pkparam);
                bool successfullyVerified = verifier.VerifySignature(message, sigGenerated);

                // changing the signature by 1 byte should cause it to fail.
                sigGenerated[3]++;
                bool failedToVerify = verifier.VerifySignature(message, sigGenerated);

                successfullyVerified.Should().BeTrue();
                failedToVerify.Should().BeFalse();
            }
        }

        public IEnumerable<object[]> DilithiumInputParams()
        {
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM2.Name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM2 };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM3.Name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM3 };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM5.Name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM5 };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM2_AES.Name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM2_AES };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM3_AES.Name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM3_AES };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM5_AES.Name, Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM5_AES };
        }

        public IEnumerable<object[]> BouncyCastleDilithiumInputParams()
        {
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM2.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium2 };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM3.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium3 };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM5.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium5 };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM2_AES.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium2Aes };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM3_AES.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium3Aes };
            yield return new object[] { Internal.Signature.CRYSTALS.Dilithium.DilithiumParameters.DILITHIUM5_AES.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium5Aes };
        }
    }
}
