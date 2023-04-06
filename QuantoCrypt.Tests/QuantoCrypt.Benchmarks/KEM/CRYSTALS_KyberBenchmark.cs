using BenchmarkDotNet.Attributes;
using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;

namespace QuantoCrypt.Benchmarks.KEM
{
    [MemoryDiagnoser]
    public class CRYSTALS_KyberBenchmark
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(KYBERInputParams))]
        public void KYBERExecutor(string name, Internal.KEM.CRYSTALS.Kyber.KyberParameters kyberParameters)
        {
            for (int i = 0; i < 10; i++)
            {
                SecureRandom random = new SecureRandom();

                Internal.KEM.CRYSTALS.Kyber.KyberKeyGenerationParameters genParam = new Internal.KEM.CRYSTALS.Kyber.KyberKeyGenerationParameters(random, kyberParameters);
                Internal.KEM.CRYSTALS.Kyber.KyberKeyPairGenerator kpGen = new Internal.KEM.CRYSTALS.Kyber.KyberKeyPairGenerator(genParam);

                // Generate keys and test.
                AsymmetricKeyPair ackp = kpGen.GenerateKeyPair();

                KyberPublicKey pubKey = (KyberPublicKey)ackp.Public;
                KyberPrivateKey privKey = (KyberPrivateKey)ackp.Private;

                // KEM Enc
                Internal.KEM.CRYSTALS.Kyber.KyberKemGenerator KyberEncCipher = new Internal.KEM.CRYSTALS.Kyber.KyberKemGenerator(random);
                Infrastructure.KEM.ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubKey);

                byte[] generated_cipher_text = secWenc.GetEncapsulation();
                byte[] secret = secWenc.GetSecret();

                // KEM Dec
                Internal.KEM.CRYSTALS.Kyber.KyberKemExtractor KyberDecCipher = new Internal.KEM.CRYSTALS.Kyber.KyberKemExtractor(privKey);
                byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

                secret.Should().BeEquivalentTo(dec_key);
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(BouncyCastleKYBEREInputParams))]
        public void BouncyCastleKYBERExecutor(string name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters kyberParameters)
        {
            for (int i = 0; i < 10; i++)
            {
                Org.BouncyCastle.Security.SecureRandom random = new Org.BouncyCastle.Security.SecureRandom();

                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyPairGenerator kpGen = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyPairGenerator();
                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyGenerationParameters genParam = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyGenerationParameters(random, kyberParameters);

                // Generate keys and test.
                kpGen.Init(genParam);
                AsymmetricCipherKeyPair ackp = kpGen.GenerateKeyPair();

                KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)ackp.Public;
                KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)ackp.Private;

                // KEM Enc
                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemGenerator KyberEncCipher = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemGenerator(random);
                Org.BouncyCastle.Crypto.ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubParams);

                byte[] generated_cipher_text = secWenc.GetEncapsulation();
                byte[] secret = secWenc.GetSecret();

                // KEM Dec
                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemExtractor KyberDecCipher = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemExtractor(privParams);
                byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

                secret.Should().BeEquivalentTo(dec_key);
            }
        }

        public IEnumerable<object[]> KYBERInputParams()
        {
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512 };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768 };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024 };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512_AES.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512_AES };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768_AES.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768_AES };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024_AES.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024_AES };
        }

        public IEnumerable<object[]> BouncyCastleKYBEREInputParams()
        {
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512 };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768 };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024 };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512_aes.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512_aes };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768_aes.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768_aes };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024_aes.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024_aes };
        }
    }
}
