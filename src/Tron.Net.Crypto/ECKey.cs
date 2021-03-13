using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Tron.Net.Common;

namespace Tron.Net.Crypto
{
    public class ECKey
    {
        private const string CurveName = "secp256k1";
        private const string SignAlgorithmName = "SHA-256withECDSA";

        private static readonly ECDomainParameters Curve;
        private static readonly SecureRandom SecureRandom;
        private static readonly X9ECParameters Params;

        public ECPoint Pub { get; }
        public ECPublicKeyParameters PublicKey { get; }
        private readonly ECPrivateKeyParameters _privateKey;


        static ECKey()
        {

            Params = SecNamedCurves.GetByName(CurveName);
            Curve = new ECDomainParameters(Params.Curve, Params.G, Params.N, Params.H);
            SecureRandom = new SecureRandom();
        }

        public ECKey()
        {
            var parameters = new ECDomainParameters(Params.Curve, Params.G, Params.N, Params.H);
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(parameters, SecureRandom));
            var pair = generator.GenerateKeyPair();
            PublicKey = (ECPublicKeyParameters)pair.Public;
            Pub = PublicKey.Q;
            _privateKey = (ECPrivateKeyParameters)pair.Private;

        }


        public ECKey(BigInteger privateKey, ECPoint publicPoint)
        {
            _privateKey = new ECPrivateKeyParameters(new BigInteger(privateKey.ToString()), Curve);
            Pub = publicPoint;
            PublicKey = new ECPublicKeyParameters(publicPoint, Curve);
        }

        public byte[] SignTransaction(byte[] data)
        {
            ISigner signer = SignerUtilities.GetSigner(SignAlgorithmName);
            signer.Init(true, _privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] sigBytes = signer.GenerateSignature();

            return sigBytes;
        }

        public bool VerifySignature(byte[] signature, byte[] data)
        {
            ISigner signer = SignerUtilities.GetSigner(SignAlgorithmName);
            signer.Init(false, PublicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public static ECKey FromPrivate(BigInteger privKey)
        {
            return new ECKey(privKey, Curve.G.Multiply(privKey));
        }

        public static ECKey FromPrivate(byte[] privKeyBytes)
        {
            return FromPrivate(new BigInteger(1, privKeyBytes));
        }

        public static ECKey FromPrivateHexString(string privateKeyStr)
        {
            var bytes = privateKeyStr.FromHexToByteArray();
            return FromPrivate(new BigInteger(1, bytes));
        }
    }
}
