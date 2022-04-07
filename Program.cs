using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace RSASample
{
    class Program
    {
        private CngKey _aliceKey;
        private byte[] _alicePubKeyBlob;

        static void Main()
        {
            var p = new Program();
            p.Run();
        }

        public void Run()
        {
            AliceTasks(out byte[] document, out byte[] hash, out byte[] signature);
            BobTasks(document, hash, signature);
        }

        public void AliceTasks(out byte[] data, out byte[] hash, out byte[] signature)
        {
            Console.WriteLine("// create a key pair");
            InitAliceKeys();

            Console.WriteLine("// create some data; hash it, add a digital signature to the hash");
            Console.WriteLine("// hand off these things to bob so that he can decrypt the message");
            data = Encoding.UTF8.GetBytes("Bob, this is Alice. DC Morrison sends his best wishes to you.");
            hash = HashDocument(data);
            signature = AddSignatureToHash(hash, _aliceKey);
        }

        public void BobTasks(byte[] data, byte[] hash, byte[] signature)
        {
            Console.WriteLine("// import alices public key");
            Console.WriteLine("// validate the signiture");
            Console.WriteLine("// use the hash to validate the data");
            Console.WriteLine("// write the validated message to the console");
            CngKey aliceKey = CngKey.Import(_alicePubKeyBlob, CngKeyBlobFormat.GenericPublicBlob);
            if (!IsSignatureValid(hash, signature, aliceKey))
            {
                Console.WriteLine("signature not valid");
                return;
            }
            if (!IsDocumentUnchanged(hash, data))
            {
                Console.WriteLine("document was changed");
                return;
            }
            Console.WriteLine("signature valid, document unchanged");
            Console.WriteLine($"document from Alice: {Encoding.UTF8.GetString(data)}");
        }

        private bool IsSignatureValid(byte[] hash, byte[] signature, CngKey key)
        {
            Console.WriteLine("// use the public key to create a RSA object");
            Console.WriteLine("// use the RSA object to validate verify the hash and signature");
            using (var signingAlg = new RSACng(key))
            {
                return signingAlg.VerifyHash(hash, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
            }
        }

        private bool IsDocumentUnchanged(byte[] hash, byte[] data)
        {
            Console.WriteLine("//hash the doc again them compare hashes");
            byte[] newHash = HashDocument(data);
            return newHash.SequenceEqual(hash);
        }

        private void InitAliceKeys()
        {
            Console.WriteLine("// create a RSA key pair");
            _aliceKey = CngKey.Create(CngAlgorithm.Rsa);
            _alicePubKeyBlob = _aliceKey.Export(CngKeyBlobFormat.GenericPublicBlob);
        }

        private byte[] HashDocument(byte[] data)
        {
            Console.WriteLine("//create SHA84 hashing object");
            Console.WriteLine("//and hash the document");
            using (var hashAlg = SHA384.Create())
            {
                return hashAlg.ComputeHash(data);
            }
        }

        private byte[] AddSignatureToHash(byte[] hash, CngKey key)
        {
            Console.WriteLine("// use the key to create an RSA object");
            Console.WriteLine("// use the object to sign the hash");
            using (var signingAlg = new RSACng(key))
            {
                byte[] signed = signingAlg.SignHash(hash, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                return signed;
            }
        }
    }
}
