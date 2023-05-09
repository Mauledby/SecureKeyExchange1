using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecureKeyExchange
{
    public class DiffieHellman : IDisposable
    {
        #region Private Fields
        private Aes aes = null;
        private ECDiffieHellmanCng diffieHellman = null;

        private readonly byte[] publicKey;
        #endregion

        #region Constructor
        public DiffieHellman()
        {
            this.aes = new AesCryptoServiceProvider();

            this.diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };

            // This is the public key we will send to the other party
            this.publicKey = this.diffieHellman.PublicKey.ToByteArray();
        }
        #endregion

        #region Public Properties
        public byte[] PublicKey
        {
            get
            {
                return this.publicKey;
            }
        }

        public byte[] IV
        {
            get
            {
                return this.aes.IV;
            }
        }
        #endregion

        #region Public Methods
        public byte[] Encrypt(byte[] publicKey, string secretMessage)
        {
            byte[] encryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = this.diffieHellman.DeriveKeyMaterial(key); // "Common secret"

            this.aes.Key = derivedKey;

            using (var cipherText = new MemoryStream())
            {
                using (var encryptor = this.aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(cipherText, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    }
                }

                encryptedMessage = cipherText.ToArray();
            }

            return encryptedMessage;
        }

        public string Decrypt(byte[] publicKey, byte[] encryptedMessage, byte[] iv)
        {
            string decryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = this.diffieHellman.DeriveKeyMaterial(key);

            this.aes.Key = derivedKey;
            this.aes.IV = iv;

            using (var plainText = new MemoryStream())
            {
                using (var decryptor = this.aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(plainText, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
                    }
                }

                decryptedMessage = Encoding.UTF8.GetString(plainText.ToArray());
            }

            return decryptedMessage;
        }
        #endregion

        #region IDisposable Members
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (this.aes != null)
                    this.aes.Dispose();

                if (this.diffieHellman != null)
                    this.diffieHellman.Dispose();
            }
        }
        #endregion

        public static void Main(string[] args)
        {
            string text = "Way! ";

            using (var bob = new DiffieHellman())
            {
                using (var alice = new DiffieHellman())
                {
                    // Bob uses Alice's public key to encrypt his message.
                    Console.Write("Bob Public Key:");
                    foreach (byte b in bob.PublicKey)
                    {
                        Console.Write(" " + b);
                    }
                    Console.Write("\n\nAlice Public Key:");
                    foreach (byte b in alice.PublicKey)
                    {
                        Console.Write(" " + b);
                    }

                    byte[] secretMessage = bob.Encrypt(alice.PublicKey, text);
                    Console.Write("\n\nSecret Message:");
                    foreach (byte b in secretMessage)
                    {
                        Console.Write(" "+b);
                    }

                    // Alice uses Bob's public key and IV to decrypt the secret message.
                    string decryptedMessage = alice.Decrypt(bob.PublicKey, secretMessage, bob.IV);
                    Console.WriteLine("\n"+decryptedMessage);
                }
            };
            
        }
        
    }
}
