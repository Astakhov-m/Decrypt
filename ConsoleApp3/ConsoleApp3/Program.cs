using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp3
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            InfoFinder();

        }
        static void InfoFinder()
        {
            string arg = "c40000000108319486c1391eb98000404600566030209ccd08bf1cda097b469ce675a2ea98056860b2722f6b727c5bdb65e7706d8eca2e61b800087cf7e9ab4851fc76cb55aaf5e0d43a8fe303ea2b998f18e74820e4c944896b74f6a663e0f9f343661c84934f641a9ec4d48fb7ff15d053f128308e85682ea8cb280c2b7c7bd39af5064ac52d628df28fd9cd8bc1c688c07d43c354f73815f648fb5be42108c19e6798a94fdf5e0310e47e005e4c88ff11719dbf9dbcf4c0b3f38423c04a6177a23af91fb535478e4936f95a2872a90013c3d60e94a492cc2490ae7d53bb2eaf2228448396318cfd7dd58375e3352fb2741fe0d62657d3334fb8d1da08de646679b7daf66f613178a25364d0b9cf3cf26b5db6c39059b59eafcaf05bfe5a318a9281fe1e2faac426e752a4d86f7e8ba36d535564f79a625ab95c7d7f376e15b81f02bb5d00c1c8b445a8db0193d9aa16cbda648639669cf029ae69b1b63c623bd05af5f76f57adfb9e55f57a40215e63164923293ad0f121acefd6e6e1c3f04d99f18a900d0ce158da3f51478592db7bbc91408fec73a5a3e33f765baab35ba6f8d18a17ac7922c5cc17d866fe34d1fea899551daf1ae3e4da5dae326583802cadab8cfdf6c0e15c67361db8b78600bfba42a5624a2479a26a619605314d8e3fc44626e861501910a86ccb9787c15de4de8b6a56608c0e94b057fb2c2014b435abaa93537329b3037b4d0cefee859f11d4ed2794a6f5b5caf32c80f8a436cbc126ff5081e8ad7394e558e4fc36d087c81f92fe8f2fddd6cab8f0297a84c916b7afed72228d9474c392dd591724b4e4567e89d8507e124ca69df3a1a517ab6e138e9e2b7041480af4513032a74203527b77c2e11e21bf32d2d0a5ee86e463f43fe62f8fb377dea1b9b256b418d2cbbe1c05454a7962c9fe510fb9dab8db126b27af986ea06e2a6bc6f9d621e2fc37617a8a506f036e61c305dd16f84d97dddeafe049465a0a2cc14fa03901ad782613fcf9900c9e9fd18021d5a3cb78c777af537c26a93f3fc48b3f6c352e97362b4b6d99923675c6b89ed67150359ca47ebc66bd0d52abb65b4f00700adaa07b37c1f0f1f1d270dfd49a4130f442743d283eb67e539e8bcb26d45eb8b2e901d41fb6e1600f323c5714f6da19182f59da9db9f39dfec1ccee162422f991be6514f2ae5c57a74786eb32ee61c8ba0b1faa2de7e3d6167102c69329c8beefa69debea7eb2089d56c72ca0753f026b307fe08d94960541931c0c318cf25a1fade60be2e279cf20861eab1b1690e70c01c428803a22440785f8088869e6f316bcc361786b118d3363b5acc9c40de4ce935ec7b2768c504709036160640d7abe2df75af127a70e0882aa30517d58668d3d527d161cc6a89000c4d4a6f2b98f282baf0707fbb67a09322fc923258149981597616008f4934f312b35d04f838f74f77ffd10451aa9c6ce31cf6d23b2f3ef0b6994c89ded06ace6358c7fc484321d024eb32fb28a07246aafc58005fa3c8107dff0530ad6cc92ffbf5c042f0e9e6433c37c8b2f9a8be3e2f86c20c8783b76470693bc37f460c40ba8b08417d2a15080f6cb8aa73836141e786e28d25eaf4ea0ee36c344a629f3a38da8f1e5233b0cccf1ca08492e976a91ae859ac3d09869957815ae42224a2b09e83fb7ddf3f72d8558809ea0a6a7932443c59bf07df755701a8099216d1e6f8b84495d75453ef4d5a4b91ee0a7eba2bf81afa887c00580872e6dd11eacb1";
            byte[] encodeBytesArray = StringToByteArray(arg);
            const int flagByteNumber = 0;

            byte byte_public_flag = encodeBytesArray[flagByteNumber];
            int[] flagInBits = FlagToInfo(byte_public_flag);

            int versionNumber = 1;

            int[] byteVersion = new int[4];
            for(var i = 0; i < 4; i++)
            {
                byteVersion[i] = encodeBytesArray[i + 1];
            }
            int Version = byteVersion.Sum();

            int DestCurentIDLengthNumber = 5;

            int byteDestCurentIDLength = encodeBytesArray[DestCurentIDLengthNumber];
            int[] byteDestCurentID = new int[byteDestCurentIDLength];
            for (var i = 0; i< byteDestCurentIDLength; i++)
            {
                byteDestCurentID[i] = encodeBytesArray[DestCurentIDLengthNumber + 1 + i];
            }

            int SourceConnectionIDLengthNumber = DestCurentIDLengthNumber + byteDestCurentIDLength + 1;

            int SourceConnectionIDLength = encodeBytesArray[SourceConnectionIDLengthNumber];
            if (SourceConnectionIDLength > 0)
            {
                int[] SourceConnectionID = new int[SourceConnectionIDLength];
                for(var i = 0; i < SourceConnectionIDLength; i++)
                {
                    SourceConnectionID[i] = encodeBytesArray[SourceConnectionIDLengthNumber + 1 + i];
                }
            }

            int TokenLengthNumber = SourceConnectionIDLengthNumber + SourceConnectionIDLength + 1;
            int TokenLength = 0;
            int lengthNumber = 0;
            if (encodeBytesArray[TokenLengthNumber] != 0)
            {
                TokenLength = (encodeBytesArray[TokenLengthNumber] % 16) * 256 + encodeBytesArray[TokenLengthNumber + 1];
                int[] Token = new int[TokenLength];

                lengthNumber = TokenLengthNumber + TokenLength + 2;
            }
            else
            {
                TokenLength = 0;
                lengthNumber = TokenLengthNumber + 1;
            }
            int length = (encodeBytesArray[lengthNumber]%16)*256 + encodeBytesArray[lengthNumber + 1];//TODO: 1-st byte of length number != 44

            int pacetNumberNumber = lengthNumber + 2;
            //int pacetNumber = GetPacetNumber(flagInBits[6], flagInBits[7]);

            Console.WriteLine(length);

            int[] payload = new int[length-1];
            for (var i = 0; i < length-1; i++)
            {
                payload[i] = encodeBytesArray[pacetNumberNumber + 1 + i];
            }
            // check sample start pos
            int sampleStartPose = pacetNumberNumber + 5;
            int[] sample = new int[16];
            for(var i = 0; i < 16; i++)
            {
                sample[i] = encodeBytesArray[sampleStartPose + i];
            }
            Console.WriteLine(sample[0]);
            Console.WriteLine(sample[15]);

            var decryptedData = Decrypt(sample, GetRijndaelManaged(sample));
            for(var i = 0; i < sample.Length; i++)
            {
                Console.Write(sample[i]);
                Console.Write(" | ");
                Console.WriteLine(decryptedData[i]);
            }


        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        //public static int GetPacetNumber(int num1, int num2)
        //{//TODO: pacet number bytes != 00
        //    if( num1 == num2 && num1 == 0)
        //    {
        //        return 1;
        //    }
        //        return 2;
            
        //}

        public static int[] FlagToInfo(byte number)
        {
            int num = number;
            int[] flag = new int[8];
            for (byte i = 0; i < 8; i++)
            {
                flag[i] = num % Convert.ToInt32(Math.Pow(2, i));
            }
            return flag;
        }



        ////////

        public static RijndaelManaged GetRijndaelManaged(int[] secretKey)
        {
            byte[] secretKeyBytes = new byte[secretKey.Length];
            for(var i = 0; i < secretKey.Length; i++)
            {
                secretKeyBytes[i] = Convert.ToByte(secretKey[i]);
            }
            var keyBytes = new byte[16];
            Array.Copy(secretKeyBytes, keyBytes, Math.Min(keyBytes.Length, secretKeyBytes.Length));
            return new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None,
                KeySize = 128,
                BlockSize = 128,
                Key = keyBytes,
                IV = keyBytes
            };
        }

        //public byte[] Encrypt(byte[] plainBytes, RijndaelManaged rijndaelManaged)
        //{
        //    return rijndaelManaged.CreateEncryptor()
        //        .TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        //}

        public static byte[] Decrypt(int[] encryptedData, RijndaelManaged rijndaelManaged)
        {
            byte[] data = new byte[encryptedData.Length];
            for(var i = 0; i < encryptedData.Length; i++)
            {
                data[i] = Convert.ToByte(encryptedData[i]);
            }
            return rijndaelManaged.CreateDecryptor()
                .TransformFinalBlock(data, 0, data.Length);
        }


        // Encrypts plaintext using AES 128bit key and a Chain Block Cipher and returns a base64 encoded string

        //public String Encrypt(String plainText, String key)
        //{
        //    var plainBytes = Encoding.UTF8.GetBytes(plainText);
        //    return Convert.ToBase64String(Encrypt(plainBytes, GetRijndaelManaged(key)));
        //}


        //public String Decrypt(String encryptedText, String key)
        //{
        //    var encryptedBytes = Convert.FromBase64String(encryptedText);
        //    return Encoding.UTF8.GetString(Decrypt(encryptedBytes, GetRijndaelManaged(key)));
        //}

    }
}
