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
            string arg = "ce0000000108350dce7aa59f6058000044d01127cff2decab2ad37df69b115631668fc919e522b9ff37eaa64299c2b7fcabfbfa322b44d33c5810998e2078ed2b0acdd47cded3ae5f2e5ee8dc901865432e56d6bfa9ed42e0be4b0e4fdde1e35200d087b19dfaea75fed0693eb510321839dd256234a61d7d94759d9f1017db592530885c3e45295615724cef85a34a0d2f714d2d84c8af8cb4862e2bb840cb52e95b62b5e41e5ecf3e17b70a3f3e4c9b0d02f1aaf746347af8e7cdbf2e6d1b7ea1d88f5c5165197ab9aa5590c732210793cb6d6ea202fa16902d998a36723604ed254fddc86530d24f344b18eb1cc687c08930403fc4e25445bb63890e158d85d78d5e3b094f00665c86f940aed64de16020a92f1cbd5bc174530f19905d69bd53ed85fee3526f75216541614c2712c1bfd3546e3f015229e830a15f8e4d6cadb68b5192e13bbc9cd0c81f417f3532644580e678d9ffb007775c4c1fbeffd53f3d682c0c55de4b2c26821ee794fed5b6065e427d8270d07c42d3ba0336aedb28754a6580b703fe6588ae4c36e961c3323d14bcd7130973b0e9de446062b6d73df0bdfeab8b9aef32c29c24e6afc4f868121c44fa389027f510824d0033e8dfb6fc0b10246e2b7045fe5719e1ca7f9987a85f02e98291718c8fef98480258b3ba806d09c762982be1f5b86e56c423c00277cb922c349fe8d0c8f743ba6ea2e8a0a42097c18484036f74bf50deec0bce43afc92b0362e188003754348b336286d91cb2f33efd5d28ca02140bf87fc37b0a23c9c3f75d3b1c2e8950f5edafbf8a0a5f7357b7cf3df6a812d8f88aaa8e9bd5b2348e8334a1099cfb79eeb9d9ccd416548052acd99c29700c74d15c2f33184764be97b496d9ea5e4aae9d527adac929fea7402497b622acc4e248883f8f3d867952967099bb8d1d12d0ccd663f7ffc44c08a1ffd5e8be1ea5d0e2881b376056f1c9ff279d904d3ed620baf902bd79026262b6d69b737edde73e5ab4442aa4cd95fbf55d49fca6cc503a2758441076260d50ee9f51eff7e370614ce996df6112da18b311f8ace1b4f5987a41931df09b2bd23cf35432b0cccabb674829324fae251647c5eb21b1de1346c2976368af1fa54e02fe58e2f10b917496981ca391627937c4631a29b13448d3b6a495feb184220c50b5bd3907cb944a84710b3f32b882104233d6e8ec084a3eaa9ad9692a59deca5c3a5dbefd9166d52e473430cfdf6bfdbe00df9ffc786987ebacc8744068779c3a4feec9aa4cc12be76188469a3261ba44e162e983694c58adc0f33253b868a8087a2a14484d4c67b90d2d469ab1c82d1ff117f45c0419a69708413f06d1b47583fcb3422e069090003d8a26632fb44e9772a6a393b284c19f9ae8733fa5e6e0430a632ee77beff55d7da83d37b5f21a49e388bccc0afa8dbfa30477e9786ef7cb108ef32ecf3e5c3b9369ba66f45da79e7849f6b8c9e3dfd3f605ba7980181fb90156b527484cb4e26e5b118bc83f330f0dfa8c27e3b634aa4f9ffa2bacfcea3bb525a2113e3d303d47f856015db06545aee54c2a0037513013982e9572de8c98f600c502d18dbe248414b4e2be195a503565ec4bebb432e9f0b869ad58fcb0354a3c0d767898d750e235bcc8acbe5f918067d10851f71cac79c5b0f703bb796cd3b2ec5d15da1b5421c3ed0fd2c60fb59b84ebb22a1fbf1d9fb856536f1f5f2688df96359f523715224d6024a4cf46a99150d0cfa10d0c558bc56964d067a";
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
            int pacetNumber = GetPacetNumber(flagInBits[6], flagInBits[7]);

            Console.WriteLine(length);

            int[] payload = new int[length-1];
            for (var i = 0; i < length-1; i++)
            {
                payload[i] = encodeBytesArray[pacetNumberNumber + 1 + i];
            }
            // check sample start pos
            int sampleStartPose = pacetNumberNumber + 4;
            int[] sample = new int[16];
            for(var i = 0; i < 16; i++)
            {
                sample[i] = encodeBytesArray[sampleStartPose + i];
            }

            byte[] headerProtectionMask = Decrypt(sample, GetRijndaelManaged(sample));

            //byte decryptedFlags = ((byte)(byte_public_flag ^ headerProtectionMask[0]) & 0b00001111);

            Console.WriteLine(byte_public_flag);
            var initialSecret = extractInitialSecret(byteDestCurentID, byteVersion);
            //Console.WriteLine(extractInitialSecret(byteDestCurentID, byteVersion));

            var clientSecret = expandInitialClientSecret(initialSecret);
            Console.WriteLine($"clientSecret[0] = {clientSecret[0]}");

            var clientInitialKey = expandInitialQuicKey(clientSecret);
            Console.WriteLine($"InitialQuicKey[0] = {clientInitialKey[0]}");

            var clientInitialIV = expandInitialQuicIv(clientSecret);
            Console.WriteLine($"clientInitialIV[0] = {clientInitialIV[0]}");

            var headerProtectionSecret = expandInitialHeaderProtection(clientSecret);
            Console.WriteLine($"headerProtectionSecret[0] = {headerProtectionSecret[0]}");


        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static int GetPacetNumber(int num1, int num2)
        {//TODO: pacet number bytes != 00
            if( num1 == num2 && num1 == 0)
            {
                return 1;
            }
                return 2;
            
        }

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








        public static byte[] INITIAL_SALT_v1 = new byte[]{
            (byte) 0x38, (byte) 0x76, (byte) 0x2c, (byte) 0xf7, (byte) 0xf5, (byte) 0x59, (byte) 0x34, (byte) 0xb3, (byte) 0x4d, (byte) 0x17, (byte) 0x9a, (byte) 0xe6, (byte) 0xa4, (byte) 0xc8, (byte) 0x0c, (byte) 0xad, (byte) 0xcc, (byte) 0xbb, (byte) 0x7f, (byte) 0x0a

    };
        public static byte[] handshake_salt_draft_23 = new byte[]{
            (byte) 0xc3, (byte) 0xee, (byte) 0xf7, (byte) 0x12, (byte) 0xc7, (byte) 0x2e, (byte) 0xbb, (byte) 0x5a, (byte) 0x11, (byte) 0xa7, (byte) 0xd2, (byte) 0x43, (byte) 0x2b, (byte) 0xb4, (byte) 0x63, (byte) 0x65, (byte) 0xbe, (byte) 0xf9, (byte) 0xf5, (byte) 0x02,
    };
        public static byte[] handshake_salt_draft_22 = new byte[]{
            (byte) 0x7f, (byte) 0xbc, (byte) 0xdb, (byte) 0x0e, (byte) 0x7c, (byte) 0x66, (byte) 0xbb, (byte) 0xe9, (byte) 0x19, (byte) 0x3a,
            (byte) 0x96, (byte) 0xcd, (byte) 0x21, (byte) 0x51, (byte) 0x9e, (byte) 0xbd, (byte) 0x7a, (byte) 0x02, (byte) 0x64, (byte) 0x4a
    };
        public static byte[] handshake_salt_draft_29 = new byte[]{
            (byte) 0xaf, (byte) 0xbf, (byte) 0xec, (byte) 0x28, (byte) 0x99, (byte) 0x93, (byte) 0xd2, (byte) 0x4c, (byte) 0x9e, (byte) 0x97,
            (byte) 0x86, (byte) 0xf1, (byte) 0x9c, (byte) 0x61, (byte) 0x11, (byte) 0xe0, (byte) 0x43, (byte) 0x90, (byte) 0xa8, (byte) 0x99
    };
        public static byte[] hanshake_salt_draft_q50 = new byte[]{
            (byte) 0x50, (byte) 0x45, (byte) 0x74, (byte) 0xEF, (byte) 0xD0, (byte) 0x66, (byte) 0xFE, (byte) 0x2F, (byte) 0x9D, (byte) 0x94,
            (byte) 0x5C, (byte) 0xFC, (byte) 0xDB, (byte) 0xD3, (byte) 0xA7, (byte) 0xF0, (byte) 0xD3, (byte) 0xB5, (byte) 0x6B, (byte) 0x45
    };
        public static byte[] hanshake_salt_draft_t50 = new byte[]{
            (byte) 0x7f, (byte) 0xf5, (byte) 0x79, (byte) 0xe5, (byte) 0xac, (byte) 0xd0, (byte) 0x72, (byte) 0x91, (byte) 0x55, (byte) 0x80,
            (byte) 0x30, (byte) 0x4c, (byte) 0x43, (byte) 0xa2, (byte) 0x36, (byte) 0x7c, (byte) 0x60, (byte) 0x48, (byte) 0x83, (byte) 0x10
    };
        public static byte[] hanshake_salt_draft_t51 = new byte[]{
            (byte) 0x7a, (byte) 0x4e, (byte) 0xde, (byte) 0xf4, (byte) 0xe7, (byte) 0xcc, (byte) 0xee, (byte) 0x5f, (byte) 0xa4, (byte) 0x50,
            (byte) 0x6c, (byte) 0x19, (byte) 0x12, (byte) 0x4f, (byte) 0xc8, (byte) 0xcc, (byte) 0xda, (byte) 0x6e, (byte) 0x03, (byte) 0x3d
    };
        public static byte[] handshake_salt_v2_draft_00 = new byte[]{
            (byte) 0xa7, (byte) 0x07, (byte) 0xc2, (byte) 0x03, (byte) 0xa5, (byte) 0x9b, (byte) 0x47, (byte) 0x18, (byte) 0x4a, (byte) 0x1d,
            (byte) 0x62, (byte) 0xca, (byte) 0x57, (byte) 0x04, (byte) 0x06, (byte) 0xea, (byte) 0x7a, (byte) 0xe3, (byte) 0xe5, (byte) 0xd3
    };

        public static byte[] extractInitialSecret( int[] byteDestCurentID, int[] byteVersion)
        {
            byte[] initialSecret;
            int version = getIetfDraftVersion(byteVersion);
            if (version == 0x51303530)
                initialSecret = hanshake_salt_draft_q50;
            else if (version == 0x54303531)
            {
                initialSecret = hanshake_salt_draft_t51;
            }
            else if (version <= 22)
            {
                initialSecret = handshake_salt_draft_22;
            }
            else if (version <= 28)
            {
                initialSecret = handshake_salt_draft_23;
            }
            else if (version <= 32)
            {
                initialSecret = handshake_salt_draft_29;
            }
            else if (version <= 34)
            {
                initialSecret = INITIAL_SALT_v1;
            }
            else
            {
                initialSecret = handshake_salt_v2_draft_00;
            }
            byte[] DESTID = new byte[byteDestCurentID.Length];
            for( var i = 0; i< byteDestCurentID.Length; i++)
            {
                DESTID[i] = (byte)byteDestCurentID[i];
            }

            return HKDF.Extract(HashAlgorithmName.SHA256, DESTID, initialSecret);
        }

        public static int getIetfDraftVersion(int[] versionArray)
        {
            int version = versionArray[3] + versionArray[2] * 16 + versionArray[1] * 16 * 16 + versionArray[0] * 16 * 16 * 16;
            if (version >> 8 == 0xff0000)
            {
                return version;
            }
            if (version == 0xfaceb001)
            {
                return 22;
            }
            if (version == 0xfaceb002 || version == 0xfaceb00e)
            {
                return 27;
            }
            if (version == 0x51303530 ||
                version == 0x54303530 ||
                version == 0x54303531)
            {
                return 27;
            }
            if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
            {
                return 29;
            }
            if (version == 0x00000001)
            {
                return 34;
            }
            if (version == 0x709A50C4)
            {
                return 100;
            }
            return 0;
        }

            static byte[] lableClientSecret = {(byte)0x63, (byte)0x6c, (byte)0x69, (byte)0x65,
                    (byte)0x6e, (byte)0x74, (byte)0x20, (byte)0x69, (byte)0x6e};
        static byte[] lableQuic_Key = {(byte)0x71, (byte)0x75, (byte)0x69, (byte)0x63, (byte)0x20,
                    (byte)0x6b, (byte)0x65, (byte)0x79};
        static byte[] lableQUIC_IV =
            new byte[] { (byte)0x71, (byte)0x75, (byte)0x69, (byte)0x63, (byte)0x20, (byte)0x69, (byte)0x76 };
        static byte[] lableQUIC_HP =
            new byte[]{(byte)0x71, (byte)0x75, (byte)0x69, (byte)0x63, (byte)0x20, (byte)0x68, (byte)0x70};
    public static byte[] expandInitialClientSecret(byte[] initialSecret)
        {

            return HKDF.Expand(HashAlgorithmName.SHA256, initialSecret, (256 / 8), lableClientSecret);
            
        }

        public static byte[] expandInitialQuicKey(byte[] initialSecret)
        {
            return HKDF.Expand(HashAlgorithmName.SHA256,
                    initialSecret,(128 / 8), lableQuic_Key);
        }

        public static byte[] expandInitialQuicIv(byte[] initialSecret)
        {
            return HKDF.Expand(HashAlgorithmName.SHA256,
                    initialSecret, (96 / 8), lableQUIC_IV);
        }

        public static byte[] expandInitialHeaderProtection(byte[] initialSecret)
        {
            return HKDF.Expand(HashAlgorithmName.SHA256,
                    initialSecret, 16, lableQUIC_HP);
        }
    }
}
