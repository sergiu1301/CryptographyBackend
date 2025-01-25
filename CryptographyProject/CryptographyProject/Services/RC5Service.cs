using System.Text;

namespace CryptographyProject.Services;

public static class RC5Service
{
    /// <summary>
    /// Encrypts the given plaintext (string) using RC5 with parameters w, r.
    /// Returns the ciphertext as a hexadecimal string.
    /// </summary>
    public static string Encrypt(int w, int r, string plainText, string keyString)
    {
        // Validate input parameters
        ValidateInputs(w, r, keyString);

        // 1. Get P and Q for the given word size w (16, 32, or 64).
        (ulong P, ulong Q) = ComputePQ(w);

        // 2. Convert the user key (string) to b bytes.
        byte[] userKey = Encoding.UTF8.GetBytes(keyString);

        // 3. Build subkeys array S using a generic key schedule.
        ulong[] S = KeyScheduleGeneric(w, r, userKey, P, Q);

        // 4. Convert plaintext to bytes and pad to a multiple of block size (2*w bits).
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        plainBytes = PadToBlock(plainBytes, w);

        // 5. Encrypt each block of (2*w)/8 bytes.
        int blockSizeBytes = (2 * w) / 8;
        for (int offset = 0; offset < plainBytes.Length; offset += blockSizeBytes)
        {
            // Read A, B
            ulong A = ReadUlong(plainBytes, offset, w);
            ulong B = ReadUlong(plainBytes, offset + blockSizeBytes / 2, w);

            // A += S[0], B += S[1]
            A = ModAdd(A, S[0], w);
            B = ModAdd(B, S[1], w);

            // r rounds
            for (int i = 1; i <= r; i++)
            {
                A ^= B;
                A = RotateLeft(A, (int)(B & ((ulong)w - 1)), w);
                A = ModAdd(A, S[2 * (ulong)i], w);

                B ^= A;
                B = RotateLeft(B, (int)(A & ((ulong)w - 1)), w);
                B = ModAdd(B, S[2 * (ulong)i + 1], w);
            }

            // Write A, B back to the byte array
            WriteUlong(plainBytes, offset, A, w);
            WriteUlong(plainBytes, offset + blockSizeBytes / 2, B, w);
        }

        // 6. Return the result as a hex string
        return BitConverter.ToString(plainBytes).Replace("-", "");
    }

    /// <summary>
    /// Decrypts the given ciphertext (hex string) using RC5 with parameters w, r.
    /// Returns the plaintext as a UTF-8 string.
    /// </summary>
    public static string Decrypt(int w, int r, string cipherHex, string keyString)
    {
        // Validate input parameters
        ValidateInputs(w, r, keyString);

        (ulong P, ulong Q) = ComputePQ(w);
        byte[] userKey = Encoding.UTF8.GetBytes(keyString);

        // Build subkeys
        ulong[] S = KeyScheduleGeneric(w, r, userKey, P, Q);

        // Convert hex -> bytes
        byte[] cipherBytes = HexToBytes(cipherHex);
        int blockSizeBytes = (2 * w) / 8;

        // Decrypt each block
        for (int offset = 0; offset < cipherBytes.Length; offset += blockSizeBytes)
        {
            ulong A = ReadUlong(cipherBytes, offset, w);
            ulong B = ReadUlong(cipherBytes, offset + blockSizeBytes / 2, w);

            // Rounds in reverse
            for (int i = r; i >= 1; i--)
            {
                B = ModSub(B, S[2 * (ulong)i + 1], w);
                B = RotateRight(B, (int)(A & ((ulong)w - 1)), w);
                B ^= A;

                A = ModSub(A, S[2 * (ulong)i], w);
                A = RotateRight(A, (int)(B & ((ulong)w - 1)), w);
                A ^= B;
            }

            B = ModSub(B, S[1], w);
            A = ModSub(A, S[0], w);

            // Write result
            WriteUlong(cipherBytes, offset, A, w);
            WriteUlong(cipherBytes, offset + blockSizeBytes / 2, B, w);
        }

        // Remove padding and convert to string
        cipherBytes = RemovePadding(cipherBytes, w);
        return Encoding.UTF8.GetString(cipherBytes);
    }

    // ------------------------------------------------------------------------
    // Key Schedule
    // ------------------------------------------------------------------------
    /// <summary>
    /// Builds subkeys for RC5 generically (supports w=16,32,64) in a single approach.
    /// </summary>
    private static ulong[] KeyScheduleGeneric(int w, int r, byte[] userKey, ulong P, ulong Q)
    {
        // 1. Build array L of length c = b / (w/8)
        int b = userKey.Length;
        int countChars = w / 8;
        int c = (int)Math.Ceiling((double)Math.Max(b, 1) / countChars);
        ulong[] L = new ulong[c];

        // Fill L[i] (little-endian)
        for (int i = b - 1; i >= 0; i--)
        {
            int index = i / countChars;
            L[index] = (L[index] << 8) + userKey[i];
        }

        for (int i = 0; i < c; i++)
        {
            L[i] &= MaskFor(w);
        }

        // 2. Build array S of size 2*(r+1)
        int t = 2 * (r + 1);
        ulong[] S = new ulong[t];
        S[0] = P;
        for (int i = 1; i < t; i++)
        {
            S[i] = ModAdd(S[i - 1], Q, w);
        }

        // 3. Mix S and L
        ulong A = 0, B = 0;
        int iIndex = 0, jIndex = 0;
        int n = 3 * Math.Max(t, c);

        for (int k = 0; k < n; k++)
        {
            S[iIndex] = RotateLeft(ModAdd(S[iIndex], A, w) + B, 3, w);
            A = S[iIndex];

            L[jIndex] = RotateLeft(ModAdd(L[jIndex], A, w) + B, (int)((A + B) & ((ulong)w - 1)), w);
            B = L[jIndex];

            iIndex = (iIndex + 1) % t;
            jIndex = (c > 0) ? (jIndex + 1) % c : 0;
        }

        return S;
    }

    // ------------------------------------------------------------------------
    // Compute (P, Q) constants depending on w
    // ------------------------------------------------------------------------
    private static (ulong, ulong) ComputePQ(int w)
    {
        switch (w)
        {
            case 16:
                // P16=0xB7E1, Q16=0x9E37
                return (0xB7E1UL, 0x9E37UL);
            case 32:
                // P32=0xB7E15163, Q32=0x9E3779B9
                return (0xB7E15163UL, 0x9E3779B9UL);
            case 64:
                // P64=0xB7E151628AED2A6B, Q64=0x9E3779B97F4A7C15
                return (0xB7E151628AED2A6BUL, 0x9E3779B97F4A7C15UL);
            default:
                throw new ArgumentException("RC5 supports only w=16,32,64.");
        }
    }

    // ------------------------------------------------------------------------
    // Rotate, mod-add, mod-sub
    // ------------------------------------------------------------------------
    private static ulong RotateLeft(ulong x, int shift, int w)
    {
        switch (w)
        {
            case 16:
                shift &= 15;
                x &= 0xFFFF;
                return ((x << shift) | (x >> (16 - shift))) & 0xFFFF;
            case 32:
                shift &= 31;
                x &= 0xFFFFFFFF;
                return ((x << shift) | (x >> (32 - shift))) & 0xFFFFFFFF;
            case 64:
                shift &= 63;
                return (x << shift) | (x >> (64 - shift));
            default:
                throw new ArgumentException("w must be 16, 32, or 64.");
        }
    }

    private static ulong RotateRight(ulong x, int shift, int w)
    {
        switch (w)
        {
            case 16:
                shift &= 15;
                x &= 0xFFFF;
                return ((x >> shift) | (x << (16 - shift))) & 0xFFFF;
            case 32:
                shift &= 31;
                x &= 0xFFFFFFFF;
                return ((x >> shift) | (x << (32 - shift))) & 0xFFFFFFFF;
            case 64:
                shift &= 63;
                return (x >> shift) | (x << (64 - shift));
            default:
                throw new ArgumentException("w must be 16, 32, or 64.");
        }
    }

    private static ulong ModAdd(ulong a, ulong b, int w)
    {
        // (a + b) mod 2^w
        return (a + b) & MaskFor(w);
    }

    private static ulong ModSub(ulong a, ulong b, int w)
    {
        // (a - b) mod 2^w
        return (a - b) & MaskFor(w);
    }

    private static ulong MaskFor(int w)
    {
        return w switch
        {
            16 => 0xFFFFUL,
            32 => 0xFFFFFFFFUL,
            64 => 0xFFFFFFFFFFFFFFFFUL,
            _ => throw new ArgumentException("Invalid w"),
        };
    }

    private static byte[] PadToBlock(byte[] data, int w)
    {
        // Each block is 2*w bits => (2*w)/8 bytes
        int blockBytes = (2 * w) / 8;
        int pad = blockBytes - (data.Length % blockBytes);
        if (pad == blockBytes) pad = 0;

        byte[] result = new byte[data.Length + pad];
        Array.Copy(data, result, data.Length);

        for (int i = data.Length; i < result.Length; i++)
        {
            result[i] = (byte)pad;
        }
        return result;
    }

    private static byte[] RemovePadding(byte[] data, int w)
    {
        if (data.Length == 0) return data;
        int blockBytes = (2 * w) / 8;

        int pad = data[data.Length - 1];
        if (pad < 1 || pad > blockBytes) return data;

        int newLen = data.Length - pad;
        if (newLen < 0) return data;

        byte[] result = new byte[newLen];
        Array.Copy(data, result, newLen);
        return result;
    }

    /// <summary>
    /// Reads w bits from the byte array (little-endian) into a ulong, then masks it.
    /// </summary>
    private static ulong ReadUlong(byte[] data, int offset, int w)
    {
        ulong val = 0;
        int bytes = w / 8;
        for (int i = 0; i < bytes; i++)
        {
            val |= ((ulong)data[offset + i]) << (8 * i);
        }
        return val & MaskFor(w);
    }

    /// <summary>
    /// Writes w bits (from a ulong) into the byte array at offset in little-endian order.
    /// </summary>
    private static void WriteUlong(byte[] data, int offset, ulong val, int w)
    {
        val &= MaskFor(w);
        int bytes = w / 8;
        for (int i = 0; i < bytes; i++)
        {
            data[offset + i] = (byte)(val >> (8 * i));
        }
    }

    /// <summary>
    /// Converts hex string to byte[].
    /// </summary>
    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex length.");

        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return result;
    }

    /// <summary>
    /// Validates RC5 input parameters.
    /// </summary>
    private static void ValidateInputs(int w, int r, string key)
    {
        // Validate word size
        if (w != 16 && w != 32 && w != 64)
            throw new ArgumentException("Invalid word size. Only 16, 32, or 64 are allowed.");

        // Validate number of rounds
        if (r < 0 || r > 255)
            throw new ArgumentException("Invalid number of rounds. Must be between 0 and 255.");

        // Validate key length
        int keyBits = Encoding.UTF8.GetBytes(key).Length * 8;
        if (keyBits > 2040)
            throw new ArgumentException("Invalid key length. Key size must not exceed 2040 bits.");
    }
}