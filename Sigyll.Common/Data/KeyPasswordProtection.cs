#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Text;

namespace Sigyll.Common.Data;

/// <summary>
/// Encrypts the passwords of stored private keys (<c>PfxPassword</c>, <c>KeyPassword</c>) with a 256-bit master key
/// kept outside the database, so that reading the database alone does not yield usable keys.
/// <para>
/// Stored form: <c>enc:v1:</c> + base64(nonce | ciphertext | tag), AES-256-GCM. A value without the prefix is a
/// password written before a master key was configured; it reads back as it is and
/// <see cref="KeyPasswordMigration"/> encrypts it.
/// </para>
/// <para>
/// The master key is process-wide because <see cref="SigyllDbContext"/> applies it through an EF value converter, and
/// EF builds the model once per process. Set it once at startup with <see cref="UseMasterKey"/>.
/// </para>
/// </summary>
public static class KeyPasswordProtection
{
    public const string Prefix = "enc:v1:";
    public const int MasterKeyLength = 32;

    private const int NonceLength = 12;
    private const int TagLength = 16;

    private static byte[]? _masterKey;

    /// <summary>True once a master key is set; until then passwords are stored as they are.</summary>
    public static bool IsEnabled => Volatile.Read(ref _masterKey) is not null;

    public static void UseMasterKey(ReadOnlySpan<byte> masterKey)
    {
        if (masterKey.Length != MasterKeyLength)
        {
            throw new ArgumentException($"The key-password master key must be {MasterKeyLength} bytes.", nameof(masterKey));
        }

        Volatile.Write(ref _masterKey, masterKey.ToArray());
    }

    /// <summary>Reads a master key written as base64 (the form kept in Vault and configuration).</summary>
    public static byte[] ParseMasterKey(string base64)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64.Trim());
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("The key-password master key is not valid base64.");
        }

        if (key.Length != MasterKeyLength)
        {
            throw new InvalidOperationException(
                $"The key-password master key must be {MasterKeyLength} bytes (base64 of {MasterKeyLength} random bytes); it is {key.Length}.");
        }

        return key;
    }

    public static bool IsProtected(string? value) => value?.StartsWith(Prefix, StringComparison.Ordinal) == true;

    /// <summary>Encrypts with the process master key; returns the value unchanged when none is set.</summary>
    public static string Protect(string value)
    {
        var key = Volatile.Read(ref _masterKey);
        return key is null || IsProtected(value) ? value : Protect(value, key);
    }

    /// <summary>Decrypts with the process master key; a value without the prefix is returned unchanged.</summary>
    public static string Unprotect(string value)
    {
        if (!IsProtected(value))
        {
            return value;
        }

        var key = Volatile.Read(ref _masterKey)
            ?? throw new InvalidOperationException(
                "Stored key passwords are encrypted, but no key-password master key is configured. " +
                "Set Vault:KeyProtectionPath (with Vault AppRole credentials) or KeyProtection:MasterKey.");
        return Unprotect(value, key);
    }

    public static string Protect(string value, byte[] key)
    {
        var plaintext = Encoding.UTF8.GetBytes(value);
        var payload = new byte[NonceLength + plaintext.Length + TagLength];
        var nonce = payload.AsSpan(0, NonceLength);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, payload.AsSpan(NonceLength, plaintext.Length),
            payload.AsSpan(NonceLength + plaintext.Length, TagLength));

        return Prefix + Convert.ToBase64String(payload);
    }

    public static string Unprotect(string value, byte[] key)
    {
        var payload = Convert.FromBase64String(value[Prefix.Length..]);
        if (payload.Length < NonceLength + TagLength)
        {
            throw new CryptographicException("Encrypted key password is truncated.");
        }

        var cipherLength = payload.Length - NonceLength - TagLength;
        var plaintext = new byte[cipherLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(payload.AsSpan(0, NonceLength), payload.AsSpan(NonceLength, cipherLength),
            payload.AsSpan(NonceLength + cipherLength, TagLength), plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }
}
