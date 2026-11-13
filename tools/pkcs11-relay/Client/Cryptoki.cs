#if CRYPTOKI_WINDOWS
global using CK_ULONG = uint;
#else
global using CK_ULONG = nuint;
#endif

using System.Runtime.InteropServices;

namespace Sigyll.Pkcs11Relay;

// The Cryptoki structures the caller passes by pointer, laid out as the platform's header lays them out: packed to
// one byte on Windows, naturally aligned elsewhere.

#if CRYPTOKI_WINDOWS
[StructLayout(LayoutKind.Sequential, Pack = 1)]
#else
[StructLayout(LayoutKind.Sequential)]
#endif
internal unsafe struct CK_ATTRIBUTE
{
    public CK_ULONG type;
    public void* pValue;
    public CK_ULONG ulValueLen;
}

#if CRYPTOKI_WINDOWS
[StructLayout(LayoutKind.Sequential, Pack = 1)]
#else
[StructLayout(LayoutKind.Sequential)]
#endif
internal unsafe struct CK_MECHANISM
{
    public CK_ULONG mechanism;
    public void* pParameter;
    public CK_ULONG ulParameterLen;
}

/// <summary>
/// Writes a structure of byte arrays and CK_ULONGs into the caller's memory, field by field, with the platform's
/// layout.
/// </summary>
internal unsafe ref struct StructWriter(void* target)
{
    private readonly byte* _start = (byte*)target;
    private int _offset;

    public void Bytes(ReadOnlySpan<byte> value)
    {
        value.CopyTo(new Span<byte>(_start + _offset, value.Length));
        _offset += value.Length;
    }

    public void ULong(ulong value)
    {
#if !CRYPTOKI_WINDOWS
        _offset = (_offset + sizeof(CK_ULONG) - 1) / sizeof(CK_ULONG) * sizeof(CK_ULONG);
#endif
        *(CK_ULONG*)(_start + _offset) = Cryptoki.Narrow(value);
        _offset += sizeof(CK_ULONG);
    }
}

internal static unsafe class Cryptoki
{
    /// <summary>The 64-bit wire value as this platform's CK_ULONG; "all ones" (unavailable information) stays all ones.</summary>
    public static CK_ULONG Narrow(ulong value) => value == Wire.Unavailable ? CK_ULONG.MaxValue : (CK_ULONG)value;

    public static ulong Widen(CK_ULONG value) => value == CK_ULONG.MaxValue ? Wire.Unavailable : value;

    /// <summary>
    /// Attributes whose value is a single CK_ULONG, so its size differs between platforms. Everything else is a
    /// byte string, a one-byte boolean or a date, and is the same everywhere.
    /// </summary>
    public static bool IsULongAttribute(ulong type) => type is
        0x000   // CKA_CLASS
        or 0x080   // CKA_CERTIFICATE_TYPE
        or 0x087   // CKA_CERTIFICATE_CATEGORY
        or 0x088   // CKA_JAVA_MIDP_SECURITY_DOMAIN
        or 0x08C   // CKA_NAME_HASH_ALGORITHM
        or 0x100   // CKA_KEY_TYPE
        or 0x121   // CKA_MODULUS_BITS
        or 0x133   // CKA_PRIME_BITS
        or 0x134   // CKA_SUBPRIME_BITS
        or 0x160   // CKA_VALUE_BITS
        or 0x161   // CKA_VALUE_LEN
        or 0x166   // CKA_KEY_GEN_MECHANISM
        or 0x300   // CKA_HW_FEATURE_TYPE
        or 0x500;  // CKA_MECHANISM_TYPE

    /// <summary>Writes a template's attributes (type and value) to a request.</summary>
    public static void WriteTemplate(BinaryWriter request, CK_ATTRIBUTE* template, CK_ULONG count)
    {
        request.Write((int)count);
        for (var i = 0; i < (int)count; i++)
        {
            var attribute = template[i];
            request.Write(Widen(attribute.type));
            if (IsULongAttribute(attribute.type) && attribute.ulValueLen == (CK_ULONG)sizeof(CK_ULONG) && attribute.pValue != null)
            {
                request.Write(sizeof(ulong));
                request.Write(Widen(*(CK_ULONG*)attribute.pValue));
            }
            else
            {
                request.WriteBlob(attribute.pValue == null
                    ? default
                    : new ReadOnlySpan<byte>(attribute.pValue, (int)attribute.ulValueLen));
            }
        }
    }

    /// <summary>
    /// Writes a mechanism to a request. Its parameter travels as plain bytes, which is right for mechanisms without
    /// a parameter and for byte-string parameters; parameter structures holding CK_ULONGs are not translated.
    /// </summary>
    public static void WriteMechanism(BinaryWriter request, CK_MECHANISM* mechanism)
    {
        request.Write(Widen(mechanism->mechanism));
        request.WriteBlob(mechanism->pParameter == null
            ? default
            : new ReadOnlySpan<byte>(mechanism->pParameter, (int)mechanism->ulParameterLen));
    }
}
