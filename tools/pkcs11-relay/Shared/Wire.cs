using System.Buffers.Binary;

namespace Sigyll.Pkcs11Relay;

/// <summary>
/// The functions the relay forwards. Each value is the function's position in CK_FUNCTION_LIST (PKCS #11 v2.40),
/// counted from 1.
/// </summary>
public enum Fn : byte
{
    Initialize = 1,
    Finalize = 2,
    GetInfo = 3,
    GetSlotList = 5,
    GetSlotInfo = 6,
    GetTokenInfo = 7,
    GetMechanismList = 8,
    GetMechanismInfo = 9,
    InitToken = 10,
    InitPin = 11,
    OpenSession = 13,
    CloseSession = 14,
    GetSessionInfo = 16,
    Login = 19,
    Logout = 20,
    DestroyObject = 23,
    GetAttributeValue = 25,
    FindObjectsInit = 27,
    FindObjects = 28,
    FindObjectsFinal = 29,
    SignInit = 43,
    Sign = 44,
    GenerateKeyPair = 60,
}

/// <summary>PKCS #11 return values the relay itself produces or inspects.</summary>
public static class Ckr
{
    public const ulong Ok = 0x00;
    public const ulong GeneralError = 0x05;
    public const ulong ArgumentsBad = 0x07;
    public const ulong AttributeSensitive = 0x11;
    public const ulong AttributeTypeInvalid = 0x12;
    public const ulong DeviceRemoved = 0x32;
    public const ulong FunctionNotSupported = 0x54;
    public const ulong BufferTooSmall = 0x150;
    public const ulong CryptokiNotInitialized = 0x190;
    public const ulong CryptokiAlreadyInitialized = 0x191;
}

/// <summary>
/// The relay's wire format, shared by the client library and the server. One request and one reply per call, each
/// a 4-byte little-endian length followed by the payload. A request payload starts with the function number; a
/// reply payload starts with the PKCS #11 return value.
/// <para>
/// Every CK_ULONG travels as 8 bytes, whatever its size is on either machine (4 bytes on Windows, 8 on 64-bit
/// Linux). That includes the value of an attribute whose value is a CK_ULONG, such as CKA_CLASS: the client
/// library widens and narrows those, so the server can pass attribute values through as plain bytes.
/// </para>
/// </summary>
public static class Wire
{
    public const int DefaultPort = 5696;
    public const int MaxFrame = 1 << 20;

    /// <summary>
    /// Raised whenever a request or reply changes shape. The client sends it with C_Initialize, and a server built
    /// for another version refuses the connection's calls instead of misreading them.
    /// </summary>
    public const int ProtocolVersion = 1;

    /// <summary>"Unavailable information" (all ones) in a length or count.</summary>
    public const ulong Unavailable = ulong.MaxValue;

    public static void WriteFrame(Stream stream, ReadOnlySpan<byte> payload)
    {
        Span<byte> header = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        stream.Write(header);
        stream.Write(payload);
        stream.Flush();
    }

    /// <summary>Reads one frame, or returns null when the other side closed the connection between frames.</summary>
    public static byte[]? ReadFrame(Stream stream)
    {
        Span<byte> header = stackalloc byte[4];
        var read = stream.ReadAtLeast(header, 4, throwOnEndOfStream: false);
        if (read == 0)
            return null;
        if (read < 4)
            throw new EndOfStreamException();

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 0 or > MaxFrame)
            throw new InvalidDataException($"Frame of {length} bytes is outside the allowed size.");

        var payload = new byte[length];
        stream.ReadExactly(payload);
        return payload;
    }

    /// <summary>A byte string: a 4-byte length, then the bytes.</summary>
    public static void WriteBlob(this BinaryWriter writer, ReadOnlySpan<byte> value)
    {
        writer.Write(value.Length);
        writer.Write(value);
    }

    public static byte[] ReadBlob(this BinaryReader reader)
    {
        var length = reader.ReadInt32();
        if (length is < 0 or > MaxFrame)
            throw new InvalidDataException($"Byte string of {length} bytes is outside the allowed size.");
        return reader.ReadBytes(length);
    }
}
