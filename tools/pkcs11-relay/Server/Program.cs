using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI80;
using Sigyll.Pkcs11Relay;

// Relay server: one PKCS #11 library, shared by every connection. Runs on 64-bit Linux, where CK_ULONG is 8 bytes
// and structures are naturally aligned (Pkcs11Interop's LowLevelAPI80), which is also the wire format's view of a
// CK_ULONG, so attribute values pass through as plain bytes.

const int MaxItems = 4096;        // slots, mechanisms, attributes or object handles in one call
const int MaxBuffer = 1 << 20;    // one attribute value or signature

var libraryPath = Environment.GetEnvironmentVariable("PKCS11_RELAY_LIBRARY") ?? "/usr/lib/softhsm/libsofthsm2.so";
var port = int.Parse(Environment.GetEnvironmentVariable("PKCS11_RELAY_PORT") ?? Wire.DefaultPort.ToString());

// Pkcs11Interop asks for "libdl"; current glibc installs only libdl.so.2 unless developer packages are present.
NativeLibrary.SetDllImportResolver(typeof(Pkcs11Library).Assembly, (name, assembly, path) =>
    name == "libdl" && NativeLibrary.TryLoad("libdl.so.2", assembly, path, out var handle) ? handle : IntPtr.Zero);

using var library = new Pkcs11Library(libraryPath);
var gate = new Lock();
var initialised = 0; // connections that have called C_Initialize and not yet C_Finalize

var listener = new TcpListener(IPAddress.Any, port);
listener.Start();
Console.WriteLine($"Relaying PKCS #11 calls on port {port} to {libraryPath}");

while (true)
{
    var client = listener.AcceptTcpClient();
    new Thread(() => Serve(client)) { IsBackground = true }.Start();
}

void Serve(TcpClient client)
{
    var remote = client.Client.RemoteEndPoint;
    var connection = new Connection();
    Console.WriteLine($"{remote} connected");
    try
    {
        using var stream = client.GetStream();
        client.NoDelay = true;
        while (Wire.ReadFrame(stream) is { } frame)
        {
            var request = new BinaryReader(new MemoryStream(frame));
            var reply = new BinaryWriter(new MemoryStream());
            lock (gate)
                Dispatch(connection, request, reply);

            reply.Flush();
            var body = (MemoryStream)reply.BaseStream;
            Wire.WriteFrame(stream, body.GetBuffer().AsSpan(0, (int)body.Length));
        }
    }
    catch (Exception e) when (e is IOException or SocketException or InvalidDataException)
    {
        Console.WriteLine($"{remote} dropped: {e.Message}");
    }
    finally
    {
        // A client that goes away takes its sessions with it, as on a network HSM.
        lock (gate)
            Release(connection);

        client.Dispose();
        Console.WriteLine($"{remote} disconnected");
    }
}

// Ends a connection's use of the library: closes its sessions, and finalises the library when it was the last user.
ulong Release(Connection connection)
{
    if (!connection.Initialised)
        return Ckr.CryptokiNotInitialized;

    foreach (var session in connection.Sessions)
        library.C_CloseSession(session);
    connection.Sessions.Clear();
    connection.Initialised = false;
    return --initialised == 0 ? (ulong)library.C_Finalize(IntPtr.Zero) : Ckr.Ok;
}

void Dispatch(Connection connection, BinaryReader request, BinaryWriter reply)
{
    var function = (Fn)request.ReadByte();
    if (!connection.Initialised && function is not (Fn.Initialize or Fn.Finalize))
    {
        reply.Write(Ckr.CryptokiNotInitialized);
        return;
    }

    switch (function)
    {
        case Fn.Initialize:
        {
            var rv = Ckr.CryptokiAlreadyInitialized;
            var clientVersion = request.ReadInt32();
            if (clientVersion != Wire.ProtocolVersion)
            {
                Console.WriteLine($"Refused a client speaking relay protocol {clientVersion}; this server speaks {Wire.ProtocolVersion}. Use a client library and a server built from the same source.");
                rv = Ckr.GeneralError;
            }
            else if (!connection.Initialised)
            {
                rv = initialised == 0 ? (ulong)library.C_Initialize(null) : Ckr.Ok;
                if (rv == Ckr.Ok)
                {
                    initialised++;
                    connection.Initialised = true;
                }
            }

            reply.Write(rv);
            break;
        }

        case Fn.Finalize:
            reply.Write(Release(connection));
            break;

        case Fn.GetInfo:
        {
            var info = new CK_INFO();
            var rv = (ulong)library.C_GetInfo(ref info);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                Version(reply, info.CryptokiVersion);
                reply.Write(info.ManufacturerId);
                reply.Write(info.Flags);
                reply.Write(info.LibraryDescription);
                Version(reply, info.LibraryVersion);
            }

            break;
        }

        case Fn.GetSlotList:
        {
            var tokenPresent = request.ReadBoolean();
            var (list, count) = ReadListBuffer(request);
            var rv = (ulong)library.C_GetSlotList(tokenPresent, list, ref count);
            WriteList(reply, rv, list, count);
            break;
        }

        case Fn.GetSlotInfo:
        {
            var info = new CK_SLOT_INFO();
            var rv = (ulong)library.C_GetSlotInfo(request.ReadUInt64(), ref info);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                reply.Write(info.SlotDescription);
                reply.Write(info.ManufacturerId);
                reply.Write(info.Flags);
                Version(reply, info.HardwareVersion);
                Version(reply, info.FirmwareVersion);
            }

            break;
        }

        case Fn.GetTokenInfo:
        {
            var info = new CK_TOKEN_INFO();
            var rv = (ulong)library.C_GetTokenInfo(request.ReadUInt64(), ref info);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                reply.Write(info.Label);
                reply.Write(info.ManufacturerId);
                reply.Write(info.Model);
                reply.Write(info.SerialNumber);
                reply.Write(info.Flags);
                reply.Write(info.MaxSessionCount);
                reply.Write(info.SessionCount);
                reply.Write(info.MaxRwSessionCount);
                reply.Write(info.RwSessionCount);
                reply.Write(info.MaxPinLen);
                reply.Write(info.MinPinLen);
                reply.Write(info.TotalPublicMemory);
                reply.Write(info.FreePublicMemory);
                reply.Write(info.TotalPrivateMemory);
                reply.Write(info.FreePrivateMemory);
                Version(reply, info.HardwareVersion);
                Version(reply, info.FirmwareVersion);
                reply.Write(info.UtcTime);
            }

            break;
        }

        case Fn.GetMechanismList:
        {
            var slot = request.ReadUInt64();
            var (list, count) = ReadListBuffer(request);
            var mechanisms = list == null ? null : new CKM[list.Length];
            var rv = (ulong)library.C_GetMechanismList(slot, mechanisms, ref count);
            if (rv == Ckr.Ok && mechanisms != null)
            {
                for (var i = 0UL; i < count; i++)
                    list![i] = (ulong)mechanisms[i];
            }

            WriteList(reply, rv, list, count);
            break;
        }

        case Fn.GetMechanismInfo:
        {
            var slot = request.ReadUInt64();
            var info = new CK_MECHANISM_INFO();
            var rv = (ulong)library.C_GetMechanismInfo(slot, (CKM)request.ReadUInt64(), ref info);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                reply.Write(info.MinKeySize);
                reply.Write(info.MaxKeySize);
                reply.Write(info.Flags);
            }

            break;
        }

        case Fn.InitToken:
        {
            var slot = request.ReadUInt64();
            var pin = request.ReadBlob();
            var label = request.ReadBlob();
            reply.Write((ulong)library.C_InitToken(slot, pin, (ulong)pin.Length, label));
            break;
        }

        case Fn.InitPin:
        {
            var session = request.ReadUInt64();
            var pin = request.ReadBlob();
            reply.Write((ulong)library.C_InitPIN(session, pin, (ulong)pin.Length));
            break;
        }

        case Fn.OpenSession:
        {
            var slot = request.ReadUInt64();
            var flags = request.ReadUInt64();
            ulong session = 0;
            var rv = (ulong)library.C_OpenSession(slot, flags, IntPtr.Zero, IntPtr.Zero, ref session);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                connection.Sessions.Add(session);
                reply.Write(session);
            }

            break;
        }

        case Fn.CloseSession:
        {
            var session = request.ReadUInt64();
            var rv = (ulong)library.C_CloseSession(session);
            if (rv == Ckr.Ok)
                connection.Sessions.Remove(session);
            reply.Write(rv);
            break;
        }

        case Fn.GetSessionInfo:
        {
            var info = new CK_SESSION_INFO();
            var rv = (ulong)library.C_GetSessionInfo(request.ReadUInt64(), ref info);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                reply.Write(info.SlotId);
                reply.Write(info.State);
                reply.Write(info.Flags);
                reply.Write(info.DeviceError);
            }

            break;
        }

        case Fn.Login:
        {
            var session = request.ReadUInt64();
            var userType = (CKU)request.ReadUInt64();
            var pin = request.ReadBlob();
            reply.Write((ulong)library.C_Login(session, userType, pin, (ulong)pin.Length));
            break;
        }

        case Fn.Logout:
            reply.Write((ulong)library.C_Logout(request.ReadUInt64()));
            break;

        case Fn.DestroyObject:
        {
            var session = request.ReadUInt64();
            reply.Write((ulong)library.C_DestroyObject(session, request.ReadUInt64()));
            break;
        }

        case Fn.GetAttributeValue:
        {
            var session = request.ReadUInt64();
            var objectHandle = request.ReadUInt64();
            var count = Count(request.ReadInt32());
            var template = new CK_ATTRIBUTE[count];
            var capacity = new ulong[count];
            try
            {
                for (var i = 0; i < count; i++)
                {
                    template[i].type = request.ReadUInt64();
                    var hasBuffer = request.ReadBoolean();
                    capacity[i] = Math.Min(request.ReadUInt64(), MaxBuffer);
                    if (hasBuffer)
                    {
                        template[i].value = Marshal.AllocHGlobal((int)Math.Max(capacity[i], 1));
                        template[i].valueLen = capacity[i];
                    }
                }

                var rv = (ulong)library.C_GetAttributeValue(session, objectHandle, template, (ulong)count);
                reply.Write(rv);
                if (rv is Ckr.Ok or Ckr.AttributeSensitive or Ckr.AttributeTypeInvalid or Ckr.BufferTooSmall)
                {
                    for (var i = 0; i < count; i++)
                    {
                        var length = template[i].valueLen;
                        var filled = template[i].value != IntPtr.Zero && length != Wire.Unavailable && length <= capacity[i];
                        reply.Write(length);
                        reply.Write(filled);
                        if (filled)
                        {
                            var value = new byte[length];
                            Marshal.Copy(template[i].value, value, 0, value.Length);
                            reply.WriteBlob(value);
                        }
                    }
                }
            }
            finally
            {
                FreeTemplate(template);
            }

            break;
        }

        case Fn.FindObjectsInit:
        {
            var session = request.ReadUInt64();
            var template = ReadTemplate(request);
            try
            {
                reply.Write((ulong)library.C_FindObjectsInit(session, template, (ulong)template.Length));
            }
            finally
            {
                FreeTemplate(template);
            }

            break;
        }

        case Fn.FindObjects:
        {
            var session = request.ReadUInt64();
            var handles = new ulong[Math.Min(request.ReadUInt64(), MaxItems)];
            ulong count = 0;
            var rv = (ulong)library.C_FindObjects(session, handles, (ulong)handles.Length, ref count);
            reply.Write(rv);
            if (rv == Ckr.Ok)
            {
                reply.Write(count);
                for (var i = 0UL; i < count; i++)
                    reply.Write(handles[i]);
            }

            break;
        }

        case Fn.FindObjectsFinal:
            reply.Write((ulong)library.C_FindObjectsFinal(request.ReadUInt64()));
            break;

        case Fn.SignInit:
        {
            var session = request.ReadUInt64();
            var mechanism = ReadMechanism(request);
            try
            {
                reply.Write((ulong)library.C_SignInit(session, ref mechanism, request.ReadUInt64()));
            }
            finally
            {
                Marshal.FreeHGlobal(mechanism.Parameter);
            }

            break;
        }

        case Fn.Sign:
        {
            var session = request.ReadUInt64();
            var data = request.ReadBlob();
            var hasBuffer = request.ReadBoolean();
            var length = Math.Min(request.ReadUInt64(), MaxBuffer);
            var signature = hasBuffer ? new byte[length] : null;
            var rv = (ulong)library.C_Sign(session, data, (ulong)data.Length, signature, ref length);
            reply.Write(rv);
            if (rv is Ckr.Ok or Ckr.BufferTooSmall)
            {
                reply.Write(length);
                if (rv == Ckr.Ok && signature != null)
                    reply.WriteBlob(signature.AsSpan(0, (int)length));
            }

            break;
        }

        case Fn.GenerateKeyPair:
        {
            var session = request.ReadUInt64();
            var mechanism = ReadMechanism(request);
            CK_ATTRIBUTE[] publicTemplate = [], privateTemplate = [];
            try
            {
                publicTemplate = ReadTemplate(request);
                privateTemplate = ReadTemplate(request);
                ulong publicKey = 0, privateKey = 0;
                var rv = (ulong)library.C_GenerateKeyPair(session, ref mechanism,
                    publicTemplate, (ulong)publicTemplate.Length, privateTemplate, (ulong)privateTemplate.Length,
                    ref publicKey, ref privateKey);
                reply.Write(rv);
                if (rv == Ckr.Ok)
                {
                    reply.Write(publicKey);
                    reply.Write(privateKey);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(mechanism.Parameter);
                FreeTemplate(publicTemplate);
                FreeTemplate(privateTemplate);
            }

            break;
        }

        default:
            reply.Write(Ckr.FunctionNotSupported);
            break;
    }
}

static void Version(BinaryWriter reply, CK_VERSION version)
{
    reply.Write(version.Major[0]);
    reply.Write(version.Minor[0]);
}

static int Count(int count) =>
    count is >= 0 and <= MaxItems ? count : throw new InvalidDataException($"{count} items is outside the allowed number.");

// The caller's side of a "how many, then which" call: whether it gave a buffer, and how many entries it holds.
static (ulong[]? List, ulong Count) ReadListBuffer(BinaryReader request)
{
    var hasBuffer = request.ReadBoolean();
    var count = request.ReadUInt64();
    if (!hasBuffer)
        return (null, count);

    var list = new ulong[Math.Min(count, MaxItems)];
    return (list, (ulong)list.Length);
}

static void WriteList(BinaryWriter reply, ulong rv, ulong[]? list, ulong count)
{
    reply.Write(rv);
    if (rv is not (Ckr.Ok or Ckr.BufferTooSmall))
        return;

    reply.Write(count);
    if (rv == Ckr.Ok && list != null)
    {
        for (var i = 0UL; i < count; i++)
            reply.Write(list[i]);
    }
}

static CK_ATTRIBUTE[] ReadTemplate(BinaryReader request)
{
    var template = new CK_ATTRIBUTE[Count(request.ReadInt32())];
    for (var i = 0; i < template.Length; i++)
    {
        template[i].type = request.ReadUInt64();
        var value = request.ReadBlob();
        template[i].value = Marshal.AllocHGlobal(Math.Max(value.Length, 1));
        template[i].valueLen = (ulong)value.Length;
        Marshal.Copy(value, 0, template[i].value, value.Length);
    }

    return template;
}

static void FreeTemplate(CK_ATTRIBUTE[] template)
{
    foreach (var attribute in template)
        Marshal.FreeHGlobal(attribute.value);
}

static CK_MECHANISM ReadMechanism(BinaryReader request)
{
    var mechanism = new CK_MECHANISM { Mechanism = request.ReadUInt64() };
    var parameter = request.ReadBlob();
    if (parameter.Length > 0)
    {
        mechanism.Parameter = Marshal.AllocHGlobal(parameter.Length);
        mechanism.ParameterLen = (ulong)parameter.Length;
        Marshal.Copy(parameter, 0, mechanism.Parameter, parameter.Length);
    }

    return mechanism;
}

/// <summary>What one client connection holds on the token.</summary>
sealed class Connection
{
    public bool Initialised;
    public readonly HashSet<ulong> Sessions = [];
}
