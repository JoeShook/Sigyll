using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Sigyll.Pkcs11Relay;

/// <summary>
/// The library's C entry points. A caller finds them through C_GetFunctionList, as with any PKCS #11 library.
/// Functions the relay does not forward answer CKR_FUNCTION_NOT_SUPPORTED. No exception leaves a function: a
/// broken connection is reported as CKR_DEVICE_REMOVED, anything else as CKR_GENERAL_ERROR.
/// </summary>
internal static unsafe class Exports
{
    /// <summary>Where the relay server listens, as host:port.</summary>
    private const string AddressVariable = "SIGYLL_PKCS11_RELAY";

    private const int FunctionCount = 68; // CK_FUNCTION_LIST, PKCS #11 v2.40
#if CRYPTOKI_WINDOWS
    private const int FirstFunctionOffset = 2; // packed: the pointers follow the 2-byte version directly
#else
    private const int FirstFunctionOffset = 8;
#endif

    private static readonly Lock Gate = new();
    private static void* _functionList;
    private static TcpClient? _client;
    private static NetworkStream? _stream;

    [UnmanagedCallersOnly(EntryPoint = "C_GetFunctionList", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetFunctionList(void** ppFunctionList)
    {
        if (ppFunctionList == null)
            return (CK_ULONG)Ckr.ArgumentsBad;

        lock (Gate)
        {
            if (_functionList == null)
                _functionList = BuildFunctionList();
        }

        *ppFunctionList = _functionList;
        return (CK_ULONG)Ckr.Ok;
    }

    private static void* BuildFunctionList()
    {
        var list = (byte*)NativeMemory.AllocZeroed((nuint)(FirstFunctionOffset + FunctionCount * sizeof(void*)));
        list[0] = 2;  // Cryptoki version 2.40
        list[1] = 40;

        var functions = (void**)(list + FirstFunctionOffset);
        for (var i = 0; i < FunctionCount; i++)
            functions[i] = (delegate* unmanaged[Cdecl]<CK_ULONG>)&NotSupported;

        // A function's position is its Fn value less one.
        functions[3] = (delegate* unmanaged[Cdecl]<void**, CK_ULONG>)&C_GetFunctionList;
        Set(Fn.Initialize, (delegate* unmanaged[Cdecl]<void*, CK_ULONG>)&C_Initialize);
        Set(Fn.Finalize, (delegate* unmanaged[Cdecl]<void*, CK_ULONG>)&C_Finalize);
        Set(Fn.GetInfo, (delegate* unmanaged[Cdecl]<void*, CK_ULONG>)&C_GetInfo);
        Set(Fn.GetSlotList, (delegate* unmanaged[Cdecl]<byte, CK_ULONG*, CK_ULONG*, CK_ULONG>)&C_GetSlotList);
        Set(Fn.GetSlotInfo, (delegate* unmanaged[Cdecl]<CK_ULONG, void*, CK_ULONG>)&C_GetSlotInfo);
        Set(Fn.GetTokenInfo, (delegate* unmanaged[Cdecl]<CK_ULONG, void*, CK_ULONG>)&C_GetTokenInfo);
        Set(Fn.GetMechanismList, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG*, CK_ULONG*, CK_ULONG>)&C_GetMechanismList);
        Set(Fn.GetMechanismInfo, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG, void*, CK_ULONG>)&C_GetMechanismInfo);
        Set(Fn.InitToken, (delegate* unmanaged[Cdecl]<CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG>)&C_InitToken);
        Set(Fn.InitPin, (delegate* unmanaged[Cdecl]<CK_ULONG, byte*, CK_ULONG, CK_ULONG>)&C_InitPIN);
        Set(Fn.OpenSession, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG, void*, void*, CK_ULONG*, CK_ULONG>)&C_OpenSession);
        Set(Fn.CloseSession, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG>)&C_CloseSession);
        Set(Fn.GetSessionInfo, (delegate* unmanaged[Cdecl]<CK_ULONG, void*, CK_ULONG>)&C_GetSessionInfo);
        Set(Fn.Login, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG, byte*, CK_ULONG, CK_ULONG>)&C_Login);
        Set(Fn.Logout, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG>)&C_Logout);
        Set(Fn.DestroyObject, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG, CK_ULONG>)&C_DestroyObject);
        Set(Fn.GetAttributeValue, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_ULONG>)&C_GetAttributeValue);
        Set(Fn.FindObjectsInit, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_ULONG>)&C_FindObjectsInit);
        Set(Fn.FindObjects, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG*, CK_ULONG, CK_ULONG*, CK_ULONG>)&C_FindObjects);
        Set(Fn.FindObjectsFinal, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_ULONG>)&C_FindObjectsFinal);
        Set(Fn.SignInit, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_MECHANISM*, CK_ULONG, CK_ULONG>)&C_SignInit);
        Set(Fn.Sign, (delegate* unmanaged[Cdecl]<CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_ULONG>)&C_Sign);
        Set(Fn.GenerateKeyPair, (delegate* unmanaged[Cdecl]<CK_ULONG, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_ULONG*, CK_ULONG*, CK_ULONG>)&C_GenerateKeyPair);
        return list;

        void Set(Fn function, void* entry) => functions[(int)function - 1] = entry;
    }

    /// <summary>Stands in for every function the relay does not forward; it reads no arguments.</summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG NotSupported() => (CK_ULONG)Ckr.FunctionNotSupported;

    // --- library ---

    [UnmanagedCallersOnly(EntryPoint = "C_Initialize", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_Initialize(void* pInitArgs)
    {
        try
        {
            lock (Gate)
            {
                if (_stream == null)
                {
                    var address = Environment.GetEnvironmentVariable(AddressVariable) ?? $"127.0.0.1:{Wire.DefaultPort}";
                    var separator = address.LastIndexOf(':');
                    var host = separator < 0 ? address : address[..separator];
                    var port = separator < 0 ? Wire.DefaultPort : int.Parse(address[(separator + 1)..]);

                    _client = new TcpClient { NoDelay = true };
                    _client.Connect(host, port);
                    _stream = _client.GetStream();
                }
            }

            return (CK_ULONG)Send(Begin(Fn.Initialize), out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_Finalize", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_Finalize(void* pReserved)
    {
        try
        {
            var rv = Send(Begin(Fn.Finalize), out _);
            Disconnect();
            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetInfo", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetInfo(void* pInfo)
    {
        try
        {
            if (pInfo == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var rv = Send(Begin(Fn.GetInfo), out var reply);
            if (rv == Ckr.Ok)
            {
                var info = new StructWriter(pInfo);   // CK_INFO
                info.Bytes(reply.ReadBytes(2));       // cryptokiVersion
                info.Bytes(reply.ReadBytes(32));      // manufacturerID
                info.ULong(reply.ReadUInt64());       // flags
                info.Bytes(reply.ReadBytes(32));      // libraryDescription
                info.Bytes(reply.ReadBytes(2));       // libraryVersion
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    // --- slots and tokens ---

    [UnmanagedCallersOnly(EntryPoint = "C_GetSlotList", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetSlotList(byte tokenPresent, CK_ULONG* pSlotList, CK_ULONG* pulCount)
    {
        try
        {
            if (pulCount == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetSlotList);
            request.Write(tokenPresent != 0);
            request.Write(pSlotList != null);
            request.Write(Cryptoki.Widen(*pulCount));
            return ReadList(request, pSlotList, pulCount);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetSlotInfo", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetSlotInfo(CK_ULONG slotId, void* pInfo)
    {
        try
        {
            if (pInfo == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetSlotInfo);
            request.Write(Cryptoki.Widen(slotId));

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
            {
                var info = new StructWriter(pInfo);   // CK_SLOT_INFO
                info.Bytes(reply.ReadBytes(64));      // slotDescription
                info.Bytes(reply.ReadBytes(32));      // manufacturerID
                info.ULong(reply.ReadUInt64());       // flags
                info.Bytes(reply.ReadBytes(2));       // hardwareVersion
                info.Bytes(reply.ReadBytes(2));       // firmwareVersion
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetTokenInfo", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetTokenInfo(CK_ULONG slotId, void* pInfo)
    {
        try
        {
            if (pInfo == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetTokenInfo);
            request.Write(Cryptoki.Widen(slotId));

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
            {
                var info = new StructWriter(pInfo);   // CK_TOKEN_INFO
                info.Bytes(reply.ReadBytes(32));      // label
                info.Bytes(reply.ReadBytes(32));      // manufacturerID
                info.Bytes(reply.ReadBytes(16));      // model
                info.Bytes(reply.ReadBytes(16));      // serialNumber
                for (var i = 0; i < 11; i++)          // flags, then the ten session, PIN-length and memory counts
                    info.ULong(reply.ReadUInt64());
                info.Bytes(reply.ReadBytes(2));       // hardwareVersion
                info.Bytes(reply.ReadBytes(2));       // firmwareVersion
                info.Bytes(reply.ReadBytes(16));      // utcTime
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetMechanismList", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetMechanismList(CK_ULONG slotId, CK_ULONG* pMechanismList, CK_ULONG* pulCount)
    {
        try
        {
            if (pulCount == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetMechanismList);
            request.Write(Cryptoki.Widen(slotId));
            request.Write(pMechanismList != null);
            request.Write(Cryptoki.Widen(*pulCount));
            return ReadList(request, pMechanismList, pulCount);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetMechanismInfo", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetMechanismInfo(CK_ULONG slotId, CK_ULONG type, void* pInfo)
    {
        try
        {
            if (pInfo == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetMechanismInfo);
            request.Write(Cryptoki.Widen(slotId));
            request.Write(Cryptoki.Widen(type));

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
            {
                var info = new StructWriter(pInfo);   // CK_MECHANISM_INFO
                info.ULong(reply.ReadUInt64());       // ulMinKeySize
                info.ULong(reply.ReadUInt64());       // ulMaxKeySize
                info.ULong(reply.ReadUInt64());       // flags
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_InitToken", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_InitToken(CK_ULONG slotId, byte* pPin, CK_ULONG ulPinLen, byte* pLabel)
    {
        try
        {
            if (pLabel == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.InitToken);
            request.Write(Cryptoki.Widen(slotId));
            request.WriteBlob(Span(pPin, ulPinLen));
            request.WriteBlob(new ReadOnlySpan<byte>(pLabel, 32)); // the label is always 32 bytes, blank padded
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_InitPIN", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_InitPIN(CK_ULONG hSession, byte* pPin, CK_ULONG ulPinLen)
    {
        try
        {
            var request = Begin(Fn.InitPin);
            request.Write(Cryptoki.Widen(hSession));
            request.WriteBlob(Span(pPin, ulPinLen));
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    // --- sessions ---

    [UnmanagedCallersOnly(EntryPoint = "C_OpenSession", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_OpenSession(CK_ULONG slotId, CK_ULONG flags, void* pApplication, void* notify, CK_ULONG* phSession)
    {
        try
        {
            if (phSession == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            // Notification callbacks are not relayed; the application pointer only matters to them.
            var request = Begin(Fn.OpenSession);
            request.Write(Cryptoki.Widen(slotId));
            request.Write(Cryptoki.Widen(flags));

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
                *phSession = Cryptoki.Narrow(reply.ReadUInt64());
            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_CloseSession", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_CloseSession(CK_ULONG hSession) => SessionCall(Fn.CloseSession, hSession);

    [UnmanagedCallersOnly(EntryPoint = "C_GetSessionInfo", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetSessionInfo(CK_ULONG hSession, void* pInfo)
    {
        try
        {
            if (pInfo == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetSessionInfo);
            request.Write(Cryptoki.Widen(hSession));

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
            {
                var info = new StructWriter(pInfo);   // CK_SESSION_INFO
                for (var i = 0; i < 4; i++)           // slotID, state, flags, ulDeviceError
                    info.ULong(reply.ReadUInt64());
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_Login", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_Login(CK_ULONG hSession, CK_ULONG userType, byte* pPin, CK_ULONG ulPinLen)
    {
        try
        {
            var request = Begin(Fn.Login);
            request.Write(Cryptoki.Widen(hSession));
            request.Write(Cryptoki.Widen(userType));
            request.WriteBlob(Span(pPin, ulPinLen));
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_Logout", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_Logout(CK_ULONG hSession) => SessionCall(Fn.Logout, hSession);

    // --- objects ---

    [UnmanagedCallersOnly(EntryPoint = "C_DestroyObject", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_DestroyObject(CK_ULONG hSession, CK_ULONG hObject)
    {
        try
        {
            var request = Begin(Fn.DestroyObject);
            request.Write(Cryptoki.Widen(hSession));
            request.Write(Cryptoki.Widen(hObject));
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    /// <summary>
    /// The caller asks for each attribute either without a buffer (to learn its length) or with one. The server
    /// makes the same call with buffers of the same sizes, so the token decides the outcome of each attribute.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "C_GetAttributeValue", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GetAttributeValue(CK_ULONG hSession, CK_ULONG hObject, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount)
    {
        try
        {
            if (pTemplate == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GetAttributeValue);
            request.Write(Cryptoki.Widen(hSession));
            request.Write(Cryptoki.Widen(hObject));
            request.Write((int)ulCount);
            for (var i = 0; i < (int)ulCount; i++)
            {
                var isULong = Cryptoki.IsULongAttribute(pTemplate[i].type);
                request.Write(Cryptoki.Widen(pTemplate[i].type));
                request.Write(pTemplate[i].pValue != null);
                request.Write(isULong && pTemplate[i].ulValueLen == (CK_ULONG)sizeof(CK_ULONG)
                    ? sizeof(ulong)
                    : Cryptoki.Widen(pTemplate[i].ulValueLen));
            }

            var rv = Send(request, out var reply);
            if (rv is Ckr.Ok or Ckr.AttributeSensitive or Ckr.AttributeTypeInvalid or Ckr.BufferTooSmall)
            {
                for (var i = 0; i < (int)ulCount; i++)
                {
                    var isULong = Cryptoki.IsULongAttribute(pTemplate[i].type);
                    var length = reply.ReadUInt64();
                    var value = reply.ReadBoolean() ? reply.ReadBlob() : null;

                    if (isULong && length == sizeof(ulong))
                    {
                        pTemplate[i].ulValueLen = (CK_ULONG)sizeof(CK_ULONG);
                        if (value != null)
                            *(CK_ULONG*)pTemplate[i].pValue = Cryptoki.Narrow(BitConverter.ToUInt64(value));
                    }
                    else
                    {
                        pTemplate[i].ulValueLen = Cryptoki.Narrow(length);
                        value?.CopyTo(new Span<byte>(pTemplate[i].pValue, value.Length));
                    }
                }
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_FindObjectsInit", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_FindObjectsInit(CK_ULONG hSession, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount)
    {
        try
        {
            var request = Begin(Fn.FindObjectsInit);
            request.Write(Cryptoki.Widen(hSession));
            Cryptoki.WriteTemplate(request, pTemplate, ulCount);
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_FindObjects", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_FindObjects(CK_ULONG hSession, CK_ULONG* phObject, CK_ULONG ulMaxObjectCount, CK_ULONG* pulObjectCount)
    {
        try
        {
            if (phObject == null || pulObjectCount == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.FindObjects);
            request.Write(Cryptoki.Widen(hSession));
            request.Write(Cryptoki.Widen(ulMaxObjectCount));

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
            {
                var count = reply.ReadUInt64();
                *pulObjectCount = Cryptoki.Narrow(count);
                for (var i = 0UL; i < count; i++)
                    phObject[i] = Cryptoki.Narrow(reply.ReadUInt64());
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_FindObjectsFinal", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_FindObjectsFinal(CK_ULONG hSession) => SessionCall(Fn.FindObjectsFinal, hSession);

    // --- keys and signing ---

    [UnmanagedCallersOnly(EntryPoint = "C_SignInit", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_SignInit(CK_ULONG hSession, CK_MECHANISM* pMechanism, CK_ULONG hKey)
    {
        try
        {
            if (pMechanism == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.SignInit);
            request.Write(Cryptoki.Widen(hSession));
            Cryptoki.WriteMechanism(request, pMechanism);
            request.Write(Cryptoki.Widen(hKey));
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    /// <summary>Called without a signature buffer to learn the length, then with one; both calls go to the token.</summary>
    [UnmanagedCallersOnly(EntryPoint = "C_Sign", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_Sign(CK_ULONG hSession, byte* pData, CK_ULONG ulDataLen, byte* pSignature, CK_ULONG* pulSignatureLen)
    {
        try
        {
            if (pulSignatureLen == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.Sign);
            request.Write(Cryptoki.Widen(hSession));
            request.WriteBlob(Span(pData, ulDataLen));
            request.Write(pSignature != null);
            request.Write(Cryptoki.Widen(*pulSignatureLen));

            var rv = Send(request, out var reply);
            if (rv is Ckr.Ok or Ckr.BufferTooSmall)
            {
                *pulSignatureLen = Cryptoki.Narrow(reply.ReadUInt64());
                if (rv == Ckr.Ok && pSignature != null)
                {
                    var signature = reply.ReadBlob();
                    signature.CopyTo(new Span<byte>(pSignature, signature.Length));
                }
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GenerateKeyPair", CallConvs = [typeof(CallConvCdecl)])]
    private static CK_ULONG C_GenerateKeyPair(CK_ULONG hSession, CK_MECHANISM* pMechanism,
        CK_ATTRIBUTE* pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
        CK_ATTRIBUTE* pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
        CK_ULONG* phPublicKey, CK_ULONG* phPrivateKey)
    {
        try
        {
            if (pMechanism == null || phPublicKey == null || phPrivateKey == null)
                return (CK_ULONG)Ckr.ArgumentsBad;

            var request = Begin(Fn.GenerateKeyPair);
            request.Write(Cryptoki.Widen(hSession));
            Cryptoki.WriteMechanism(request, pMechanism);
            Cryptoki.WriteTemplate(request, pPublicKeyTemplate, ulPublicKeyAttributeCount);
            Cryptoki.WriteTemplate(request, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);

            var rv = Send(request, out var reply);
            if (rv == Ckr.Ok)
            {
                *phPublicKey = Cryptoki.Narrow(reply.ReadUInt64());
                *phPrivateKey = Cryptoki.Narrow(reply.ReadUInt64());
            }

            return (CK_ULONG)rv;
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    // --- plumbing ---

    /// <summary>A call whose only argument is a session handle and whose only result is the return value.</summary>
    private static CK_ULONG SessionCall(Fn function, CK_ULONG hSession)
    {
        try
        {
            var request = Begin(function);
            request.Write(Cryptoki.Widen(hSession));
            return (CK_ULONG)Send(request, out _);
        }
        catch (Exception e)
        {
            return Fail(e);
        }
    }

    /// <summary>
    /// Sends a request for a list of CK_ULONGs and fills the caller's count and, when a buffer was given and was
    /// large enough, the list.
    /// </summary>
    private static CK_ULONG ReadList(BinaryWriter request, CK_ULONG* pList, CK_ULONG* pulCount)
    {
        var rv = Send(request, out var reply);
        if (rv is Ckr.Ok or Ckr.BufferTooSmall)
        {
            var count = reply.ReadUInt64();
            *pulCount = Cryptoki.Narrow(count);
            if (rv == Ckr.Ok && pList != null)
            {
                for (var i = 0UL; i < count; i++)
                    pList[i] = Cryptoki.Narrow(reply.ReadUInt64());
            }
        }

        return (CK_ULONG)rv;
    }

    private static ReadOnlySpan<byte> Span(byte* data, CK_ULONG length) =>
        data == null ? default : new ReadOnlySpan<byte>(data, (int)length);

    private static BinaryWriter Begin(Fn function)
    {
        var writer = new BinaryWriter(new MemoryStream());
        writer.Write((byte)function);
        return writer;
    }

    /// <summary>Sends one request and waits for its reply; returns the PKCS #11 return value the server sent.</summary>
    private static ulong Send(BinaryWriter request, out BinaryReader reply)
    {
        lock (Gate)
        {
            if (_stream == null)
            {
                reply = new BinaryReader(Stream.Null);
                return Ckr.CryptokiNotInitialized;
            }

            request.Flush();
            var body = (MemoryStream)request.BaseStream;
            Wire.WriteFrame(_stream, body.GetBuffer().AsSpan(0, (int)body.Length));

            var frame = Wire.ReadFrame(_stream) ?? throw new EndOfStreamException();
            reply = new BinaryReader(new MemoryStream(frame));
            return reply.ReadUInt64();
        }
    }

    private static void Disconnect()
    {
        lock (Gate)
        {
            _stream?.Dispose();
            _client?.Dispose();
            _stream = null;
            _client = null;
        }
    }

    private static CK_ULONG Fail(Exception exception)
    {
        if (exception is IOException or SocketException or ObjectDisposedException)
        {
            Disconnect();
            return (CK_ULONG)Ckr.DeviceRemoved;
        }

        return (CK_ULONG)Ckr.GeneralError;
    }
}
