#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Sigyll.Common.Services.Pqc;

/// <summary>
/// BouncyCastle signature factory that signs with a .NET post-quantum key.
/// Used for CRLs, which <see cref="Org.BouncyCastle.X509.X509V2CrlGenerator"/> still builds.
/// The algorithm identifier carries the CA public-key OID and no parameters.
/// </summary>
internal sealed class PqcSignatureFactory : ISignatureFactory
{
    private readonly AlgorithmIdentifier _algorithm;
    private readonly Func<byte[], byte[]> _sign;

    public PqcSignatureFactory(string signatureOid, Func<byte[], byte[]> sign)
    {
        _algorithm = new AlgorithmIdentifier(new DerObjectIdentifier(signatureOid));
        _sign = sign;
    }

    public object AlgorithmDetails => _algorithm;

    public IStreamCalculator<IBlockResult> CreateCalculator() => new Calculator(_sign);

    private sealed class Calculator : IStreamCalculator<IBlockResult>
    {
        private readonly MemoryStream _buffer = new();
        private readonly Func<byte[], byte[]> _sign;

        public Calculator(Func<byte[], byte[]> sign) => _sign = sign;

        public Stream Stream => _buffer;

        public IBlockResult GetResult() => new BlockResult(_sign(_buffer.ToArray()));
    }

    private sealed class BlockResult : IBlockResult
    {
        private readonly byte[] _signature;

        public BlockResult(byte[] signature) => _signature = signature;

        public byte[] Collect() => _signature;

        public int Collect(byte[] destination, int offset)
        {
            Buffer.BlockCopy(_signature, 0, destination, offset, _signature.Length);
            return _signature.Length;
        }

        public int Collect(Span<byte> output)
        {
            _signature.CopyTo(output);
            return _signature.Length;
        }

        public int GetMaxResultLength() => _signature.Length;
    }
}
