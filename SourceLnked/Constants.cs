namespace SourceLnked;

internal static class Constants
{
    public static readonly Guid SourceLinkRowKind = new(0xcc110556, 0xa091, 0x4d38, 0x9f, 0xec, 0x25, 0xab, 0x9a, 0x35, 0x1a, 0x6a);

    // Typically there are two sourcelink streams (sourcelink$1 and sourcelink$2),
    // but stream 2 is usually malformed (points to a non-existent stream index).
    public static ReadOnlySpan<byte> SourceLinkStreamName => "sourcelink$1"u8;

    public static ReadOnlySpan<byte> SrcSrvName => "srcsrv"u8;

    public static ReadOnlySpan<byte> MsfBigMagic => "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"u8;

    public static ReadOnlySpan<byte> MsfSmallMagic => "Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47\0\0"u8;

    public static ReadOnlySpan<byte> BsjbMagic => "BSJB"u8;

    public static ReadOnlySpan<byte> ComPlusMagic => "COM+"u8;

    public const int InfoSuccess = 0;

    public const int InfoFail = 1;

    public const int InfoPartial = 2;

    public const int InfoNone = 3;
}
