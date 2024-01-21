using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace Tamper.NET;
public static class Tamper
{

[DllImport("Kernel32.dll")]
static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int nSize, IntPtr lpNumberOfBytesRead);

[DllImport("kernel32.dll")]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int size, IntPtr lpNumberOfBytesWritten);

static Process? _process;

/// <summary>
/// Returns a <see cref="Process"/> object that is running with the specified <paramref name="procname"/>.
/// </summary>
/// <param name="procname">The name of the <see cref="Process"/> to be returned.</param>
/// <returns>A <see cref="Process"/> object containing information about the process.</returns>
public static Process GetProcessByName(string procname)
{
    _process = Process.GetProcessesByName(procname)[0];
    return _process;
}
public static IntPtr ReadPointer(IntPtr addy, int offset)
{
    byte[] buffer = new byte[8];
    ReadProcessMemory(_process.Handle, IntPtr.Add(addy, offset), buffer, buffer.Length, IntPtr.Zero);
    return (IntPtr)BitConverter.ToInt64(buffer);
}

public static byte[] ReadBytes(IntPtr addy, int bytes)
{
    byte[] buffer = new byte[bytes];
    ReadProcessMemory(_process.Handle, addy, buffer, buffer.Length, IntPtr.Zero);
    return buffer;
}

public static byte[] ReadBytes(IntPtr addy, int offset, int bytes)
{
    byte[] buffer = new byte[bytes];
    ReadProcessMemory(_process.Handle, addy + offset, buffer, buffer.Length, IntPtr.Zero);
    return buffer;
}

public static bool WriteBytes(IntPtr address, byte[] newbytes) => WriteProcessMemory(_process.Handle, address, newbytes, newbytes.Length, IntPtr.Zero);
public static bool WriteBytes(IntPtr address, int offset, byte[] newbytes) => WriteProcessMemory(_process.Handle, address + offset, newbytes, newbytes.Length, IntPtr.Zero);

// Typed values
public static int ReadInt(IntPtr address) => BitConverter.ToInt32(ReadBytes(address, 4));
public static int ReadInt(IntPtr address, int offset) => BitConverter.ToInt32(ReadBytes(address + offset, 4));

public static IntPtr ReadLong(IntPtr address) => (IntPtr)BitConverter.ToInt64(ReadBytes(address, 8));
public static IntPtr ReadLong(IntPtr address, int offset) => (IntPtr)BitConverter.ToInt64(ReadBytes(address + offset, 8));

public static float ReadFloat(IntPtr address) => BitConverter.ToSingle(ReadBytes(address, 4));
public static float ReadFloat(IntPtr address, int offset) => BitConverter.ToSingle(ReadBytes(address + offset, 4));

public static double ReadDouble(IntPtr address) => BitConverter.ToDouble(ReadBytes(address, 8));
public static double ReadDouble(IntPtr address, int offset) => BitConverter.ToDouble(ReadBytes(address + offset, 4));




public static Vector3 ReadVec(IntPtr address)
{
    var bytes = ReadBytes(address, 12);
    return new Vector3
    {
        X = BitConverter.ToSingle(bytes, 0),
        Y = BitConverter.ToSingle(bytes, 4),
        Z = BitConverter.ToSingle(bytes, 8)
    };
}

public static Vector3 ReadVec(IntPtr address, int offset)
{
    var bytes = ReadBytes(address + offset, 12);
    return new Vector3
    {
        X = BitConverter.ToSingle(bytes, 0),
        Y = BitConverter.ToSingle(bytes, 4),
        Z = BitConverter.ToSingle(bytes, 8)
    };
}


public static bool WriteLong(IntPtr address, long value) => WriteBytes(address, BitConverter.GetBytes(value));
public static bool WriteULong(IntPtr address, ulong value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteULong(IntPtr address, int offset, ulong value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteFloat(IntPtr address, float value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteFloat(IntPtr address, int offset, float value) => WriteBytes(address + offset, BitConverter.GetBytes(value));


public static bool WriteLong(IntPtr address, int offset, long value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteDouble(IntPtr address, double value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteDouble(IntPtr address, int offset, double value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteBool(IntPtr address, bool value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteBool(IntPtr address, int offset, bool value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteString(IntPtr address, string value) => WriteBytes(address, Encoding.UTF8.GetBytes(value));
public static bool WriteInt(IntPtr address, int value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteInt(IntPtr address, int offset, int value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteShort(IntPtr address, short value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteShort(IntPtr address, int offset, short value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteUShort(IntPtr address, ushort value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteUShort(IntPtr address, int offset, ushort value) => WriteBytes(address + offset, BitConverter.GetBytes(value));

public static bool WriteUInt(IntPtr address, uint value) => WriteBytes(address, BitConverter.GetBytes(value));

public static bool WriteUInt(IntPtr address, int offset, uint value) => WriteBytes(address + offset, BitConverter.GetBytes(value));


public static ulong ReadULong(IntPtr address) => BitConverter.ToUInt64(ReadBytes(address, 8));

public static ulong ReadULong(IntPtr address, int offset) => BitConverter.ToUInt64(ReadBytes(address + offset, 8));
public static string ReadString(IntPtr address, int length) => Encoding.UTF8.GetString(ReadBytes(address, length));

public static string ReadString(IntPtr address, int offset, int length) => Encoding.UTF8.GetString(ReadBytes(address + offset, length));
public static short ReadShort(IntPtr address) => BitConverter.ToInt16(ReadBytes(address, 2));

public static short ReadShort(IntPtr address, int offset) => BitConverter.ToInt16(ReadBytes(address + offset, 2));

public static ushort ReadUShort(IntPtr address) => BitConverter.ToUInt16(ReadBytes(address, 2));

public static ushort ReadUShort(IntPtr address, int offset) => BitConverter.ToUInt16(ReadBytes(address + offset, 2));

public static uint ReadUInt(IntPtr address) => BitConverter.ToUInt32(ReadBytes(address, 4));

public static char ReadChar(IntPtr address) => BitConverter.ToChar(ReadBytes(address, 2));

public static char ReadChar(IntPtr address, int offset) => BitConverter.ToChar(ReadBytes(address + offset, 2));

public static bool ReadBool(IntPtr address) => BitConverter.ToBoolean(ReadBytes(address, 1));

public static uint ReadUInt(IntPtr address, int offset) => BitConverter.ToUInt32(ReadBytes(address + offset, 4));


public static bool ReadBool(IntPtr address, int offset) => BitConverter.ToBoolean(ReadBytes(address + offset, 1));


public static float[] ReadMatrix(IntPtr address)
{
    var bytes = ReadBytes(address, 4 * 16);
    var matrix = new float[bytes.Length];

    matrix[0] = BitConverter.ToSingle(bytes, 0 * 4);
    matrix[1] = BitConverter.ToSingle(bytes, 1 * 4);
    matrix[2] = BitConverter.ToSingle(bytes, 2 * 4);
    matrix[3] = BitConverter.ToSingle(bytes, 3 * 4);

    matrix[4] = BitConverter.ToSingle(bytes, 4 * 4);
    matrix[5] = BitConverter.ToSingle(bytes, 5 * 4);
    matrix[6] = BitConverter.ToSingle(bytes, 6 * 4);
    matrix[7] = BitConverter.ToSingle(bytes, 7 * 4);

    matrix[8] = BitConverter.ToSingle(bytes, 8 * 4);
    matrix[9] = BitConverter.ToSingle(bytes, 9 * 4);
    matrix[10] = BitConverter.ToSingle(bytes, 10 * 4);
    matrix[11] = BitConverter.ToSingle(bytes, 11 * 4);

    matrix[12] = BitConverter.ToSingle(bytes, 12 * 4);
    matrix[13] = BitConverter.ToSingle(bytes, 13 * 4);
    matrix[14] = BitConverter.ToSingle(bytes, 14 * 4);
    matrix[15] = BitConverter.ToSingle(bytes, 15 * 4);

    return matrix;

}

public static bool WriteVec(IntPtr address, Vector3 value)
{
    byte[] bytes = new byte[12];
    byte[] xBytes = BitConverter.GetBytes(value.X);
    byte[] yBytes = BitConverter.GetBytes(value.Y);
    byte[] zBytes = BitConverter.GetBytes(value.Z);
    xBytes.CopyTo(bytes, 0);
    yBytes.CopyTo(bytes, 4);
    zBytes.CopyTo(bytes, 8);
    return WriteBytes(address, bytes);
}
public static bool WriteVec(IntPtr address, int offset, Vector3 value)
{
    byte[] bytes = new byte[12];
    byte[] xBytes = BitConverter.GetBytes(value.X);
    byte[] yBytes = BitConverter.GetBytes(value.Y);
    byte[] zBytes = BitConverter.GetBytes(value.Z);
    xBytes.CopyTo(bytes, 0);
    yBytes.CopyTo(bytes, 4);
    zBytes.CopyTo(bytes, 8);
    return WriteBytes(address + offset, bytes);
}
}
