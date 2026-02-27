using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace EasyInject;

public static class ShellcodeParser
{
    private static readonly Regex _escapedHex = new(@"\\x([0-9a-fA-F]{2})", RegexOptions.Compiled);
    private static readonly Regex _prefixedHex = new(@"0x([0-9a-fA-F]{2})", RegexOptions.Compiled);
    private static readonly Regex _bareHex2 = new(@"[0-9a-fA-F]{2}", RegexOptions.Compiled);

    public static byte[] Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return Array.Empty<byte>();

        input = input.Trim();
        var bytes = new List<byte>();

        if (_escapedHex.IsMatch(input))
        {
            foreach (Match m in _escapedHex.Matches(input))
                bytes.Add(Convert.ToByte(m.Groups[1].Value, 16));
            if (bytes.Count > 0) return bytes.ToArray();
        }

        if (_prefixedHex.IsMatch(input))
        {
            foreach (Match m in _prefixedHex.Matches(input))
                bytes.Add(Convert.ToByte(m.Groups[1].Value, 16));
            if (bytes.Count > 0) return bytes.ToArray();
        }

        string cleaned = input.Replace(",", " ").Replace("\r", " ").Replace("\n", " ");
        foreach (Match m in _bareHex2.Matches(cleaned))
            bytes.Add(Convert.ToByte(m.Value, 16));

        return bytes.ToArray();
    }
}