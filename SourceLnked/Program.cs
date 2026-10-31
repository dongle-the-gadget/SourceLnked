using AsmResolver.PE.DotNet.Metadata;
using AsmResolver.PE.DotNet.Metadata.Tables;
using AsmResolver.Symbols.Pdb.Metadata.Info;
using AsmResolver.Symbols.Pdb.Msf;
using SourceLnked.SrcSrv;
using Spectre.Console;
using System.Text;
using System.Text.Json;

namespace SourceLnked;

internal class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        string file = args[0];
        byte[] fileData = File.ReadAllBytes(file);

        if (fileData.StartsWith(Constants.BsjbMagic))
        {
            AnalyzeFromPortablePdb(MetadataDirectory.FromBytes(fileData));
        }
        else if (fileData.StartsWith(Constants.MsfBigMagic))
        {
            AnalyzeFromWindowsPdb(MsfFile.FromBytes(fileData));
        }
        else if (fileData.StartsWith(Constants.ComPlusMagic))
        {
            PrintError("Legacy COM+ files are not supported.");
        }
        else if (fileData.StartsWith(Constants.MsfSmallMagic))
        {
            PrintError("Small PDB files are not supported.");
        }
        else
        {
            PrintError("Unrecognized file format.");
        }
    }

    static void AnalyzeFromPortablePdb(MetadataDirectory directory)
    {
        PrintInformation("Portable PDB detected, analyzing...");
        Console.WriteLine();

        if (!directory.TryGetStream(out TablesStream? tablesStream))
        {
            PrintError("Failed to get tables stream.");
            return;
        }

        if (!directory.TryGetStream(out GuidStream? guidStream))
        {
            PrintError("Failed to get GUID stream.");
            return;
        }

        if (!directory.TryGetStream(out BlobStream? blobStream))
        {
            PrintError("Failed to get blob stream.");
            return;
        }

        MetadataTable<CustomDebugInformationRow> cdiTable = tablesStream.GetTable<CustomDebugInformationRow>(TableIndex.CustomDebugInformation);
        var sourceLinkInfo = cdiTable.FirstOrDefault(x => guidStream.GetGuidByIndex(x.Kind) == Constants.SourceLinkRowKind);
        
        if (sourceLinkInfo == default)
        {
            PrintError("No Source Link information available.");
            return;
        }

        PrintInformation("Source Link information is available, analyzing...");

        byte[]? utf8Json = blobStream.GetBlobByIndex(sourceLinkInfo.Value);

        if (utf8Json is null)
        {
            PrintError("Source Link information is malformed.");
            return;
        }

        int result = DeserializeSourceLinkJson(utf8Json);

        Console.WriteLine();

        switch (result)
        {
            case Constants.InfoSuccess:
                PrintSuccess("Source Link information is valid.");
                break;

            case Constants.InfoFail:
                PrintError("Source Link information is malformed.");
                break;

            default:
                break;
        }
    }

    static void AnalyzeFromWindowsPdb(MsfFile file)
    {
        PrintInformation("Windows PDB detected, analyzing...");

        if (file.Streams.Count < 2)
        {
            PrintError("PDB file is malformed.");
            return;
        }

        Console.WriteLine();

        MsfStream pdbiStream = file.Streams[1];
        InfoStream infoStream = InfoStream.FromReader(pdbiStream.CreateReader());
        var sourceLinkStreamIndex = infoStream.StreamIndices
            .Where(static x => x.Key.AsSpan().SequenceEqual(Constants.SourceLinkStreamName))
            .Select(x => x.Value)
            .FirstOrDefault(x => x < file.Streams.Count, -1);

        int sourceLinkStatus = Constants.InfoNone;
        
        if (sourceLinkStreamIndex == -1)
        {
            PrintInformation("No Source Link information available.");
        }
        else
        {
            PrintInformation("Source Link information is available, analyzing...");
            var reader = file.Streams[sourceLinkStreamIndex].CreateReader();
            byte[] utf8Json = reader.ReadToEnd();
            sourceLinkStatus = DeserializeSourceLinkJson(utf8Json);
        }

        Console.WriteLine();
        int srcSrvStatus = AnalyzeSrcSrvFromWindowsPdb(file, infoStream);

        Console.WriteLine();
        Console.WriteLine("Summary:");
        switch (sourceLinkStatus)
        {
            case Constants.InfoSuccess:
                AnsiConsole.MarkupLine("- [green]✓ Source Link information is valid.[/]");
                break;
            case Constants.InfoFail:
                AnsiConsole.MarkupLine("- [red]✗ Source Link information is malformed.[/]");
                break;
            case Constants.InfoNone:
                AnsiConsole.MarkupLine("- [red]✗ No Source Link information available.[/]");
                break;
        }
        switch (srcSrvStatus)
        {
            case Constants.InfoSuccess:
                AnsiConsole.MarkupLine("- [green]✓ Source Server information is valid.[/]");
                break;
            case Constants.InfoPartial:
                AnsiConsole.MarkupLine("- [yellow]! Source Server information is malformed for some files.[/]");
                break;
            case Constants.InfoFail:
                AnsiConsole.MarkupLine("- [red]✗ Source Server information is malformed.[/]");
                break;
            case Constants.InfoNone:
                AnsiConsole.MarkupLine("- [red]✗ No Source Server information available.[/]");
                break;
        }
    }

    static int AnalyzeSrcSrvFromWindowsPdb(MsfFile file, InfoStream infoStream)
    {
        var srcSrvIndices = infoStream.StreamIndices.Where(static x => x.Key.AsSpan().SequenceEqual(Constants.SrcSrvName)).Select(x => x.Value);
        if (srcSrvIndices.Count() == 0)
        {
            PrintInformation("No Source Server stream available.");
            return Constants.InfoNone;
        }

        PrintInformation("Source Server stream is available, analyzing...");
        MsfStream stream = file.Streams[srcSrvIndices.ElementAt(0)];
        byte[] srcSrvUtf8 = stream.CreateReader().ReadToEnd();
        return DeserializeSrcSrv(srcSrvUtf8);
    }

    static int DeserializeSourceLinkJson(byte[] utf8)
    {
        try
        {
            JsonElement root = JsonDocument.Parse(utf8).RootElement;
            JsonElement documents = root.GetProperty("documents"u8);
            foreach (JsonProperty document in documents.EnumerateObject())
            {
                Console.WriteLine($"\"{document.Name}\" ==> \"{document.Value}\"");
            }
            return Constants.InfoSuccess;
        }
        catch (JsonException)
        {
            return Constants.InfoFail;
        }
    }

    static int DeserializeSrcSrv(byte[] utf8)
    {
        Parser parser = new();
        parser.UpsertVariable("targ", "{targ}");
        string srcSrvString = Encoding.UTF8.GetString(utf8);
        string[] lines = srcSrvString.Split(["\r\n", "\n"], StringSplitOptions.None);

        int stage = 0;
        bool failedLines = false;
        foreach (string line in lines)
        {
            if (line == "SRCSRV: variables ------------------------------------------")
            {
                stage = 1;
                continue;
            }

            if (line == "SRCSRV: source files ---------------------------------------")
            {
                stage = 2;
                continue;
            }

            if (stage == 2 && line == "SRCSRV: end ------------------------------------------------")
            {
                stage = 3;
                break;
            }

            if (stage == 1)
            {
                int equal = line.IndexOf('=');
                parser.UpsertVariable(line[..equal], line[(equal + 1)..]);
            }

            if (stage == 2)
            {
                string[] variables = line.Split('*');
                string path1 = variables[0];
                for (int i = 0; i < variables.Length; i++)
                {
                    string name = i == 0 ? "path1" : $"var{i+1}";
                    parser.UpsertVariable(name, variables[i]);
                }
                if (parser.TryEvaluateVariable("SRCSRVTRG", out string? target))
                {
                    if (parser.TryEvaluateVariable("SRCSRVCMD", out string? command))
                    {
                        Console.WriteLine($"\"{path1}\" ==> Command(\"{command}\", \"{target}\")");
                    }
                    else
                    {
                        Console.WriteLine($"\"{path1}\" ==> Path(\"{command}\")");
                    }
                }
                else
                {
                    Console.WriteLine($"\"{path1}\" ==> \"<failed to evaluate>\"");
                    failedLines = true;
                }
            }
        }

        Console.WriteLine();

        if (stage != 3)
        {
            PrintError("Source Server information is malformed.");
            return Constants.InfoFail;
        }
        else if (failedLines)
        {
            PrintWarning("Source Server information is malformed for some files.");
            return Constants.InfoPartial;
        }
        else
        {
            PrintSuccess("Source Server information is valid.");
            return Constants.InfoSuccess;
        }
    }

    static void PrintError(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[bold red]{"[✗]"} Error:[/] {message}");
    }

    static void PrintWarning(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[yellow]{"[!]"} Warning:[/] {message}");
    }

    static void PrintSuccess(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[green]{"[✓]"} Success:[/] {message}");
    }

    static void PrintInformation(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[cyan]{"[i]"} Info:[/] {message}");
    }
}
