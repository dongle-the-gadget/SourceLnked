using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace SourceLnked.SrcSrv;

internal static class Lexer
{
    public abstract record Node()
    {
        public sealed record Literal(string Value) : Node;

        public sealed record VariableOrFunctionMarker() : Node
        {
            public static VariableOrFunctionMarker Instance { get; } = new VariableOrFunctionMarker();
        }

        public sealed record ArgumentStart() : Node
        {
            public static ArgumentStart Instance { get; } = new ArgumentStart();
        }

        public sealed record ArgumentEnd() : Node
        {
            public static ArgumentEnd Instance { get; } = new ArgumentEnd();
        }
    }

    internal static bool IsFunctionName(string name) => name is Constants.FunctionNameFnVar or Constants.FunctionNameFnBksl or Constants.FunctionNameFnFile;

    public static bool TryAnalyze(string input, [NotNullWhen(true)] out List<Node>? nodes)
    {
        // Variables are represented by %name%, and functions by %name%(%variable%).
        // Names cannot contain parentheses, and functions have one non-nested variable argument.
        // Only fnvar, fnbksl, and fnfile followed immediately by '(' start functions; other parentheses are literal text.

        var nodesStore = new List<Node>();
        var currentLiteral = new StringBuilder();

        bool insideVariableOrFunctionName = false;
        bool insideFunctionArgument = false;

        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            switch (c)
            {
                case Constants.VariableOrFunctionMarker:
                    if (currentLiteral.Length > 0)
                    {
                        nodesStore.Add(new Node.Literal(currentLiteral.ToString()));
                        currentLiteral.Clear();
                    }
                    nodesStore.Add(Node.VariableOrFunctionMarker.Instance);
                    insideVariableOrFunctionName = !insideVariableOrFunctionName;
                    break;
                case Constants.ArgumentStart:
                    if (insideVariableOrFunctionName || insideFunctionArgument)
                        goto Failure;
                    if (i > 0 && input[i - 1] == Constants.VariableOrFunctionMarker &&
                        nodesStore.Count >= 3 && nodesStore[^2] is Node.Literal name &&
                        IsFunctionName(name.Value))
                    {
                        if (i + 1 >= input.Length || input[i + 1] != Constants.VariableOrFunctionMarker)
                            goto Failure;
                        insideFunctionArgument = true;
                        nodesStore.Add(Node.ArgumentStart.Instance);
                    }
                    else
                    {
                        currentLiteral.Append(c);
                    }
                    break;
                case Constants.ArgumentEnd:
                    if (insideVariableOrFunctionName)
                        goto Failure;
                    if (insideFunctionArgument)
                    {
                        if (currentLiteral.Length > 0)
                            goto Failure;
                        insideFunctionArgument = false;
                        nodesStore.Add(Node.ArgumentEnd.Instance);
                    }
                    else
                    {
                        currentLiteral.Append(c);
                    }
                    break;
                default:
                    if (insideFunctionArgument && !insideVariableOrFunctionName)
                        goto Failure;
                    currentLiteral.Append(c);
                    break;
            }
        }

        if (insideVariableOrFunctionName || insideFunctionArgument)
            goto Failure;

        if (currentLiteral.Length > 0)
        {
            nodesStore.Add(new Node.Literal(currentLiteral.ToString()));
        }

        nodes = nodesStore;
        return true;

Failure:
        nodes = null;
        return false;
    }
}