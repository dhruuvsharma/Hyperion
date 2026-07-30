using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class CandidateSourcePolicy
{
    private static readonly string[] ForbiddenNamespacePrefixes =
    [
        "Microsoft.Win32",
        "System.Diagnostics",
        "System.IO",
        "System.Management",
        "System.Net",
        "System.Reflection",
        "System.Runtime.InteropServices",
        "System.Runtime.Intrinsics",
        "System.Runtime.Loader",
        "System.Security.Cryptography",
        "System.Timers",
    ];

    private static readonly string[] ForbiddenTypeNames =
    [
        "System.AppContext",
        "System.Activator",
        "System.AppDomain",
        "System.Console",
        "System.Environment",
        "System.GC",
        "System.HashCode",
        "System.Runtime.CompilerServices.AsyncVoidMethodBuilder",
        "System.Runtime.CompilerServices.ModuleInitializerAttribute",
        "System.OperatingSystem",
        "System.Random",
        "System.TimeProvider",
        "System.TimeZoneInfo",
        "System.Threading.SynchronizationContext",
        "System.Type",
        "System.Threading.CancellationTokenSource",
        "System.Threading.AutoResetEvent",
        "System.Threading.Barrier",
        "System.Threading.CountdownEvent",
        "System.Threading.EventWaitHandle",
        "System.Threading.ManualResetEvent",
        "System.Threading.ManualResetEventSlim",
        "System.Threading.Monitor",
        "System.Threading.Mutex",
        "System.Threading.NativeOverlapped",
        "System.Threading.PeriodicTimer",
        "System.Threading.ReaderWriterLock",
        "System.Threading.ReaderWriterLockSlim",
        "System.Threading.RegisteredWaitHandle",
        "System.Threading.Semaphore",
        "System.Threading.SemaphoreSlim",
        "System.Threading.SpinLock",
        "System.Threading.SpinWait",
        "System.Threading.Thread",
        "System.Threading.ThreadPool",
        "System.Threading.Timer",
        "System.Threading.WaitHandle",
        "System.Threading.Tasks.Parallel",
        "System.Threading.Tasks.TaskCompletionSource",
        "System.Threading.Tasks.TaskFactory",
        "System.Threading.Tasks.TaskScheduler",
        "System.Linq.ParallelEnumerable",
    ];

    public static List<VerifierDiagnostic> Inspect(
        SyntaxTree syntaxTree,
        CSharpCompilation compilation,
        out string? strategyTypeName)
    {
        var diagnostics = new List<VerifierDiagnostic>();
        var root = syntaxTree.GetRoot();
        var model = compilation.GetSemanticModel(syntaxTree, ignoreAccessibility: false);
        InspectSyntax(root, diagnostics);
        InspectStaticState(root, diagnostics);
        InspectSymbols(root, model, diagnostics);
        strategyTypeName = InspectStrategyShape(root, model, compilation, diagnostics);
        return diagnostics;
    }

    private static void InspectSyntax(
        SyntaxNode root,
        List<VerifierDiagnostic> diagnostics)
    {
        foreach (var directive in root.DescendantTrivia(descendIntoTrivia: true)
                     .Where(item => item.IsDirective))
        {
            Add(diagnostics, "DAXV2100", "Preprocessor directives are not permitted.", directive.GetLocation());
        }

        foreach (var node in root.DescendantNodesAndSelf())
        {
            switch (node)
            {
                case UnsafeStatementSyntax:
                case PointerTypeSyntax:
                case FunctionPointerTypeSyntax:
                case StackAllocArrayCreationExpressionSyntax:
                case FixedStatementSyntax:
                    Add(diagnostics, "DAXV2101", "Unsafe or native-memory syntax is not permitted.", node.GetLocation());
                    break;
                case DestructorDeclarationSyntax:
                    Add(diagnostics, "DAXV2105", "Finalizers are not permitted.", node.GetLocation());
                    break;
                case MethodDeclarationSyntax method
                    when method.Modifiers.Any(SyntaxKind.AsyncKeyword)
                        && method.ReturnType is PredefinedTypeSyntax returnType
                        && returnType.Keyword.IsKind(SyntaxKind.VoidKeyword):
                case LocalFunctionStatementSyntax localFunction
                    when localFunction.Modifiers.Any(SyntaxKind.AsyncKeyword):
                case AnonymousFunctionExpressionSyntax anonymousFunction
                    when anonymousFunction.AsyncKeyword.IsKind(SyntaxKind.AsyncKeyword):
                    Add(
                        diagnostics,
                        "DAXV2106",
                        "Async-void and nested asynchronous functions are not permitted.",
                        node.GetLocation());
                    break;
                case TypeOfExpressionSyntax:
                    Add(diagnostics, "DAXV2102", "Runtime type inspection is not permitted.", node.GetLocation());
                    break;
                case IdentifierNameSyntax identifier when identifier.Identifier.ValueText == "dynamic":
                    Add(diagnostics, "DAXV2103", "Dynamic dispatch is not permitted.", node.GetLocation());
                    break;
            }
        }

        foreach (var token in root.DescendantTokens())
        {
            if (token.IsKind(SyntaxKind.UnsafeKeyword) || token.IsKind(SyntaxKind.ExternKeyword))
            {
                Add(diagnostics, "DAXV2104", "unsafe and extern declarations are not permitted.", token.GetLocation());
            }
        }
    }

    private static void InspectStaticState(
        SyntaxNode root,
        List<VerifierDiagnostic> diagnostics)
    {
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            if (field.Modifiers.Any(SyntaxKind.StaticKeyword)
                && !field.Modifiers.Any(SyntaxKind.ConstKeyword))
            {
                Add(diagnostics, "DAXV2110", "Mutable static fields are not permitted.", field.GetLocation());
            }
        }

        foreach (var eventField in root.DescendantNodes().OfType<EventFieldDeclarationSyntax>())
        {
            if (eventField.Modifiers.Any(SyntaxKind.StaticKeyword))
            {
                Add(diagnostics, "DAXV2111", "Static events are not permitted.", eventField.GetLocation());
            }
        }

        foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
        {
            if (property.Modifiers.Any(SyntaxKind.StaticKeyword)
                && (property.AccessorList?.Accessors.Any(accessor =>
                        accessor.IsKind(SyntaxKind.SetAccessorDeclaration)
                        || accessor.IsKind(SyntaxKind.InitAccessorDeclaration)) == true
                    || property.Initializer is not null))
            {
                Add(diagnostics, "DAXV2112", "Mutable static properties are not permitted.", property.GetLocation());
            }
        }
    }

    private static void InspectSymbols(
        SyntaxNode root,
        SemanticModel model,
        List<VerifierDiagnostic> diagnostics)
    {
        var reported = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in root.DescendantNodesAndSelf())
        {
            ISymbol? symbol = node switch
            {
                UsingDirectiveSyntax usingDirective when usingDirective.Name is not null =>
                    model.GetSymbolInfo(usingDirective.Name).Symbol,
                InvocationExpressionSyntax invocation => model.GetSymbolInfo(invocation).Symbol,
                ObjectCreationExpressionSyntax creation => model.GetSymbolInfo(creation).Symbol,
                AttributeSyntax attribute => model.GetSymbolInfo(attribute).Symbol,
                MemberAccessExpressionSyntax memberAccess => model.GetSymbolInfo(memberAccess).Symbol,
                IdentifierNameSyntax identifier => model.GetSymbolInfo(identifier).Symbol,
                GenericNameSyntax generic => model.GetSymbolInfo(generic).Symbol,
                _ => null,
            };
            if (symbol is IAliasSymbol alias)
            {
                symbol = alias.Target;
            }

            if (symbol is null || !IsForbidden(symbol, out var display))
            {
                continue;
            }

            var span = node.GetLocation().GetLineSpan().StartLinePosition;
            var key = $"{display}\0{span.Line}\0{span.Character}";
            if (reported.Add(key))
            {
                Add(
                    diagnostics,
                    "DAXV2120",
                    $"The API '{display}' is outside the headless strategy profile.",
                    node.GetLocation());
            }
        }
    }

    private static string? InspectStrategyShape(
        SyntaxNode root,
        SemanticModel model,
        CSharpCompilation compilation,
        List<VerifierDiagnostic> diagnostics)
    {
        var interfaceType = compilation.GetTypeByMetadataName(
            "TradingTerminal.Core.Backtest.IBacktestStrategy");
        var contractType = compilation.GetTypeByMetadataName(
            "TradingTerminal.Core.Domain.Contract");
        if (interfaceType is null || contractType is null)
        {
            Add(diagnostics, "DAXV2130", "The frozen Core strategy contracts are unavailable.", root.GetLocation());
            return null;
        }

        var declaredTypes = root.DescendantNodes()
            .OfType<BaseTypeDeclarationSyntax>()
            .Select(item => model.GetDeclaredSymbol(item))
            .OfType<INamedTypeSymbol>()
            .ToArray();
        var publicTypes = declaredTypes
            .Where(item => item.DeclaredAccessibility == Accessibility.Public)
            .ToArray();
        var strategies = publicTypes
            .Where(item => item.TypeKind == TypeKind.Class
                && item.AllInterfaces.Contains(interfaceType, SymbolEqualityComparer.Default))
            .ToArray();
        if (strategies.Length != 1)
        {
            Add(
                diagnostics,
                "DAXV2131",
                "The source must declare exactly one public IBacktestStrategy class.",
                root.GetLocation());
            return null;
        }

        var strategy = strategies[0];
        if (publicTypes.Length != 1
            || strategy.IsAbstract
            || strategy.IsGenericType
            || strategy.ContainingType is not null)
        {
            Add(
                diagnostics,
                "DAXV2132",
                "The strategy must be the only public type and must be top-level, concrete, and non-generic.",
                strategy.Locations.FirstOrDefault() ?? root.GetLocation());
        }

        var hasContractConstructor = strategy.InstanceConstructors.Any(constructor =>
            constructor.DeclaredAccessibility == Accessibility.Public
            && constructor.Parameters.Length == 1
            && SymbolEqualityComparer.Default.Equals(constructor.Parameters[0].Type, contractType));
        if (!hasContractConstructor)
        {
            Add(
                diagnostics,
                "DAXV2133",
                "The strategy must expose a public constructor with exactly one Contract parameter.",
                strategy.Locations.FirstOrDefault() ?? root.GetLocation());
        }

        return strategy.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
            .Replace("global::", string.Empty, StringComparison.Ordinal);
    }

    private static bool IsForbidden(ISymbol symbol, out string display)
    {
        var containingType = symbol as INamedTypeSymbol ?? symbol.ContainingType;
        var typeName = containingType?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
            .Replace("global::", string.Empty, StringComparison.Ordinal)
            ?? string.Empty;
        var namespaceName = containingType?.ContainingNamespace?.ToDisplayString() ?? string.Empty;
        display = symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);

        if (symbol is INamespaceSymbol namespaceSymbol)
        {
            var referencedNamespace = namespaceSymbol.ToDisplayString();
            return CandidateApiSurface.IsProfileNamespaceName(referencedNamespace)
                && !CandidateApiSurface.IsAllowedNamespaceName(referencedNamespace);
        }

        var assemblyName = (symbol as INamedTypeSymbol)?.ContainingAssembly?.Name
            ?? symbol.ContainingAssembly?.Name
            ?? containingType?.ContainingAssembly?.Name;
        if (CandidateApiSurface.IsProfileAssemblyName(assemblyName)
            || CandidateApiSurface.IsProfileTypeName(typeName))
        {
            if (!CandidateApiSurface.IsAllowedTypeName(typeName))
            {
                return true;
            }

            if (symbol is not INamedTypeSymbol
                && !CandidateApiSurface.IsAllowedMember(typeName, symbol.Name))
            {
                return true;
            }
        }

        if (ForbiddenNamespacePrefixes.Any(prefix =>
                namespaceName.Equals(prefix, StringComparison.Ordinal)
                || namespaceName.StartsWith(prefix + ".", StringComparison.Ordinal))
            || IsForbiddenTypeName(typeName))
        {
            return true;
        }

        if (symbol is not IMethodSymbol and not IPropertySymbol)
        {
            return false;
        }

        var memberName = symbol.Name;
        return (typeName is "System.DateTime" or "System.DateTimeOffset"
                && memberName is "Now" or "UtcNow" or "Today" or "get_Now" or "get_UtcNow" or "get_Today")
            || (typeName == "System.Guid" && memberName == "NewGuid")
            || memberName == "GetHashCode"
            || (symbol is IMethodSymbol && memberName == "GetAwaiter")
            || (containingType?.SpecialType == SpecialType.System_Object
                && memberName == "GetType")
            || (typeName == "System.Delegate" && memberName == "DynamicInvoke")
            || (namespaceName.StartsWith("System", StringComparison.Ordinal)
                && memberName is "BeginInvoke" or "EndInvoke")
            || (typeName == "System.Threading.CancellationToken"
                && memberName is "Register" or "UnsafeRegister")
            || (IsTypeOrGeneric(typeName, "System.IProgress")
                && memberName == "Report")
            || (IsTypeOrGeneric(typeName, "System.Progress")
                && memberName == "Report")
            || (namespaceName == "System.Runtime.CompilerServices"
                && memberName is "OnCompleted" or "UnsafeOnCompleted")
            || (IsTypeOrGeneric(typeName, "System.Threading.Tasks.Task")
                && memberName is ".ctor" or "Run" or "Start" or "RunSynchronously" or
                    "ContinueWith" or "Delay" or "Yield" or "Wait" or "WaitAll" or
                    "WaitAny" or "WaitAsync" or "Result" or "get_Result" or "get_Factory")
            || (IsTypeOrGeneric(typeName, "System.Threading.Tasks.ValueTask")
                && memberName is "Result" or "get_Result" or "AsTask")
            || (typeName == "System.Delegate" && memberName == "CreateDelegate")
            || (typeName == "System.Runtime.CompilerServices.RuntimeHelpers"
                && memberName is not "InitializeArray");
    }

    private static bool IsForbiddenTypeName(string typeName) =>
        ForbiddenTypeNames.Contains(typeName, StringComparer.Ordinal)
        || IsTypeOrGeneric(typeName, "System.IProgress")
        || IsTypeOrGeneric(typeName, "System.Progress")
        || IsTypeOrGeneric(typeName, "System.Linq.ParallelQuery")
        || IsTypeOrGeneric(typeName, "System.Threading.Tasks.TaskCompletionSource")
        || typeName.StartsWith("System.Threading.Tasks.TaskFactory", StringComparison.Ordinal)
        || typeName.StartsWith("System.Threading.Tasks.Parallel", StringComparison.Ordinal);

    private static bool IsTypeOrGeneric(string typeName, string definitionName) =>
        typeName.Equals(definitionName, StringComparison.Ordinal)
        || typeName.StartsWith(definitionName + "<", StringComparison.Ordinal)
        || typeName.StartsWith(definitionName + "`", StringComparison.Ordinal);

    private static void Add(
        List<VerifierDiagnostic> diagnostics,
        string code,
        string message,
        Location location)
    {
        var lineSpan = location.GetLineSpan();
        var position = lineSpan.StartLinePosition;
        diagnostics.Add(new(
            "source-policy",
            code,
            "error",
            message,
            position.Line + 1,
            position.Character + 1));
    }
}
