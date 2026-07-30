namespace DaxAlgo.Daxq.Vm.Tests;

internal static class NativeTestSupport
{
    public static string? FindLibrary()
    {
        var configured = Environment.GetEnvironmentVariable("DAXQ_VM_NATIVE_PATH");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var fullPath = Path.GetFullPath(configured);
            Assert.True(
                File.Exists(fullPath),
                $"DAXQ_VM_NATIVE_PATH was explicitly set, but no native library exists at '{fullPath}'.");
            return fullPath;
        }

        var fileName = OperatingSystem.IsWindows()
            ? "daxq_vm.dll"
            : OperatingSystem.IsMacOS() ? "libdaxq_vm.dylib" : "libdaxq_vm.so";
        var root = Directory.GetCurrentDirectory();
        string[] candidates =
        [
            Path.Combine(root, "tmp", "daxq-vm-build", "Release", fileName),
            Path.Combine(root, "tmp", "daxq-vm-build", fileName),
            Path.Combine(root, "tmp", "daxq-vm-build-native", "Release", fileName),
            Path.Combine(root, "tmp", "daxq-vm-build-native", fileName),
            Path.Combine(root, "tmp", "daxq-vm-build-managed", "Release", fileName),
            Path.Combine(root, "tmp", "daxq-vm-build-managed", fileName),
        ];
        return candidates.FirstOrDefault(File.Exists);
    }
}
