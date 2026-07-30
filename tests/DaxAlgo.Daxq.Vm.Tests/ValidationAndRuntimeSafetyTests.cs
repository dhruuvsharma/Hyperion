using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace DaxAlgo.Daxq.Vm.Tests;

public sealed class ValidationAndRuntimeSafetyTests
{
    [Fact]
    public void Disposing_program_zeroes_decrypted_and_decoded_material()
    {
        var plaintext = MinimalProgram();
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(plaintext, out var program));
        Assert.NotNull(program);
        Assert.Contains(program.Bytecode, value => value != 0);
        Assert.Contains(program.Entrypoints, entrypoint => entrypoint is not null);

        program.Dispose();

        Assert.All(program.Bytecode, value => Assert.Equal(0, value));
        Assert.All(program.ConstantPoolSection, value => Assert.Equal(0, value));
        Assert.All(program.OpcodeMapSection, value => Assert.Equal(0, value));
        Assert.All(program.HostMapSection, value => Assert.Equal(0, value));
        Assert.All(program.EntrypointSection, value => Assert.Equal(0, value));
        Assert.All(program.Entrypoints, entrypoint => Assert.Null(entrypoint));
    }

    [Fact]
    public void DQXP_parser_rejects_noncanonical_structure_maps_constants_and_watermark()
    {
        var valid = MinimalProgram();

        var trailing = new byte[valid.Length + 1];
        valid.CopyTo(trailing, 0);
        Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(trailing, out _));

        var flags = (byte[])valid.Clone();
        flags[18] = 1;
        Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(flags, out _));

        var duplicateOpcode = (byte[])valid.Clone();
        var opcodeMapOffset = SectionOffset(duplicateOpcode, sectionIndex: 2);
        duplicateOpcode[opcodeMapOffset + 4] = duplicateOpcode[opcodeMapOffset + 2];
        Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(duplicateOpcode, out _));

        var watermark = (byte[])valid.Clone();
        var watermarkOffset = SectionOffset(watermark, sectionIndex: 5);
        watermark[watermarkOffset + 3] = (byte)'x';
        Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(watermark, out _));

        var nonFiniteBuilder = new DaxqTestContainerBuilder();
        var finite = nonFiniteBuilder.AddDouble(1);
        nonFiniteBuilder.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_F64).U16(finite).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        var nonFinite = nonFiniteBuilder.Build();
        var constantOffset = SectionOffset(nonFinite, sectionIndex: 1);
        BinaryPrimitives.WriteInt64LittleEndian(
            nonFinite.AsSpan(constantOffset + 3),
            BitConverter.DoubleToInt64Bits(double.NaN));
        Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(nonFinite, out _));
    }

    [Fact]
    public void Map_duplicate_tracking_is_cleared_between_repeated_loads()
    {
        var valid = MinimalProgram();
        var opcodeMapOffset = SectionOffset(valid, sectionIndex: 2);
        var hostMapOffset = SectionOffset(valid, sectionIndex: 3);

        for (var index = 0; index < 64; index++)
        {
            var duplicateOpcode = (byte[])valid.Clone();
            duplicateOpcode[opcodeMapOffset + 5] = duplicateOpcode[opcodeMapOffset + 3];
            Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(duplicateOpcode, out _));
            Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(valid, out _));

            var duplicateHost = (byte[])valid.Clone();
            duplicateHost[hostMapOffset + 8] = duplicateHost[hostMapOffset + 4];
            duplicateHost[hostMapOffset + 9] = duplicateHost[hostMapOffset + 5];
            Assert.Equal(DaxqFault.InvalidFormat, DaxqProgram.TryLoad(duplicateHost, out _));
            Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(valid, out _));
        }
    }

    [Fact]
    public void Verifier_rejects_uninitialized_locals_bad_merges_types_refs_hosts_and_RET_stack()
    {
        var uninitialized = new DaxqTestContainerBuilder();
        uninitialized.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(uninitialized);

        var merge = new DaxqTestContainerBuilder();
        var integer = merge.AddInt64(1);
        var floating = merge.AddDouble(1);
        var mergeCode = merge.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        mergeCode.Op(Opcode.PUSH_BOOL).U8(1);
        var floatBranch = mergeCode.Branch(Opcode.BRT);
        mergeCode.Op(Opcode.PUSH_I64).U16(integer).Op(Opcode.ST_LOC).U16(0);
        var mergeBranch = mergeCode.Branch(Opcode.BR);
        var floatPath = mergeCode.Mark();
        mergeCode.Op(Opcode.PUSH_F64).U16(floating).Op(Opcode.ST_LOC).U16(0);
        var mergeTarget = mergeCode.Mark();
        mergeCode.Op(Opcode.RET);
        mergeCode.PatchBranch(floatBranch, floatPath);
        mergeCode.PatchBranch(mergeBranch, mergeTarget);
        AssertVerification(merge);

        var stateType = new DaxqTestContainerBuilder();
        stateType.AddState(DaxqValueType.I64);
        stateType.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Op(Opcode.PUSH_BOOL).U8(1).Op(Opcode.ST_STATE).U16(0).Op(Opcode.RET);
        AssertVerification(stateType);

        var badArgument = new DaxqTestContainerBuilder();
        badArgument.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.LD_ARG).U16(1).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(badArgument);

        var badArity = new DaxqTestContainerBuilder();
        badArity.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Call(HostFn.TIndex, 1).Op(Opcode.RET);
        AssertVerification(badArity);

        var directState = new DaxqTestContainerBuilder();
        directState.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Call(HostFn.State, 0).Op(Opcode.RET);
        AssertVerification(directState);

        var nonEmptyReturn = new DaxqTestContainerBuilder();
        nonEmptyReturn.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Op(Opcode.PUSH_BOOL).U8(1).Op(Opcode.RET);
        AssertVerification(nonEmptyReturn);
    }

    [Fact]
    public void Verifier_rejects_non_boundary_branch_and_noncanonical_constant_order_or_unused_entries()
    {
        var badBranch = new DaxqTestContainerBuilder();
        var code = badBranch.AddEntrypoint(DaxqEntrypoint.OnBar);
        var operand = code.Branch(Opcode.BR);
        code.Op(Opcode.RET);
        code.PatchBranch(operand, targetOffset: 1);
        AssertVerification(badBranch);

        var outOfOrder = new DaxqTestContainerBuilder();
        var first = outOfOrder.AddInt64(1);
        var second = outOfOrder.AddInt64(2);
        outOfOrder.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(second).Op(Opcode.ST_LOC).U16(0)
            .Op(Opcode.PUSH_I64).U16(first).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(outOfOrder);

        var unused = new DaxqTestContainerBuilder();
        var used = unused.AddInt64(1);
        unused.AddInt64(2);
        unused.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(used).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(unused);
    }

    [Fact]
    public void Verifier_requires_every_instruction_to_have_an_incoming_control_flow_state()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Op(Opcode.RET)
            .Op(Opcode.PUSH_BOOL).U8(1)
            .Op(Opcode.RET);

        AssertVerification(builder);
    }

    [Fact]
    public void Verifier_rejects_provably_invalid_host_values_after_constant_expressions()
    {
        var arithmetic = new DaxqTestContainerBuilder();
        var three = arithmetic.AddInt64(3);
        var zero = arithmetic.AddInt64(0);
        arithmetic.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(three).Op(Opcode.PUSH_I64).U16(three).Op(Opcode.ADD)
            .Op(Opcode.PUSH_I64).U16(zero).Call(HostFn.Bar, 2)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(arithmetic);

        var conversion = new DaxqTestContainerBuilder();
        var six = conversion.AddInt64(6);
        var conversionZero = conversion.AddInt64(0);
        conversion.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(six).Op(Opcode.I2F).Op(Opcode.F2I)
            .Op(Opcode.PUSH_I64).U16(conversionZero).Call(HostFn.Bar, 2)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(conversion);

        var bufferLength = new DaxqTestContainerBuilder();
        var bufferLookback = bufferLength.AddInt64(0);
        bufferLength.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.NEWBUF).U8((byte)DaxqValueType.I64).U16(6).Op(Opcode.LEN)
            .Op(Opcode.PUSH_I64).U16(bufferLookback).Call(HostFn.Bar, 2)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(bufferLength);

        var local = new DaxqTestContainerBuilder();
        var localSix = local.AddInt64(6);
        var localZero = local.AddInt64(0);
        local.AddEntrypoint(DaxqEntrypoint.OnBar, 2)
            .Op(Opcode.PUSH_I64).U16(localSix).Op(Opcode.ST_LOC).U16(0)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(localZero)
            .Call(HostFn.Bar, 2).Op(Opcode.ST_LOC).U16(1).Op(Opcode.RET);
        AssertVerification(local);

        var indicator = new DaxqTestContainerBuilder();
        var atr = indicator.AddInt64(4);
        var period = indicator.AddInt64(14);
        var open = indicator.AddInt64(1);
        indicator.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(atr).Op(Opcode.PUSH_I64).U16(period)
            .Op(Opcode.PUSH_I64).U16(open).Call(HostFn.Ind, 3)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(indicator);

        var parameter = new DaxqTestContainerBuilder();
        var one = parameter.AddInt64(1);
        parameter.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(one).Op(Opcode.NEG).Call(HostFn.Param, 1)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(parameter);

        var parameterUpper = new DaxqTestContainerBuilder();
        var twoHundredFiftySix = parameterUpper.AddInt64(256);
        parameterUpper.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.PUSH_I64).U16(twoHundredFiftySix).Call(HostFn.Param, 1)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        AssertVerification(parameterUpper);

        var initializeIndex = new DaxqTestContainerBuilder();
        var indexOffset = initializeIndex.AddInt64(256);
        initializeIndex.AddEntrypoint(DaxqEntrypoint.Initialize, 1)
            .Call(HostFn.TIndex, 0).Op(Opcode.PUSH_I64).U16(indexOffset).Op(Opcode.ADD)
            .Call(HostFn.Param, 1).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        initializeIndex.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        AssertVerification(initializeIndex);

        var emit = new DaxqTestContainerBuilder();
        var kind = emit.AddInt64(1);
        var unitStrength = emit.AddDouble(1);
        var note = emit.AddInt64(0);
        emit.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Op(Opcode.PUSH_I64).U16(kind)
            .Op(Opcode.PUSH_F64).U16(unitStrength).Op(Opcode.PUSH_F64).U16(unitStrength)
            .Op(Opcode.ADD).Op(Opcode.PUSH_I64).U16(note).Call(HostFn.Emit, 3)
            .Op(Opcode.RET);
        AssertVerification(emit);

        var log = new DaxqTestContainerBuilder();
        var message = log.AddInt64(-1);
        var value = log.AddDouble(0);
        log.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Op(Opcode.PUSH_I64).U16(message).Op(Opcode.PUSH_F64).U16(value)
            .Call(HostFn.Log, 2).Op(Opcode.RET);
        AssertVerification(log);
    }

    [Fact]
    public void Verifier_uses_one_type_per_local_but_merges_disagreeing_same_type_values_to_unknown()
    {
        var disjointTypes = new DaxqTestContainerBuilder();
        var integer = disjointTypes.AddInt64(1);
        var floating = disjointTypes.AddDouble(1);
        var disjointCode = disjointTypes.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        disjointCode.Op(Opcode.PUSH_BOOL).U8(1);
        var floatBranch = disjointCode.Branch(Opcode.BRT);
        disjointCode.Op(Opcode.PUSH_I64).U16(integer).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        var floatPath = disjointCode.Mark();
        disjointCode.Op(Opcode.PUSH_F64).U16(floating).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        disjointCode.PatchBranch(floatBranch, floatPath);
        AssertVerification(disjointTypes);

        var sameType = new DaxqTestContainerBuilder();
        var compare = sameType.AddInt64(0);
        var validField = sameType.AddInt64(4);
        var invalidField = sameType.AddInt64(6);
        var lookback = sameType.AddInt64(0);
        var sameTypeCode = sameType.AddEntrypoint(DaxqEntrypoint.OnBar, 2);
        sameTypeCode.Op(Opcode.LD_ARG).U16(0).Op(Opcode.PUSH_I64).U16(compare).Op(Opcode.CEQ);
        var invalidBranch = sameTypeCode.Branch(Opcode.BRT);
        sameTypeCode.Op(Opcode.PUSH_I64).U16(validField).Op(Opcode.ST_LOC).U16(0);
        var mergeBranch = sameTypeCode.Branch(Opcode.BR);
        var invalidPath = sameTypeCode.Mark();
        sameTypeCode.Op(Opcode.PUSH_I64).U16(invalidField).Op(Opcode.ST_LOC).U16(0);
        var merge = sameTypeCode.Mark();
        sameTypeCode.Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(lookback)
            .Call(HostFn.Bar, 2).Op(Opcode.ST_LOC).U16(1).Op(Opcode.RET);
        sameTypeCode.PatchBranch(invalidBranch, invalidPath);
        sameTypeCode.PatchBranch(mergeBranch, merge);

        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(sameType.Build(), out _));
    }

    [Fact]
    public void Successful_reference_hot_path_allocates_no_managed_bytes_after_setup()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        var vm = new DaxqReferenceVm(program!, DaxqNullHost.Instance, 1);
        Assert.Equal(DaxqFault.Ok, vm.OnBar(0).Fault);

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < 1_000; index++)
        {
            var result = vm.OnBar(index);
            if (result.Fault != DaxqFault.Ok)
                throw new InvalidOperationException(result.Fault.ToString());
        }
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(0, allocated);
    }

    [Fact]
    public void Successful_native_bridge_hot_path_allocates_no_managed_bytes_after_setup_when_DLL_is_available()
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));

        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, DaxqNullHost.Instance, 1, out var vm));
        using (vm)
        {
            Assert.Equal(DaxqFault.Ok, vm!.OnBar(0).Fault);
            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var index = 0; index < 1_000; index++)
            {
                var result = vm.OnBar(index);
                if (result.Fault != DaxqFault.Ok)
                    throw new InvalidOperationException(result.Fault.ToString());
            }
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.Equal(0, allocated);
        }
    }

    [Fact]
    public void Native_protection_ABI_accepts_valid_ES256_evidence_and_enforces_revocation_when_DLL_is_available()
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));

        using var program = InitializeBarReadProgram();
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, DaxqNullHost.Instance, 1, out var native));
        using (native)
        using (var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var now = DateTimeOffset.UtcNow;
            var licenseId = Guid.NewGuid();
            var releaseId = Guid.NewGuid();
            var accountId = Guid.NewGuid();
            var deviceId = Guid.NewGuid();
            var payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema_version = 1,
                token_kind = "run_token",
                token_id = Guid.NewGuid().ToString("N"),
                license_id = licenseId,
                release_id = releaseId,
                account_id = accountId,
                device_id = deviceId,
                issuer = "daxalgo-platform-development",
                audience = "daxalgo-daxq-host",
                issued_at = now,
                expires_at = now.AddMinutes(30),
                access_valid_until = now.AddMinutes(30),
                revocation_seq = 0,
            });
            var signature = signingKey.SignData(
                payload,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var parameters = signingKey.ExportParameters(false);
            var publicKey = new byte[64];
            parameters.Q.X!.CopyTo(publicKey, 0);
            parameters.Q.Y!.CopyTo(publicKey, 32);
            try
            {
                Assert.Equal(DaxqFault.Ok, native!.ApplyLicenseEvidence(payload, signature, publicKey));
                var offlinePayload = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema_version = 1,
                    token_kind = "offline_lease",
                    token_id = Guid.NewGuid().ToString("N"),
                    license_id = licenseId,
                    release_id = releaseId,
                    account_id = accountId,
                    device_id = deviceId,
                    issuer = "daxalgo-platform-development",
                    audience = "daxalgo-daxq-host",
                    issued_at = now,
                    expires_at = now.AddMinutes(45),
                    access_valid_until = now.AddMinutes(45),
                    revocation_seq = 0,
                });
                var offlineSignature = signingKey.SignData(
                    offlinePayload,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                try
                {
                    Assert.Equal(
                        DaxqFault.Ok,
                        native.ApplyLicenseEvidence(offlinePayload, offlineSignature, publicKey));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(offlinePayload);
                    CryptographicOperations.ZeroMemory(offlineSignature);
                }
                Assert.Equal(DaxqFault.Ok, native.OnBar(0).Fault);
                Assert.Equal(DaxqFault.Ok, native.RevokeLicense());
                Assert.Equal(DaxqFault.InvalidLifecycle, native.OnBar(1).Fault);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(signature);
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
    }

    [Fact]
    public void Reentrant_callback_is_rejected_and_negative_zero_is_normalized()
    {
        var builder = new DaxqTestContainerBuilder();
        var message = builder.AddInt64(1);
        var close = builder.AddInt64(4);
        var zero = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        code.Op(Opcode.PUSH_I64).U16(message)
            .Op(Opcode.PUSH_I64).U16(close).Op(Opcode.PUSH_I64).U16(zero)
            .Call(HostFn.Bar, 2).Call(HostFn.Log, 2).Op(Opcode.RET);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        var host = new ReentrantNegativeZeroHost();
        var vm = new DaxqReferenceVm(program!, host, 1);
        host.Vm = vm;

        var result = vm.OnBar(0);

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Equal(DaxqFault.Reentrant, host.ReentrantFault);
        var logged = Assert.Single(vm.Logs.ToArray());
        Assert.Equal(0L, BitConverter.DoubleToInt64Bits(logged.Value));
    }

    [Fact]
    public void Losing_reentrant_gate_call_does_not_erase_published_reference_or_native_outputs()
    {
        var program = SignalProgram();
        var reference = new DaxqReferenceVm(program, DaxqNullHost.Instance, 1);
        Assert.Equal(DaxqFault.Ok, reference.OnBar(0).Fault);
        Assert.Single(reference.EmittedSignals.ToArray());
        SetInvocationGate(reference, 1);
        try
        {
            Assert.Equal(DaxqFault.Reentrant, reference.OnBar(1).Fault);
            Assert.Single(reference.EmittedSignals.ToArray());
        }
        finally
        {
            SetInvocationGate(reference, 0);
        }

        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, DaxqNullHost.Instance, 1, out var native));
        using (native)
        {
            Assert.Equal(DaxqFault.Ok, native!.OnBar(0).Fault);
            Assert.Single(native.EmittedSignals.ToArray());
            SetInvocationGate(native, 1);
            try
            {
                Assert.Equal(DaxqFault.Reentrant, native.OnBar(1).Fault);
                Assert.Single(native.EmittedSignals.ToArray());
            }
            finally
            {
                SetInvocationGate(native, 0);
            }
        }
    }

    [Fact]
    public void Wrong_arity_invocations_clear_only_after_winning_the_reference_and_native_gate()
    {
        var program = SignalProgram();
        var reference = new DaxqReferenceVm(program, DaxqNullHost.Instance, 1);
        Assert.Equal(DaxqFault.Ok, reference.OnBar(0).Fault);
        Assert.Equal(DaxqFault.InvalidArgument, reference.Invoke(DaxqEntrypoint.OnBar, []).Fault);
        Assert.Empty(reference.EmittedSignals.ToArray());

        Assert.Equal(DaxqFault.Ok, reference.OnBar(0).Fault);
        SetInvocationGate(reference, 1);
        try
        {
            Assert.Equal(DaxqFault.Reentrant, reference.Invoke(DaxqEntrypoint.OnBar, []).Fault);
            Assert.Single(reference.EmittedSignals.ToArray());
        }
        finally
        {
            SetInvocationGate(reference, 0);
        }

        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, DaxqNullHost.Instance, 1, out var native));
        using (native)
        {
            Assert.Equal(DaxqFault.Ok, native!.OnBar(0).Fault);
            Assert.Equal(DaxqFault.InvalidArgument, native.Invoke(DaxqEntrypoint.OnBar, []).Fault);
            Assert.Empty(native.EmittedSignals.ToArray());

            Assert.Equal(DaxqFault.Ok, native.OnBar(0).Fault);
            SetInvocationGate(native, 1);
            try
            {
                Assert.Equal(DaxqFault.Reentrant, native.Invoke(DaxqEntrypoint.OnBar, []).Fault);
                Assert.Single(native.EmittedSignals.ToArray());
            }
            finally
            {
                SetInvocationGate(native, 0);
            }
        }
    }

    [Fact]
    public void Native_dispose_from_callback_is_deferred_until_the_invocation_returns()
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        var host = new DisposingHost();
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(InitializeBarReadProgram(), host, 1, out var native));
        host.Vm = native;

        Assert.Equal(DaxqFault.Ok, native!.Initialize().Fault);
        Assert.True(host.DisposedFromCallback);
        Assert.Equal(DaxqFault.InvalidLifecycle, native.OnBar(0).Fault);
    }

    [Fact]
    public async Task Native_concurrent_dispose_does_not_destroy_the_handle_during_a_callback()
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        using var host = new BlockingHost();
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(InitializeBarReadProgram(), host, 1, out var native));

        var invocation = Task.Run(() => native!.Initialize());
        Assert.True(host.Entered.Wait(TimeSpan.FromSeconds(5)));
        native!.Dispose();
        host.Release.Set();
        var result = await invocation;

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Equal(DaxqFault.InvalidLifecycle, native.OnBar(0).Fault);
    }

    [Fact]
    public void Undisposed_native_VM_is_not_rooted_by_its_callback_context()
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        var weak = CreateUndisposedNativeVm(SignalProgram());

        for (var attempt = 0; attempt < 3 && weak.IsAlive; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        Assert.False(weak.IsAlive);
    }

    private static byte[] MinimalProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        return builder.Build();
    }

    private static DaxqProgram SignalProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var kind = builder.AddInt64(1);
        var strength = builder.AddDouble(1);
        var note = builder.AddInt64(0);
        builder.AddEntrypoint(DaxqEntrypoint.OnBar)
            .Op(Opcode.PUSH_I64).U16(kind).Op(Opcode.PUSH_F64).U16(strength)
            .Op(Opcode.PUSH_I64).U16(note).Call(HostFn.Emit, 3).Op(Opcode.RET);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        return program!;
    }

    private static DaxqProgram InitializeBarReadProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var close = builder.AddInt64(4);
        var lookback = builder.AddInt64(0);
        builder.AddEntrypoint(DaxqEntrypoint.Initialize, 1)
            .Op(Opcode.PUSH_I64).U16(close).Op(Opcode.PUSH_I64).U16(lookback)
            .Call(HostFn.Bar, 2).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        builder.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        return program!;
    }

    private static void SetInvocationGate(object vm, int value)
    {
        var field = vm.GetType().GetField("_invoking", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        field.SetValue(vm, value);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference CreateUndisposedNativeVm(DaxqProgram program)
    {
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, DaxqNullHost.Instance, 1, out var native));
        return new WeakReference(native!);
    }

    private static int SectionOffset(byte[] plaintext, int sectionIndex) => checked((int)
        BinaryPrimitives.ReadUInt32LittleEndian(plaintext.AsSpan(16 + (sectionIndex * 12) + 4)));

    private static void AssertVerification(DaxqTestContainerBuilder builder) =>
        Assert.Equal(DaxqFault.Verification, DaxqProgram.TryLoad(builder.Build(), out _));

    private sealed class ReentrantNegativeZeroHost : IDaxqHost
    {
        public DaxqReferenceVm? Vm { get; set; }

        public DaxqFault ReentrantFault { get; private set; }

        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            ReentrantFault = Vm!.OnBar(0).Fault;
            value = BitConverter.Int64BitsToDouble(long.MinValue);
            return DaxqFault.Ok;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }
    }

    private sealed class DisposingHost : IDaxqHost
    {
        public DaxqNativeVm? Vm { get; set; }

        public bool DisposedFromCallback { get; private set; }

        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            Vm!.Dispose();
            DisposedFromCallback = true;
            value = 1;
            return DaxqFault.Ok;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }
    }

    private sealed class BlockingHost : IDaxqHost, IDisposable
    {
        public ManualResetEventSlim Entered { get; } = new(false);

        public ManualResetEventSlim Release { get; } = new(false);

        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            Entered.Set();
            var released = Release.Wait(TimeSpan.FromSeconds(5));
            value = 1;
            return released ? DaxqFault.Ok : DaxqFault.Host;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public void Dispose()
        {
            Entered.Dispose();
            Release.Dispose();
        }
    }
}
