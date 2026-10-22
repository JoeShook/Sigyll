#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Security;
using Sigyll.Did.Services;
using Sigyll.Vc.Services;

namespace Sigyll.Signing.Tests;

/// <summary>
/// Every class that can reach CA state (it takes the database factory) must check the operator
/// in every public method, before doing anything. Each method is called with an anonymous
/// operator and default arguments and must be refused. A new service or method that forgets its
/// check fails here; a deliberate exception carries [NoOperatorCheck] with its reason.
/// </summary>
public class ServiceBoundaryTests
{
    private static readonly Assembly[] ServiceAssemblies =
    [
        typeof(OperatorContext).Assembly,      // Sigyll.Common
        typeof(DidIssuanceService).Assembly,   // Sigyll.Did
        typeof(CredentialVerifier).Assembly,   // Sigyll.Vc
    ];

    public static TheoryData<string> ServiceMethods()
    {
        var data = new TheoryData<string>();
        foreach (var (type, method) in GuardedMethods())
            data.Add($"{type.FullName}.{Describe(method)}");
        return data;
    }

    [Fact]
    public void FindsTheServices()
    {
        // Guards the discovery itself: if it found nothing, the theory below would prove nothing.
        var types = StateBearingTypes().Select(t => t.Name).ToList();
        types.ShouldContain("CertificateIssuanceService");
        types.ShouldContain("CertificateExportService");
        types.ShouldContain("CertificateManagementService");
        types.ShouldContain("CredentialIssuanceService");
        GuardedMethods().Count().ShouldBeGreaterThan(80);
    }

    [Fact]
    public void EveryServiceTakesTheOperatorContext()
    {
        var missing = StateBearingTypes()
            .Where(t => t.GetCustomAttribute<NoOperatorCheckAttribute>() == null)
            .Where(t => !PublicConstructor(t).GetParameters().Any(p => p.ParameterType == typeof(IOperatorContext)))
            .Select(t => t.FullName)
            .ToList();

        missing.ShouldBeEmpty();
    }

    [Fact]
    public void EveryExemptionGivesAReason()
    {
        var exemptions = StateBearingTypes()
            .SelectMany(t => t.GetMethods().Cast<MemberInfo>().Append(t))
            .Select(m => m.GetCustomAttribute<NoOperatorCheckAttribute>())
            .Where(a => a != null);

        exemptions.ShouldAllBe(a => a!.Reason.Length > 20);
    }

    [Theory]
    [MemberData(nameof(ServiceMethods))]
    public async Task AnonymousCallerIsRefused(string serviceMethod)
    {
        var (type, method) = GuardedMethods().Single(m => $"{m.Type.FullName}.{Describe(m.Method)}" == serviceMethod);
        var service = Construct(type, TestOperators.Anonymous);
        var args = method.GetParameters().Select(DefaultArgument).ToArray();

        var refusal = await Should.ThrowAsync<OperatorAccessDeniedException>(async () =>
        {
            object? result;
            try
            {
                result = method.Invoke(service, args);
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }

            switch (result)
            {
                case Task task: await task; break;
                case ValueTask valueTask: await valueTask; break;
                default:
                    if (result?.GetType().GetMethod("AsTask") is { } asTask)
                        await (Task)asTask.Invoke(result, null)!;
                    break;
            }
        });

        refusal.Actor.ShouldBe(OperatorIdentity.Anonymous.Name);
    }

    private static IEnumerable<Type> StateBearingTypes() =>
        ServiceAssemblies
            .SelectMany(a => a.GetExportedTypes())
            .Where(t => t is { IsClass: true, IsAbstract: false })
            .Where(t => t.GetConstructors().Any(c => c.GetParameters()
                .Any(p => p.ParameterType == typeof(IDbContextFactory<SigyllDbContext>))));

    private static IEnumerable<(Type Type, MethodInfo Method)> GuardedMethods() =>
        StateBearingTypes()
            .Where(t => t.GetCustomAttribute<NoOperatorCheckAttribute>() == null)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => !m.IsSpecialName)
                .Where(m => m.GetCustomAttribute<NoOperatorCheckAttribute>() == null)
                .Select(m => (t, m)));

    private static string Describe(MethodInfo m) =>
        $"{m.Name}({string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name))})";

    private static ConstructorInfo PublicConstructor(Type type) =>
        type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();

    private static object Construct(Type type, IOperatorContext operatorContext)
    {
        var ctor = PublicConstructor(type);
        var args = ctor.GetParameters().Select(p => Dependency(p, operatorContext)).ToArray();
        return ctor.Invoke(args);
    }

    private static object? Dependency(ParameterInfo p, IOperatorContext operatorContext)
    {
        var t = p.ParameterType;
        if (t == typeof(IOperatorContext)) return operatorContext;
        if (t == typeof(IDbContextFactory<SigyllDbContext>)) return new TestDbContextFactory();
        if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Microsoft.Extensions.Logging.ILogger<>))
            return typeof(NullLogger<>).MakeGenericType(t.GenericTypeArguments[0]).GetField("Instance")!.GetValue(null);
        if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(IOptions<>))
            return typeof(Options).GetMethod(nameof(Options.Create))!.MakeGenericMethod(t.GenericTypeArguments[0])
                .Invoke(null, [Activator.CreateInstance(t.GenericTypeArguments[0])]);
        if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(IEnumerable<>))
            return Array.CreateInstance(t.GenericTypeArguments[0], 0);
        if (p.HasDefaultValue) return p.DefaultValue;
        if (t.IsInterface) return Substitute.For([t], []);
        return Construct(t, operatorContext);
    }

    private static object? DefaultArgument(ParameterInfo p)
    {
        if (p.HasDefaultValue) return p.DefaultValue;
        return p.ParameterType.IsValueType ? Activator.CreateInstance(p.ParameterType) : null;
    }
}
