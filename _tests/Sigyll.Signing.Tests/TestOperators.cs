#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Security;

namespace Sigyll.Signing.Tests;

/// <summary>Operator contexts for constructing services in tests.</summary>
public static class TestOperators
{
    /// <summary>Holds every permission; for tests about behavior rather than access.</summary>
    public static IOperatorContext Full { get; } =
        As(OperatorIdentity.System("test", Enum.GetValues<Permission>()));

    /// <summary>Holds nothing, like a scope nobody claimed.</summary>
    public static IOperatorContext Anonymous { get; } = As(OperatorIdentity.Anonymous);

    public static IOperatorContext With(params Permission[] permissions) =>
        As(OperatorIdentity.System("test", permissions));

    public static IOperatorContext As(OperatorIdentity identity)
    {
        var context = new OperatorContext();
        context.RunAs(identity);
        return context;
    }
}
