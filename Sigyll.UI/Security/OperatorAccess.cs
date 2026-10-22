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

namespace Sigyll.UI.Security;

/// <summary>
/// What the signed-in operator may do, so pages can disable controls they cannot use. This is
/// presentation only: the services check permissions themselves, and a refused call surfaces
/// through <c>OperatorErrorBoundary</c>.
/// </summary>
public class OperatorAccess
{
    private readonly IOperatorContext _operator;

    public OperatorAccess(IOperatorContext operatorContext)
    {
        _operator = operatorContext;
    }

    public bool CanOperate { get; private set; }
    public bool CanAdminister { get; private set; }
    public bool CanExportKeys { get; private set; }

    /// <summary>Reads the operator's permissions; call from OnInitializedAsync.</summary>
    public async Task LoadAsync()
    {
        var identity = await _operator.GetCurrentAsync();
        CanOperate = identity.Has(Permission.Operate);
        CanAdminister = identity.Has(Permission.Administer);
        CanExportKeys = identity.Has(Permission.ExportKeys);
    }
}
