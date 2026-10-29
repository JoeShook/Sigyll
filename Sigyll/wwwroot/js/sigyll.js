// (c) 2026 Joseph Shook. All rights reserved.
// Authors: Joseph Shook   JoeShook@Gmail.com
//                         Joseph.Shook@Surescripts.com
// See LICENSE in the project root for license information.

window.sigilCopyText = function(text) {
    return navigator.clipboard.writeText(text).then(function() { return true; }, function() { return false; });
};

window.sigilDownloadFile = function(url) {
    var a = document.createElement('a');
    a.href = url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
};

// Save in-memory binary data (base64-encoded, e.g. a freshly assembled .p12) as a file.
window.sigilDownloadBase64 = function(fileName, base64, mimeType) {
    var bin = atob(base64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    var blob = new Blob([bytes], { type: mimeType || 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
};

// Save in-memory text (PEM CSR, private key) as a file without a server round trip.
window.sigilDownloadText = function(fileName, text, mimeType) {
    var blob = new Blob([text], { type: mimeType || 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
};

// FluentDataGrid v4 quirk: when GridTemplateColumns uses minmax/fr/auto and
// ResizableColumns="true", the resize handles only become reliably grabbable
// after the first drag — Fluent's own moveHandler converts every minmax track
// to a fixed pixel width and sets tableLayout: fixed at that point. We do the
// same conversion at init so handles work from first render. Idempotent via
// data-sigil-frozen flag.
window.sigilFreezeResizableGrids = function() {
    requestAnimationFrame(function() {
        document.querySelectorAll('table.fluent-data-grid').forEach(function(grid) {
            if (grid.dataset.sigilFrozen === '1') return;
            if (grid.querySelectorAll('.actual-resize-handle').length === 0) return;
            var profile = grid.style.gridTemplateColumns || '';
            if (!/minmax\(|fr\b|\bauto\b/.test(profile)) {
                grid.dataset.sigilFrozen = '1';
                return;
            }
            var headers = grid.querySelectorAll('thead .column-header');
            if (headers.length === 0) return;
            var widths = [];
            for (var i = 0; i < headers.length; i++) {
                var w = headers[i].clientWidth;
                if (w === 0) return; // grid not laid out yet; try next render
                widths.push(w + 'px');
            }
            grid.style.tableLayout = 'fixed';
            grid.style.gridTemplateColumns = widths.join(' ');
            grid.dataset.sigilFrozen = '1';
        });
    });
};

// Tree right-click → call back into Blazor to open the FluentMenu at the cursor.
// Done in JS because Blazor's contextmenu directive on FluentTreeItem (a web component
// with shadow DOM) doesn't fire reliably from inside the shadow content.
window.sigilInitTreeContextMenu = function(dotnetRef) {
    window.sigilTreeMenuRef = dotnetRef;
};
document.addEventListener('contextmenu', function(e) {
    var item = e.target && e.target.closest && e.target.closest('fluent-tree-item');
    if (!item) return;
    e.preventDefault();
    var ref = window.sigilTreeMenuRef;
    if (ref && item.id) {
        try {
            ref.invokeMethodAsync('OnTreeContextMenuAsync', item.id, e.clientX, e.clientY);
        } catch (err) { /* page navigated away; ref is stale */ }
    }
});

window.sigilFolderUpload = function(inputId) {
    var input = document.getElementById(inputId);
    if (input) {
        input.setAttribute('webkitdirectory', '');
        input.setAttribute('directory', '');
        input.click();
    }
};

// The Explorer remembers, in this browser, each trust domain's collapsed tree nodes and scroll position, and
// the tree filter. Losing it costs nothing, so a browser that refuses storage just starts from the defaults.
window.sigilExplorerState = (function () {
    function read(key) {
        try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch (e) { return null; }
    }
    function write(key, value) {
        try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { }
    }
    function treeKey(trustDomainId) { return 'sigil-explorer-tree-' + trustDomainId; }
    function updateTree(trustDomainId, change) {
        var tree = read(treeKey(trustDomainId)) || {};
        change(tree);
        write(treeKey(trustDomainId), tree);
    }
    return {
        read: function (trustDomainId) {
            return { tree: read(treeKey(trustDomainId)), filter: read('sigil-explorer-filter') };
        },
        writeCollapsed: function (trustDomainId, collapsed) {
            updateTree(trustDomainId, function (tree) { tree.collapsed = collapsed; });
        },
        writeFilter: function (filter) { write('sigil-explorer-filter', filter); },
        // Saves the element's scroll position, under the trust domain it shows when the scrolling settles.
        trackScroll: function (id, trustDomainId) {
            var el = document.getElementById(id);
            if (!el) return;
            el.dataset.sigilTrustDomain = trustDomainId;
            if (el.dataset.sigilScrollTracked) return;
            el.dataset.sigilScrollTracked = 'true';
            var timer;
            el.addEventListener('scroll', function () {
                clearTimeout(timer);
                timer = setTimeout(function () {
                    var top = el.scrollTop;
                    updateTree(el.dataset.sigilTrustDomain, function (tree) { tree.scrollTop = top; });
                }, 250);
            }, { passive: true });
        }
    };
})();

// The Explorer rebuilds its tree after every change; these keep the tree's scroll position across a rebuild.
window.sigilGetScrollTop = function(id) {
    var el = document.getElementById(id);
    return el ? el.scrollTop : 0;
};

window.sigilRestoreScrollTop = function(id, top) {
    // The rebuilt tree items lay out over a few frames: retry until the content is tall enough.
    var tries = 0;
    (function apply() {
        var el = document.getElementById(id);
        if (!el) return;
        el.scrollTop = top;
        if (el.scrollTop < top - 1 && ++tries < 30)
            requestAnimationFrame(apply);
    })();
};

window.sigilHighlightTree = function(selectedId, issuerId) {
    // Clear previous highlights
    document.querySelectorAll('fluent-tree-item').forEach(function(el) {
        var pr = el.shadowRoot && el.shadowRoot.querySelector('.positioning-region');
        if (pr) {
            pr.style.removeProperty('background-color');
            pr.style.removeProperty('border-left');
            pr.style.removeProperty('border-radius');
        }
    });
    // Apply selected highlight to shadow DOM positioning-region
    if (selectedId) {
        var sel = document.getElementById(selectedId);
        if (sel) {
            var pr = sel.shadowRoot && sel.shadowRoot.querySelector('.positioning-region');
            if (pr) {
                pr.style.backgroundColor = 'rgba(45, 106, 79, 0.4)';
                pr.style.borderLeft = '3px solid #2d6a4f';
                pr.style.borderRadius = '0 4px 4px 0';
            }
        }
    }
    // Apply issuer highlight
    if (issuerId) {
        var iss = document.getElementById(issuerId);
        if (iss) {
            var pr = iss.shadowRoot && iss.shadowRoot.querySelector('.positioning-region');
            if (pr) {
                pr.style.backgroundColor = 'rgba(25, 118, 210, 0.3)';
                pr.style.borderLeft = '3px solid #1976d2';
                pr.style.borderRadius = '0 4px 4px 0';
            }
        }
    }
};

window.sigilDialogResize = (function() {
    document.addEventListener('mousedown', function(e) {
        var handle = e.target.closest('.sigil-resize-handle');
        if (!handle) return;
        e.preventDefault();
        var dialog = handle.closest('fluent-dialog');
        if (!dialog) return;
        var control = dialog.shadowRoot && dialog.shadowRoot.querySelector('[part="control"]');
        var target = control || dialog;
        var rect = target.getBoundingClientRect();
        var centerX = rect.left + rect.width / 2;
        // Capture the dialog's declared min-width once and honor it during resize.
        // (After the first resize we overwrite style.minWidth, so we cache it.)
        var floorW = parseInt(dialog.getAttribute('data-sigil-min-width'));
        if (!floorW) {
            floorW = parseInt(dialog.style.minWidth)
                  || parseInt(getComputedStyle(dialog).minWidth)
                  || 500;
            dialog.setAttribute('data-sigil-min-width', floorW);
        }
        function onMove(ev) {
            var newW = Math.max(floorW, 2 * (ev.clientX - centerX));
            dialog.style.setProperty('--dialog-width', newW + 'px');
            dialog.style.minWidth = newW + 'px';
        }
        function onUp() {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });
})();

window.sigilColResize = function(table) {
    if (!table) return;
    var cols = table.querySelectorAll('col');
    var handles = table.querySelectorAll('.col-resize');
    handles.forEach(function(handle, i) {
        handle.addEventListener('mousedown', function(e) {
            e.preventDefault();
            var startX = e.pageX;
            var startW = cols[i].offsetWidth || parseInt(getComputedStyle(cols[i]).width);
            function onMove(ev) {
                var newW = Math.max(40, startW + ev.pageX - startX);
                cols[i].style.width = newW + 'px';
            }
            function onUp() {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    });
};

window.sigilInitDragDrop = function(dotnetHelper, dragItems, dropTargets) {
    // Clean up any previous drag state
    document.querySelectorAll('[draggable="true"]').forEach(function(el) {
        el.removeAttribute('draggable');
    });

    dragItems.forEach(function(item) {
        var el = document.getElementById('tree-' + item.thumbprint);
        if (!el) return;
        el.setAttribute('draggable', 'true');
        el.style.cursor = 'grab';
        el.dataset.dragCertId = item.id;
        el.dataset.dragEntity = item.entityType;
    });

    dropTargets.forEach(function(target) {
        var el = document.getElementById('tree-' + target.thumbprint);
        if (!el) return;
        el.dataset.dropCaId = target.id;
        el.dataset.dropCaName = target.name;
    });

    // Event delegation on the document (handles shadow DOM tree items)
    if (window._sigilDragCleanup) window._sigilDragCleanup();

    function onDragStart(e) {
        var src = e.target.closest('[data-drag-cert-id]');
        if (!src) return;
        e.dataTransfer.setData('text/plain', src.dataset.dragCertId + '|' + src.dataset.dragEntity);
        e.dataTransfer.effectAllowed = 'move';
        src.classList.add('sigil-dragging');
        // Highlight all drop targets
        document.querySelectorAll('[data-drop-ca-id]').forEach(function(t) {
            t.classList.add('sigil-drop-target');
        });
    }
    function onDragOver(e) {
        var tgt = e.target.closest('[data-drop-ca-id]');
        if (!tgt) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        tgt.classList.add('sigil-drag-over');
    }
    function onDragLeave(e) {
        var tgt = e.target.closest('[data-drop-ca-id]');
        if (!tgt) return;
        tgt.classList.remove('sigil-drag-over');
    }
    function onDrop(e) {
        var tgt = e.target.closest('[data-drop-ca-id]');
        if (!tgt) return;
        e.preventDefault();
        var data = e.dataTransfer.getData('text/plain').split('|');
        var certId = parseInt(data[0]);
        var entityType = data[1];
        var caId = parseInt(tgt.dataset.dropCaId);
        var caName = tgt.dataset.dropCaName;
        cleanup();
        dotnetHelper.invokeMethodAsync('OnDragDropRenew', certId, entityType, caId, caName);
    }
    function onDragEnd() {
        cleanup();
    }
    function cleanup() {
        document.querySelectorAll('.sigil-dragging').forEach(function(el) { el.classList.remove('sigil-dragging'); });
        document.querySelectorAll('.sigil-drop-target').forEach(function(el) { el.classList.remove('sigil-drop-target'); });
        document.querySelectorAll('.sigil-drag-over').forEach(function(el) { el.classList.remove('sigil-drag-over'); });
    }

    document.addEventListener('dragstart', onDragStart);
    document.addEventListener('dragover', onDragOver);
    document.addEventListener('dragleave', onDragLeave);
    document.addEventListener('drop', onDrop);
    document.addEventListener('dragend', onDragEnd);

    window._sigilDragCleanup = function() {
        document.removeEventListener('dragstart', onDragStart);
        document.removeEventListener('dragover', onDragOver);
        document.removeEventListener('dragleave', onDragLeave);
        document.removeEventListener('drop', onDrop);
        document.removeEventListener('dragend', onDragEnd);
    };
};

// Development-only demo logins on the Login page: a button carries the account to fill in; you still press Log in.
document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest && e.target.closest('[data-demo-email]');
    if (!btn) return;
    document.getElementById('Input.Email').value = btn.dataset.demoEmail;
    document.getElementById('Input.Password').value = btn.dataset.demoPassword;
});

// Operator sessions end after a period of inactivity. An interactive page makes no requests of its own, so while the
// operator is active this pings the server to keep the sign-in cookie sliding, and once idle for the configured time
// (App.razor's sigyll-idle-minutes) it signs out. The server enforces the same limits without this script.
(function () {
    var meta = document.querySelector('meta[name="sigyll-idle-minutes"]');
    if (!meta) return;
    var idleMs = parseFloat(meta.content) * 60000;
    if (!(idleMs > 0)) return;
    var pingMs = Math.min(5 * 60000, idleMs / 3);
    var lastActivity = Date.now();
    var lastPing = Date.now();
    ['mousedown', 'mousemove', 'keydown', 'wheel', 'touchstart'].forEach(function (name) {
        document.addEventListener(name, function () { lastActivity = Date.now(); }, { passive: true });
    });
    setInterval(function () {
        var now = Date.now();
        if (now - lastActivity >= idleMs) {
            location.href = '/Account/SessionExpired';
            return;
        }
        if (lastActivity > lastPing && now - lastPing >= pingMs) {
            lastPing = now;
            fetch('/Account/KeepAlive', { method: 'POST', credentials: 'same-origin' }).then(function (response) {
                if (response.redirected || response.status === 401) location.href = '/Account/SessionExpired';
            }, function () { });
        }
    }, 15000);
})();

// Recovery code fields (data-recovery-code): type the code as XXXXX-XXXXX — letters upper-cased and the dash
// put in as you go. Delegated, so it also works after enhanced navigation. The server normalizes the same way.
(function () {
    function format(value) {
        var code = value.replace(/[^0-9a-z]/gi, '').toUpperCase().slice(0, 10);
        return code.length > 5 ? code.slice(0, 5) + '-' + code.slice(5) : code;
    }
    document.addEventListener('input', function (e) {
        var field = e.target;
        if (!(field instanceof HTMLInputElement) || !field.hasAttribute('data-recovery-code')) return;
        // Keep the caret after the same number of code characters it was after before formatting.
        var before = field.value.slice(0, field.selectionStart || 0).replace(/[^0-9a-z]/gi, '').length;
        var formatted = format(field.value);
        if (formatted === field.value) return;
        field.value = formatted;
        var caret = before > 5 || (before === 5 && formatted.length > 5) ? before + 1 : before;
        field.setSelectionRange(caret, caret);
    });
})();

// After the password step for a passkey operator, the login page marks its passkey button
// (data-passkey-autostart): start the passkey prompt straight away instead of waiting for a click.
(function () {
    var button = document.querySelector('button[data-passkey-autostart]');
    if (!button || !window.customElements) return;
    customElements.whenDefined('passkey-submit').then(function () { button.click(); });
})();
