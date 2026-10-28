// (c) 2026 Joseph Shook. All rights reserved.
// Authors: Joseph Shook   JoeShook@Gmail.com
//                         Joseph.Shook@Surescripts.com
// See LICENSE in the project root for license information.

// Development-only demo logins on the Login page: a button carries the account to fill in; you still press Log in.
document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest && e.target.closest('[data-demo-email]');
    if (!btn) return;
    document.getElementById('Input.Email').value = btn.dataset.demoEmail;
    document.getElementById('Input.Password').value = btn.dataset.demoPassword;
});
