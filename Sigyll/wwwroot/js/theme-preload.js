// (c) 2026 Joseph Shook. All rights reserved.
// Authors: Joseph Shook   JoeShook@Gmail.com
//                         Joseph.Shook@Surescripts.com
// See LICENSE in the project root for license information.

// Runs before first paint: colour the page in the theme it will open in, so nothing flashes.
try {
    var saved = JSON.parse(localStorage.getItem('sigil-theme') || 'null');
    var mode = saved && saved.mode;
    var dark = mode === 'dark' || (mode !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.style.backgroundColor = dark ? '#272727' : '#fbfbfb';
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
} catch (e) { }
