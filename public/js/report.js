/* report.js — the report page's one button. The Content-Security-Policy allows
 * no inline script, so the handler lives here. */
const button = document.getElementById('print');
if (button) button.addEventListener('click', () => window.print());
