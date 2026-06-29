# Accessibility

MNDe does not claim ADA compliance, WCAG compliance, or accessibility certification. This document records the current state, goals, and gaps for the private beta.

## Accessibility Goals

MNDe should be usable by evaluators who rely on keyboard navigation, screen readers, readable contrast, semantic structure, and predictable status messages.

The target standard for future review is WCAG 2.2 Level AA.

## Current Implementation

The repository includes a local operational dashboard in [desktop/dashboard.html](desktop/dashboard.html). It uses:

- `lang="en"` on the HTML document.
- Text labels for navigation buttons.
- Same-origin local status endpoints.
- No login, signup, account, email, password, payment, analytics, or external-origin UI.
- A small inline SVG logo with an accessible label.

The dashboard is covered by [tests/test_dashboard.mjs](tests/test_dashboard.mjs) for infrastructure vocabulary, local endpoints, no external origins, no login/signup/account CTAs, and production read endpoint authorization behavior.

## Known Limitations

The repository does not yet include:

- WCAG 2.2 AA audit.
- Automated accessibility tests.
- Manual keyboard navigation report.
- Manual screen-reader report.
- Color contrast measurements.
- Focus-indicator review.
- Error-message accessibility review.
- Accessible PDF review.
- VPAT or Accessibility Conformance Report.

## Planned Improvements

Before public launch or procurement use, add:

- Automated accessibility checks for the dashboard.
- Manual keyboard-only test notes.
- Manual screen-reader test notes.
- Color contrast review and documented fixes.
- Focus-state review.
- Accessible error and status message review.
- Accessibility regression checks in CI.
- A formal Accessibility Conformance Report if required by customers or procurement.

## Testing Approach

Private beta testing should include:

- Tab through all dashboard controls.
- Confirm the endpoint input and navigation buttons are reachable by keyboard.
- Confirm focus is visible for interactive controls.
- Confirm status changes are understandable without relying only on color.
- Inspect headings, landmarks, button names, and table structure with browser accessibility tools.
- Run an automated checker and record any violations before claiming readiness.

## Keyboard Navigation Status

Partial. Native buttons and input fields should be keyboard reachable, but the repository does not include a completed keyboard-only audit.

## Screen Reader Status

Not verified. The repository has semantic HTML elements in the dashboard, but no screen-reader test results.

## Color Contrast Review Status

Not verified. No contrast calculation or report is included.

## Accessibility Contact

Use the private beta coordinator or maintainer channel that provided access. Include the affected page, browser, assistive technology if applicable, and a short description of the barrier.

## Target Standard

Future accessibility work should target WCAG 2.2 Level AA. The current repository is not claimed to meet that standard.
