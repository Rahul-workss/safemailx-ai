# SafeMail X AI Website — Mobile Release Notes

Last updated: 2026-10-18

## Release status

**Deployed:** Yes — GitHub `main` commit `8d9f084` was published through the connected Vercel deployment serving `https://safemailx-ai.tech/`.

**Live verification:** HTTP 200 confirmed after deployment, and the live HTML contains the new `Production phone polish` mobile rules. No form was submitted.

### Follow-up correction after visual review

The first release made the phone hero too different from desktop by pausing the video, hiding the animated pipeline cards, and collapsing the sticky hero into a static block. That did not match the intended experience, so the follow-up keeps the desktop composition and animation on phones:

- The looping hero video remains enabled on mobile.
- The sticky hero and scroll runway remain active, with a shorter mobile runway.
- The three pipeline cards remain available and animate one-at-a-time in a shared mobile slot instead of being removed.
- The hero copy, buttons, and metrics are only scaled/repositioned to avoid overlap.
- The secondary bottom feature bar remains hidden on phones because it is redundant with the animated cards.
- The desktop wording is unchanged, and the accent palette is aligned to the app dashboard: black, deep indigo, restrained violet, frost text, emerald status, and minimal cyan.

## What this release fixes

The production website already worked on laptop screens, but its animated hero and information panels could feel crowded on a phone. This patch keeps the existing website, wording, animation, and visual identity, while giving narrow screens more breathing room.

## Changes made

- Added safe-area spacing for phones with a status bar or screen cutout.
- Reduced the mobile logo, header, and status pill so they stay inside the viewport.
- Kept the hero headline and description in a readable column.
- Stacked the two hero actions so they cannot sit on top of each other.
- Kept the three product metrics in a compact row instead of creating a tall block.
- Resized the animated pipeline HUD so it remains inside the phone screen.
- Removed the status pill only on very narrow screens (380px and below) to prevent header crowding.
- Reduced section heading and card sizing for phone reading comfort.
- Left the desktop layout, hero animation, waitlist form, links, and backend untouched.

## Safety and compatibility

These are CSS-only media-query changes in the active production page, `safemailx-website/index.html`. They apply at 600px and below, with additional 480px and 380px breakpoints. Desktop rules remain unchanged. No API endpoint, form field, JavaScript behavior, asset, authentication code, mobile app, or Railway backend code was changed.

## Validation

- [x] `npm run build` passes locally.
- [x] `git diff --check` passes.
- [x] Existing website source was compared with `origin/main` before release.
- [x] No waitlist form was submitted during testing.

## After deployment

- Check the live site on a narrow Android viewport and an iPhone/Safari viewport.
- If a particular device still clips content, record its screen width and browser before changing the breakpoint.
