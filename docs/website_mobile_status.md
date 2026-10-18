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
- The hero scroll choreography now uses one shared timeline: hero copy exits, layer 1 appears, layer 2 appears, layer 3 appears, and the supporting bar follows without competing triggers.
- The hero scroll runway was reduced from 260vh/220vh to 170vh/160vh (desktop/phone), so the next page section arrives after roughly one to two viewport movements instead of four to five.

## What this release fixes

The production website already worked on laptop screens, but its animated hero and information panels could feel crowded on a phone. This patch keeps the existing website, wording, animation, and visual identity, while giving narrow screens more breathing room.

## Product-flow reorder and scroll choreography — ready for deployment

The product story now follows the same clear order on desktop and phone:

1. **Main message:** “Stop scams before they cost you.”
2. **Five stages, one conclusive verdict:** the complete scan and verdict timeline.
3. **The three protection engines:** Heuristic & Rule Engine, ML & Telecom Intel, and Qwen3-8B Thinking AI.
4. **The remaining product sections:** the multi-channel summary, attack vectors, mobile client, access form, and footer.

### What changed technically, in plain language

- The hero is now one screen tall rather than a long, pinned scroll sequence. This means the next section arrives naturally after one deliberate scroll instead of requiring several swipes.
- The verdict timeline is placed immediately below the hero on every screen size and remains a five-stage scroll sequence. Its introduction fades away, each stage takes the center in turn, then the outcome details appear.
- The three engine cards have their own scroll sequence immediately after the timeline. Each card enters, remains readable, then moves away before the next card appears. The multi-channel summary appears only after the third card.
- Desktop and phone use the same order and pacing model. The phone version has a slightly longer scroll area because one card or verdict stage is deliberately shown at a time on a narrow screen.
- The old side chapter dots were removed because they described the previous card order and would have given misleading progress information.
- No public wording, waitlist form, backend call, mobile app feature, or Railway service was changed.

### Checks completed before release

- [x] Production entry page build completes successfully with `npm run build`.
- [x] The source change passes `git diff --check`.
- [x] Source review confirms the hero leads into the five-stage verdict, then the three engine cards, then the attack-vector section.
- [x] Both product sequences are tied directly to scroll progress. Earlier text is animated away before the next stage/card appears, avoiding the previous all-at-once layout.

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
