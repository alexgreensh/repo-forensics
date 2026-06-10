# Project Status Dashboard

Legitimate emoji sequences using U+200D (ZWJ) and U+FE0F (VS16) must NOT
be flagged as Unicode smuggling (issue #16). These appear in everyday
developer communication and markdown documentation.

## Team

- Alice 👩‍💻 (lead engineer)
- Bob 👨‍💻 (backend)
- Carol 👩‍🎨 (design)
- Dave 🧑‍🔬 (data science)

## Status Icons

| System     | Status         |
|------------|----------------|
| Deployment | ✅ (healthy)   |
| Tests      | ✅ (passing)   |
| Build      | ✅ (green)     |
| Coverage   | ⚠️ (82%)      |

## Notes

The family emoji 👨‍👩‍👧‍👦 uses multiple ZWJ joins between base emoji. The
technologist 👩‍💻 uses a single ZWJ between the woman emoji and laptop.
Skin-tone modifiers 👋🏽 use U+1F3FD. Flag sequences 🇨🇦 use Regional
Indicator pairs. None of these are steganographic.

Variation selector VS-16 (U+FE0F) makes ☑️ render as emoji rather than
text. This is standard Unicode emoji presentation selection, not an attack.
