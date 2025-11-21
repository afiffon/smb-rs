# Utility for documenting structures based on MSDN specifications

- When you document a structure, the *final* document you use should be official Microsoft documentation.

- Structure documentation should include:
  - A brief description of the structure's purpose.
  - A reference to the page. Use the index of specifications (MS-SMB2 X.Y.Z...), do not put url parts.
  - Field documentation should be brief and helpful, if any critical information is provided, include it.
- Never include constant names or values in the documentation! especially bit shift flags, or arbitrary symbols.
- Don't make up stuff! Always base documentation on official documentation.
- Avoid documenting for the sake of documenting. If the documentation doesn't add value, don't add it. (e.g. don't just repeat the field name in the field documentation...).
- Do not summarize or put again the instructions, that just makes me pay for more tokens.

- If the structure is under the `smb-msg` crate, you can look up the documentation.
  - Make sure that the documentation is MS-SMB2 2.* indexed - that's where structures are documented.
  - Request the documentation page to be used, do not try to look it up yourself. It won't work!
  - Do not simple document helper structures that are not part of the specification and/or produced by macros.
  - This does NOT apply to enums that represent possible field values, for example, or bitfield structs - of course!
  - NEVER document reserved fields.
