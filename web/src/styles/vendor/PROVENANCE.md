# Vendored Cyllex design system

`cyllex-design.generated.css` and `tailwind4-compat.css` are a vendored static snapshot of the
Cyllex design system, so Cyllex Argus shares the look of the rest of the Cyllex family.

Treat them as read-only: replace the whole file when the design system changes rather than
editing individual rules here. `.gitattributes` marks these files `-text`, so git stores them
byte-identical (no line-ending conversion).
