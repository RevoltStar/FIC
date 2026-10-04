#ifndef FIC_SUDOERSINCLUDEDIRECTIVE_H
#define FIC_SUDOERSINCLUDEDIRECTIVE_H

#include <string>
#include <string_view>

// Specialized sudoers include-directive lexer.
//
// This component exists because a plain "strip the inline comment, then match
// the prefix" reading of an include line is WRONG for sudoers:
//
//   @include /etc/sudoers.local # site settings
//       -> the trailing "# ..." is a comment, the pathname is
//          /etc/sudoers.local;
//   #include /etc/sudoers.local
//       -> a real directive, NOT a comment line;
//   @include /etc/sudoers\ local
//       -> the pathname is "/etc/sudoers local" (backslash escapes the
//          whitespace), it is not "/etc/sudoers\ local" and not "/etc/sudoers";
//   @include "/etc/sudoers local"
//       -> the pathname is "/etc/sudoers local" verbatim.
//
// So the directive keyword must be recognized BEFORE any comment handling,
// and only the ARGUMENT of a recognized directive gets comment/quote/escape
// semantics. Scope: the include subset only. This is deliberately NOT a
// general sudoers lexer.
namespace fic::sudoers {

enum class IncludeKind {
    // The logical line is not an include directive at all.
    None,
    // @include / #include — one single file.
    File,
    // @includedir / #includedir — a directory scanned in lexical order.
    Directory,
    // The line IS an include directive, but FIC does not model its argument
    // safely. The caller must fail closed; it must never silently ignore it.
    Unsupported
};

struct IncludeDirective {
    IncludeKind kind = IncludeKind::None;
    // Decoded pathname, only meaningful for File/Directory.
    std::string path;
    // Populated for Unsupported; empty otherwise.
    std::string error;
};

// Lexes one already continuation-joined sudoers logical line. `logicalLine` is
// the logical line WITH its comments intact (the caller must not strip them:
// '#' is both the comment introducer and part of the '#include' directive).
//
// The returned path is decoded (quotes removed, backslash escapes resolved)
// but NOT expanded: %h/%u-style expansion stays the caller's fail-closed
// decision, exactly as before this component existed.
IncludeDirective parseIncludeDirective(std::string_view logicalLine);

} // namespace fic::sudoers

#endif // FIC_SUDOERSINCLUDEDIRECTIVE_H
