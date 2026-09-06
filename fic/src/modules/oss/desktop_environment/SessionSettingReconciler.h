#ifndef FIC_SESSION_SETTING_RECONCILER_H
#define FIC_SESSION_SETTING_RECONCILER_H

#include <string>

namespace desktop_policy {

// Reader must set `matches` only after a successful effective-state read.
// This makes an unreadable state fail closed instead of attempting a blind write.
template<typename Reader, typename Writer>
bool reconcileEffectiveSetting(Reader reader,
                               Writer writer,
                               const std::string& mismatchError,
                               std::string& error)
{
    bool matches = false;
    if (!reader(matches, error)) return false;
    if (matches) {
        error.clear();
        return true;
    }
    if (!writer(error)) return false;
    if (!reader(matches, error)) return false;
    if (!matches) {
        error = mismatchError;
        return false;
    }
    error.clear();
    return true;
}

} // namespace desktop_policy

#endif
