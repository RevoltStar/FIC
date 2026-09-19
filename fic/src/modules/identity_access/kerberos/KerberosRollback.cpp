#include "modules/identity_access/kerberos/KerberosRollback.h"

#include "modules/identity_access/shared/configuration/PreparedFileChange.h"

#include <utility>

KerberosRollbackResult undoKerberosScalar(
    const KerberosRollbackOptions& options,
    const fic::rollback::UndoRestoreKerberosScalar& undo) {
    KerberosRollbackResult result;
    fic::identity::kerberos::KerberosConfiguration configuration(
        options.configuration);

    // Classification of the CURRENT root target state. Any failure to read
    // the profile graph fails closed without touching anything.
    fic::identity::kerberos::KerberosRootScalarObservation observed;
    std::string error;
    if (!configuration.inspectRootScalar(
            undo.section, undo.relation, observed, error)) {
        result.message =
            "Не удалось проанализировать Kerberos профиль: " + error;
        return result;
    }
    if (observed.externallyDefined) {
        result.conflict = true;
        result.message =
            "Target relation [" + undo.section + "]/" + undo.relation +
            " определён во внешнем include: откат отклонён (Conflict)";
        return result;
    }
    if (observed.duplicateInRoot) {
        result.conflict = true;
        result.message =
            "Target relation [" + undo.section + "]/" + undo.relation +
            " продублирован в /etc/krb5.conf: откат отклонён (Conflict)";
        return result;
    }

    if (undo.beforeKind == fic::rollback::KerberosBeforeKind::Present) {
        if (!observed.relationInRoot) {
            result.conflict = true;
            result.message =
                "Target relation [" + undo.section + "]/" + undo.relation +
                " исчез из /etc/krb5.conf: откат отклонён (Conflict)";
            return result;
        }
        if (observed.rawLine == undo.beforeRawLine) {
            // Current state already equals the recorded before-state.
            result.ok = true;
            result.nothingToDo = true;
            result.message =
                "Kerberos relation [" + undo.section + "]/" + undo.relation +
                " уже восстановлена";
            return result;
        }
        if (observed.value != undo.appliedValue) {
            result.conflict = true;
            result.message =
                "Kerberos значение [" + undo.section + "]/" + undo.relation +
                " изменилось извне ('" + observed.value + "' вместо '" +
                undo.appliedValue + "'): откат отклонён (Conflict)";
            return result;
        }
    } else {
        if (!observed.relationInRoot) {
            result.ok = true;
            result.nothingToDo = true;
            result.message =
                "Kerberos relation [" + undo.section + "]/" + undo.relation +
                " уже отсутствует";
            return result;
        }
        if (observed.value != undo.appliedValue) {
            result.conflict = true;
            result.message =
                "Kerberos значение [" + undo.section + "]/" + undo.relation +
                " изменилось извне ('" + observed.value + "' вместо '" +
                undo.appliedValue + "'): откат отклонён (Conflict)";
            return result;
        }
    }

    // AFTER: inverse delta — restore the exact raw before line or remove
    // the relation (and a provably empty FIC-created section).
    fic::identity::kerberos::KerberosRootScalarMutation mutation;
    mutation.section = undo.section;
    mutation.relation = undo.relation;
    mutation.removeEmptyCreatedSection =
        undo.beforeKind == fic::rollback::KerberosBeforeKind::Missing &&
        !undo.sectionExistedBefore;
    if (undo.beforeKind == fic::rollback::KerberosBeforeKind::Present) {
        mutation.replacementRawLine = undo.beforeRawLine;
    }
    auto prepared = configuration.prepareRootScalarMutation(mutation);
    if (!prepared.ok()) {
        result.message =
            "Не удалось подготовить обратную Kerberos мутацию: " +
            prepared.error;
        return result;
    }
    if (!fic::identity::executePreparedFileChange(
            std::move(prepared.change), error)) {
        result.message = "Не удалось выполнить обратную Kerberos мутацию: " +
            error;
        return result;
    }

    // Postcondition: re-inspect the full graph.
    fic::identity::kerberos::KerberosRootScalarObservation restored;
    if (!configuration.inspectRootScalar(
            undo.section, undo.relation, restored, error)) {
        result.message =
            "Постусловие отката Kerberos не проверено: " + error;
        return result;
    }
    const bool restoredOk =
        undo.beforeKind == fic::rollback::KerberosBeforeKind::Present
        ? restored.relationInRoot && !restored.duplicateInRoot &&
            restored.rawLine == undo.beforeRawLine
        : !restored.relationInRoot;
    if (!restoredOk) {
        result.message =
            "Постусловие отката Kerberos не выполнено";
        return result;
    }

    result.ok = true;
    result.message = "Kerberos relation [" + undo.section + "]/" +
        undo.relation + " восстановлена к before-state";
    return result;
}