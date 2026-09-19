#ifndef FIC_IDENTITY_ACCESS_KERBEROS_ROLLBACK_H
#define FIC_IDENTITY_ACCESS_KERBEROS_ROLLBACK_H

#include "modules/identity_access/kerberos/KerberosConfiguration.h"
#include "rollback/MutationRecord.h"

#include <string>

// Options for the Kerberos rollback backend. The root /etc/krb5.conf
// location comes from the CURRENT configuration options — never from the
// journal payload.
struct KerberosRollbackOptions {
    fic::identity::kerberos::KerberosConfigurationOptions configuration;
};

struct KerberosRollbackResult {
    bool ok = false;
    bool conflict = false;    // drifted topology/value; nothing was written
    bool nothingToDo = false; // current state already equals the before-state
    std::string message;
};

// Rolls back one Kerberos policy mutation as an inverse delta against the
// recorded exact target before-state. No whole-file snapshot is stored or
// used; foreign include files are never modified.
//
// Classification of the CURRENT root target state against the journal:
//   * target defined in a foreign include / duplicated in the root /
//     unsafe topology — drift: Conflict, nothing is written;
//   * beforeKind == Present:
//       - the root raw line still equals beforeRawLine — NothingToDo;
//       - the root value equals appliedValue — the exact beforeRawLine is
//         restored (indentation and '*' markers included) through an atomic
//         CAS write, the full graph is re-parsed and verified;
//       - anything else — Conflict (a foreign 2h is never replaced by the
//         recorded 8h);
//       - the root relation disappeared — Conflict (ambiguous provenance).
//   * beforeKind == Missing:
//       - the root relation is absent — NothingToDo;
//       - the root value equals appliedValue — the relation is removed; a
//         section that the journal proves FIC created is removed only while
//         it is provably empty;
//       - anything else — Conflict.
KerberosRollbackResult undoKerberosScalar(
    const KerberosRollbackOptions& options,
    const fic::rollback::UndoRestoreKerberosScalar& undo);

#endif // FIC_IDENTITY_ACCESS_KERBEROS_ROLLBACK_H