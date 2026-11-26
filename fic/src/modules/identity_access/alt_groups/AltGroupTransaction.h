#ifndef FIC_ALT_GROUP_TRANSACTION_H
#define FIC_ALT_GROUP_TRANSACTION_H

#include "rollback/AltGroupResources.h"

namespace fic::rollback { class MutationJournal; }

namespace fic::identity::alt_groups {

bool apply(const PolicyRef& policy, const std::string& desired,
           fic::rollback::MutationJournal& journal, std::string& error);
bool release(const MutationRecord& record,
             fic::rollback::MutationJournal& journal, std::string& error);

} // namespace fic::identity::alt_groups
#endif
