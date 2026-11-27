# DE/DM controlled scope configuration

Branch main; base f15cd9e7a61795f6965de5abf5367aaf4775f720.

Current task: reject empty administrative DE/DM scopes before enabling or
clearing an enabled value. Preserve empty defaults and apply semantics.

Implementation: Policy offers a narrow enabled-value validation hook, overridden
only by the two controlled-scope policies using their existing parsers. Enable
checks it before saving. setPolicyValue checks it against loaded status before
writing. IPC returns the concrete validation error. The GUI's descriptor
validator marks these two scopes and PolicyService checks the target state
before the first mutating request. Save ordering from 9b86a211 is unchanged.

Validation: fic target built. Root DM transaction suite passed in disposable
Docker; five targeted CTests passed (controlled DE, GUI descriptor/service/save,
policy execution planner). GUI target built. git diff --check passed.
No host policies or package lifecycle were applied. Full platform native matrix
was not run because the change is shared configuration validation.

Remaining: no unfinished implementation; one local completion commit, no push.
