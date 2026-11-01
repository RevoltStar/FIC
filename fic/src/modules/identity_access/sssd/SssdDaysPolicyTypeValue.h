#pragma once
#include <fic/policy/PolicyTypeValue.h>
#include <charconv>

// SSSD's policy range is independent of the native parser's accepted values.
// Keep other modules' existing defaulted integer parsing semantics unchanged.
class SssdDaysPolicyTypeValue final : public IntPolicyTypeValue {
public:
    SssdDaysPolicyTypeValue():IntPolicyTypeValue(0,3650){}
    explicit SssdDaysPolicyTypeValue(int defaultDays):IntPolicyTypeValue(0,3650,defaultDays){}
    bool validate(const std::string& value) override {
        unsigned days=0;const auto parsed=std::from_chars(value.data(),value.data()+value.size(),days);
        return !value.empty()&&parsed.ec==std::errc{}&&parsed.ptr==value.data()+value.size()&&days<=3650;
    }
};
