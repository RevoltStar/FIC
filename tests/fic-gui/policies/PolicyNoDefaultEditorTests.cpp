#include "features/policies/widgets/PolicyEditorWidget.h"
#include <QApplication>
#include <QLineEdit>
#include <QSpinBox>
#include <iostream>
int main(int argc,char** argv) {
    QApplication app(argc,argv);
    PolicyDescriptor policy;
    policy.moduleName="IDENTITY_ACCESS";policy.submoduleName="SSSD";
    policy.policyName="sssd_account_cache_expiration";
    policy.editor="spinbox";policy.validator="integer_range";
    policy.min=0;policy.max=3650;policy.hasDefault=false;policy.isSet=false;policy.valueValid=false;
    PolicyEditorWidget widget(policy.moduleName,{policy});
    const auto editors=widget.findChildren<QLineEdit*>();
    if(editors.size()!=1||!editors.front()->text().isEmpty()||!widget.findChildren<QSpinBox*>().isEmpty())return 1;
    auto* editor=editors.front();
    for(const auto* value:{"0","60","3650"}){editor->setText(value);if(!editor->hasAcceptableInput())return 1;}
    for(const auto* value:{"","-1","3651","60days"}){editor->setText(value);if(editor->hasAcceptableInput())return 1;}
    std::cout<<"No-default numeric GUI editor stays empty and validates explicit Days\n";return 0;
}
