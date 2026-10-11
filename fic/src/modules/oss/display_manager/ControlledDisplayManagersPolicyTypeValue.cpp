#include "modules/oss/display_manager/ControlledDisplayManagersPolicyTypeValue.h"
#include <algorithm>
#include <cctype>
#include <set>
ControlledDisplayManagersPolicyTypeValue::ControlledDisplayManagersPolicyTypeValue(){defaultValue.clear();}
PolicyEditorSpec ControlledDisplayManagersPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;spec.editor="textedit";spec.textDelimiter=",";spec.validator="none";return spec;
}
bool ControlledDisplayManagersPolicyTypeValue::parse(const std::string& value,std::vector<std::string>& out) {
    out.clear();std::set<std::string> names;
    if(value.empty())return true;
    std::string token;
    auto add=[&](){auto first=token.find_first_not_of(" \t");auto last=token.find_last_not_of(" \t");
        auto name=first==std::string::npos?std::string():token.substr(first,last-first+1);
        std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return std::toupper(c);});
        token.clear();return (name=="SDDM"||name=="GDM"||name=="LIGHTDM")&&names.insert(name).second;};
    for(char c:value){if(c==','||c=='\n'||c=='\r'){if(c!=','&&token.empty())continue;if(!add())return false;}else token+=c;}
    if(!token.empty()&&!add())return false;
    if(value.back()==','||names.empty())return false;
    out={names.begin(),names.end()};return true;
}
bool ControlledDisplayManagersPolicyTypeValue::validate(const std::string& value){std::vector<std::string> names;return parse(value,names);}
std::string ControlledDisplayManagersPolicyTypeValue::postProcessingValue(const std::string& value){std::vector<std::string> names;if(!parse(value,names))return {};return json(names).dump();}
std::string ControlledDisplayManagersPolicyTypeValue::reverse_postProcessingValue(const std::string& value){
    try{auto v=json::parse(value);if(!v.is_array())return value;std::string result;for(const auto& name:v){if(!name.is_string())return value;if(!result.empty())result+=',';result+=name.get<std::string>();}return result;}catch(const std::exception&){return value;}
}
std::string ControlledDisplayManagersPolicyTypeValue::getPolicyRestrictionInfo(){return "Administrative scope: SDDM, GDM, LIGHTDM. Empty is UNCONFIGURED.";}
