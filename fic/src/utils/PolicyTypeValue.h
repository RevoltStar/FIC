#ifndef POLICYTYPEVALUE_H
#define POLICYTYPEVALUE_H

#include <string>
#include <vector>
#include "utils/LocalizationManager.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

//Тип параметра политики
class PolicyTypeValue{
protected:
    std::string defaultValue;
public:
    PolicyTypeValue();
    virtual ~PolicyTypeValue() = default;

    //Дать значение по умолчанию
    std::string getDefaultValue();
    virtual std::vector<std::string> getPossibleValues();
    virtual int getMin();
    virtual int getMax();

    virtual bool validate(const std::string& value) = 0;
    //Преобразуем в удобный для хранения вид
    virtual std::string postProcessingValue(const std::string& value) = 0;
    //Преобразуем из вида, удобного для хранения, в вид для конфигурационного файла
    virtual std::string reverse_postProcessingValue(const std::string& value) = 0;
    virtual std::string getPolicyRestrictionInfo() = 0;
};

//Параметр политики - целое число
class IntPolicyTypeValue : public PolicyTypeValue{
    int min;
    int max;
public:
    /*IntPolicyTypeValue(int _min, int _max);*/
    IntPolicyTypeValue(int _min, int _max, int _defaultValue);

    int getMin() override;
    int getMax() override;

    bool validate(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
};

//Параметр политики - список доступных значений
class PossibleListPolicyTypeValue : public PolicyTypeValue{
private:
    std::vector<std::string> possibleList;
public:
    PossibleListPolicyTypeValue(const std::vector<std::string>& _possibleList);

    bool validate(const std::string& value) override;
    std::vector<std::string> getPossibleValues() override;
    std::string getPolicyRestrictionInfo() override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
};

/*
//Параметр политики - вкл/выкл
class EnableDisablePolicyTypeValue : public PossibleListPolicyTypeValue{
public:
    EnableDisablePolicyTypeValue();

    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
};
*/

//Параметр политики - фиксированное (обычно, в классе политики) значение
class FixedPolicyTypeValue : public PolicyTypeValue{
public:
    FixedPolicyTypeValue();

    std::string getPolicyRestrictionInfo() override;
    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
};


//Параметр сам по себе представляет из себя строку, состоящую из нескольких подстрок
class MultiLineTextPolicyTypeValue : public PolicyTypeValue{
private:
    std::string delimeterFrom;
    std::string delimeterTo;
public:
    /*MultiLineTextPolicyTypeValue(std::string _delimeterFrom, std::string _delimeterTo);*/
    MultiLineTextPolicyTypeValue(std::string _delimeterFrom, std::string _delimeterTo, std::string _defaultValue);

    std::string getDelimeterTo() const;

    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;

    std::vector<std::string> split_paths(const std::string& str, const char delimeter = ',');
};

#endif // POLICYTYPEVALUE_H
