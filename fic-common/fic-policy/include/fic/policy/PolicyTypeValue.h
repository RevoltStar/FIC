#ifndef POLICYTYPEVALUE_H
#define POLICYTYPEVALUE_H

#include <optional>
#include <string>
#include <vector>
#include <fic/core/LocalizationManager.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct PolicyEditorSpec {
    std::string editor;
    std::optional<int> min;
    std::optional<int> max;
    std::vector<std::string> possibleValues;
    std::optional<std::string> textDelimiter;
};

//Тип параметра политики
class PolicyTypeValue{
protected:
    std::string defaultValue;
public:
    PolicyTypeValue();
    virtual ~PolicyTypeValue() = default;

    //Дать значение по умолчанию
    std::string getDefaultValue();
    virtual PolicyEditorSpec getEditorSpec() const = 0;

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

    PolicyEditorSpec getEditorSpec() const override;

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
    PolicyEditorSpec getEditorSpec() const override;
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
private:
    std::optional<std::string> expectedValue;
public:
    FixedPolicyTypeValue();
    explicit FixedPolicyTypeValue(std::string expectedValue);

    std::optional<std::string> getIntrinsicValue() const;
    PolicyEditorSpec getEditorSpec() const override;
    std::string getPolicyRestrictionInfo() override;
    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
};


//Параметр сам по себе представляет из себя строку, состоящую из нескольких подстрок
class MultiLineTextPolicyTypeValue : public PolicyTypeValue{
private:
    std::string delimiterFrom;
    std::string delimiterTo;
public:
    /*MultiLineTextPolicyTypeValue(std::string _delimiterFrom, std::string _delimiterTo);*/
    MultiLineTextPolicyTypeValue(std::string _delimiterFrom, std::string _delimiterTo, std::string _defaultValue);

    PolicyEditorSpec getEditorSpec() const override;

    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;

    std::vector<std::string> split_paths(const std::string& str, const char delimiter = ',');
};

#endif // POLICYTYPEVALUE_H
