#include "SudoersAuthenticationTransaction.h"
#include "modules/dac/sudo/Sudo.h"
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersGlobalDefaultsTransaction.h"
#include "rollback/DaemonMutationJournal.h"

#include <filesystem>
#include <mutex>
#include <utility>
#include <vector>

namespace {

// Serializes SUDO backend access. It is the SHARED SudoersConfiguration
// lock, so apply and rollback observe the same mutex instead of two
// unrelated translation-unit-local ones.
std::mutex& sudoersMutex() {
    return SudoersConfiguration::mutationMutex();
}

bool productionSudoersOptions(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables,
    SudoersConfigurationOptions& options,
    std::string& error) {
    options.mainPath = platformConfig.mainConfigPath;
    options.managedPath = platformConfig.managedConfigPath;
    options.managedFileMode = platformConfig.managedFileMode;
    options.requireValidator = true;
    std::filesystem::path validator;
    if (!executables.resolve(
            fic::platform::ExecutableId::Visudo, validator, error)) {
        return false;
    }
    options.validatorPath = validator.string();
    error.clear();
    return true;
}

std::string defaultsPrefix(const std::string& type,
                           const std::string& group,
                           const std::string& scope) {
    std::string result = type;
    if (!group.empty()) {
        result += ":" + group;
    }
    if (!scope.empty()) {
        result += scope;
    }
    result += " ";
    return result;
}

} // namespace

std::string SingleDefaultsSudoersParam::getParamString() const {
    return defaultsPrefix(sectionName_, group_, scope_) + key_;
}

std::string KeyValueDefaultsSudoersParam::getParamString() const {
    return defaultsPrefix(sectionName_, group_, scope_) + key_ + operation_ + value_;
}

Sudo::~Sudo() {
    // Реализация деструктора
}

bool Sudo::requiresDependencyCapability(const std::string& name) const {
    if (name != "exempt_group") return true;
    fic::sudoers::SudoProviderCapabilities capabilities;
    std::string error;
    const bool proven = fic::sudoers::detectSudoProviderCapabilities(
        platformConfig_, executables_, capabilities, error);
    const std::lock_guard<std::mutex> lock(capabilityMutex_);
    if (!proven) { dependencyProvider_.reset(); return true; }
    dependencyProvider_ = capabilities;
    return capabilities.exemptGroupDisabled !=
        fic::sudoers::SudoCapabilityGuarantee::VerifiedByConstruction;
}

bool Sudo::verifyProviderWitness(
    const fic::sudoers::SudoProviderCapabilities& current, std::string& error) const {
    const std::lock_guard<std::mutex> lock(capabilityMutex_);
    if (dependencyProvider_ && (dependencyProvider_->provider != current.provider ||
        dependencyProvider_->version != current.version ||
        dependencyProvider_->executable != current.executable ||
        dependencyProvider_->validator != current.validator)) {
        error = "Active SUDO provider changed after dependency evaluation";
        return false;
    }
    return true;
}

Sudo::Sudo(
    fic::platform::SudoPlatformConfig platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : DAC(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables) {
    this->submoduleName = "SudoEdit";
    /*this->Check_And_Fix::postProcessingParameter = std::make_unique<PostProcessingParameter>(PostProcessingParameter::ToJsonWithColon);*/
    /*this->Check_And_Fix::postProcessingValue = std::make_unique<PostProcessingValueJSON>(",", ",");*/
}

// Проверить и исправить параметр sudo
bool Sudo::apply() {
    if (this->Sudo::sudoParameter == nullptr){
        this->log("Не задан sudoParameter", logLevel::FATAL);
        return false;
    }

    const std::lock_guard<std::mutex> lock(sudoersMutex());

    fic::sudoers::SudoProviderCapabilities capabilities;
    std::string capabilityError;
    if (!fic::sudoers::detectSudoProviderCapabilities(
            platformConfig_, executables_, capabilities, capabilityError) ||
        !verifyProviderWitness(capabilities, capabilityError)) {
        this->log(capabilityError, logLevel::ERROR);
        return false;
    }

    SudoersConfigurationOptions configurationOptions;
    std::string resolverError;
    if (!productionSudoersOptions(
            platformConfig_, executables_, configurationOptions, resolverError)) {
        this->log("Не удалось выбрать visudo: " + resolverError, logLevel::ERROR);
        return false;
    }
    configurationOptions.verifyProviderUnchanged = [this, capabilities](std::string& error) {
        fic::sudoers::SudoProviderCapabilities current;
        if (!fic::sudoers::detectSudoProviderCapabilities(platformConfig_, executables_, current, error)) return false;
        if (current.provider != capabilities.provider || current.version != capabilities.version ||
            current.executable != capabilities.executable || current.validator != capabilities.validator) {
            error = "Active SUDO provider changed during transaction";
            return false;
        }
        return true;
    };
    SudoersConfiguration configuration(configurationOptions);
    std::string loadError;
    if (!configuration.load(loadError)) {
        this->log("Не удалось проанализировать sudoers: " + loadError, logLevel::ERROR);
        return false;
    }
    auto valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    std::string valueNew = *valueOpt;
    if(valueNew.empty()){
        this->log("Эталон не задан", logLevel::ERROR);
        return false;
    }

    std::string key;
    std::string renderedLine;
    std::string expectedValue;
    if (const auto* parameter = dynamic_cast<const KeyValueDefaultsSudoersParam*>(
            this->Sudo::sudoParameter.get())) {
        key = parameter->getKey();
        expectedValue = valueNew;
        renderedLine = defaultsPrefix(parameter->getType(), parameter->getGroup(),
                                      parameter->getScope()) +
                       parameter->getKey() + parameter->getOperator() + valueNew;
    } else if (const auto* parameter = dynamic_cast<const SingleDefaultsSudoersParam*>(
                   this->Sudo::sudoParameter.get())) {
        key = parameter->getKey();
        expectedValue = valueNew;
        renderedLine = defaultsPrefix(parameter->getType(), parameter->getGroup(),
                                      parameter->getScope()) +
                       (valueNew == "DISABLE" ? "!" : "") + parameter->getKey();
    } else {
        this->log("Тип sudoParameter не поддерживает managed override", logLevel::ERROR);
        return false;
    }

    std::string journalError;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
    if (!journal) {
        this->log(journalError.empty() ? "Mutation journal недоступен" : journalError,
                  logLevel::ERROR);
        return false;
    }
    if (capabilities.exemptGroupDisabled == fic::sudoers::SudoCapabilityGuarantee::VerifiedByConstruction) {
        const PolicyRef exempt{"DAC", "SudoEdit", "sudo_exempt_group_disable"};
        const auto obsolete = journal->activeRecords(exempt);
        if (obsolete.size() > 1) {
            this->log("Conflicting exempt_group ownership during provider transition", logLevel::ERROR);
            return false;
        }
        if (!obsolete.empty()) {
            if (!std::holds_alternative<fic::rollback::UndoReleaseSudoGlobalDefault>(obsolete.front().undo.payload)) {
                this->log("Legacy exempt_group provenance cannot be retired by construction", logLevel::ERROR);
                return false;
            }
            auto releaseOptions = configurationOptions;
            releaseOptions.releaseOwnedUnsupportedSetting = true;
            const auto retired = fic::sudoers::GlobalDefaultsTransaction(releaseOptions, *journal).release(obsolete.front());
            if (!retired.ok || !journal->setStatus(obsolete.front().id,
                    fic::rollback::MutationStatus::RolledBack, journalError)) {
                this->log(retired.ok ? journalError : retired.message, logLevel::ERROR);
                return false;
            }
        }
    }
    fic::sudoers::GlobalDefaultsTransaction transaction(configurationOptions, *journal);
    const bool byConstruction =
        (key == "env_reset" && expectedValue == "ENABLE" &&
         capabilities.envReset == fic::sudoers::SudoCapabilityGuarantee::VerifiedByConstruction) ||
        (key == "exempt_group" && expectedValue == "DISABLE" &&
         capabilities.exemptGroupDisabled == fic::sudoers::SudoCapabilityGuarantee::VerifiedByConstruction);
    if (byConstruction) {
        const auto records = journal->activeRecords(this->policyRef());
        if (records.size() > 1) {
            this->log("Conflicting global SUDO ownership records", logLevel::ERROR);
            return false;
        }
        if (!records.empty()) {
            if (!std::holds_alternative<fic::rollback::UndoReleaseSudoGlobalDefault>(records.front().undo.payload)) {
                this->log("Legacy SUDO ownership requires explicit resolution", logLevel::ERROR);
                return false;
            }
            configurationOptions.releaseOwnedUnsupportedSetting = key == "exempt_group";
            fic::sudoers::GlobalDefaultsTransaction release(configurationOptions, *journal);
            const auto outcome = release.release(records.front());
            if (!outcome.ok || !journal->setStatus(records.front().id,
                    fic::rollback::MutationStatus::RolledBack, journalError)) {
                this->log(outcome.ok ? journalError : outcome.message, logLevel::ERROR);
                return false;
            }
        } else if (!configuration.validateConfiguration(journalError)) {
            this->log(journalError, logLevel::ERROR);
            return false;
        }
        if (!transaction.verifyNoOwnedSetting(key, journalError)) {
            this->log(journalError, logLevel::ERROR);
            return false;
        }
        if (!configurationOptions.verifyProviderUnchanged(journalError)) {
            this->log(journalError, logLevel::ERROR);
            return false;
        }
        this->log("VerifiedByConstruction: " + key + " (" + capabilities.version + ")", logLevel::INFO);
        return true;
    }
    if (key == "env_reset" &&
        capabilities.envReset == fic::sudoers::SudoCapabilityGuarantee::VerifiedByConstruction) {
        this->log("The active provider enforces env_reset unconditionally", logLevel::ERROR);
        return false;
    }
    const auto operation = transaction.reconcile(this->policyRef(), key, renderedLine, expectedValue);
    this->log(operation.message, operation.ok ? logLevel::INFO : logLevel::ERROR);
    return operation.ok;
}

bool Sudo::applyRequireAuthentication() {
    const std::lock_guard<std::mutex> lock(sudoersMutex());
    const auto configuredValue = this->getValue();
    if (!configuredValue || *configuredValue != "ENABLE") {
        this->log("Эталон политики требования аутентификации не равен ENABLE", logLevel::ERROR);
        return false;
    }

    SudoersConfigurationOptions configurationOptions;
    std::string resolverError;
    if (!productionSudoersOptions(
            platformConfig_, executables_, configurationOptions, resolverError)) {
        this->log("Не удалось выбрать visudo: " + resolverError, logLevel::ERROR);
        return false;
    }
    fic::sudoers::SudoProviderCapabilities capabilities;
    if (!fic::sudoers::detectSudoProviderCapabilities(platformConfig_, executables_, capabilities, resolverError) ||
        !verifyProviderWitness(capabilities, resolverError)) {
        this->log(resolverError, logLevel::ERROR); return false;
    }
    configurationOptions.validatorPath = capabilities.validator.string();
    configurationOptions.verifyProviderUnchanged = [this, capabilities](std::string& error) {
        fic::sudoers::SudoProviderCapabilities current;
        if (!fic::sudoers::detectSudoProviderCapabilities(platformConfig_, executables_, current, error)) return false;
        if (current.provider != capabilities.provider || current.version != capabilities.version ||
            current.executable != capabilities.executable || current.validator != capabilities.validator) {
            error = "Active provider changed during authentication transaction"; return false;
        }
        return true;
    };
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(resolverError);
    if (!journal) { this->log(resolverError, logLevel::ERROR); return false; }
    const auto operation = fic::sudoers::AuthenticationTransaction(configurationOptions, *journal).reconcile();
    this->log(operation.message, operation.ok ? logLevel::INFO : logLevel::ERROR);
    return operation.ok;
}
