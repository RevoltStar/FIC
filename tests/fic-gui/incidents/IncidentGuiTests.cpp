#include "features/incidents/pages/IncidentPage.h"
#include "app/MainWindow.h"
#include "shared/i18n/QLocalizationManager.h"
#include <QApplication>
#include <QLabel>
#include <QPlainTextEdit>
#include <QTabWidget>
#include <QPushButton>
#include <QMessageBox>
#include <QTimer>
#include <QTableView>
#include <QElapsedTimer>
#include <atomic>
#include <thread>
#include <chrono>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
using json = nlohmann::json;
using Result = fic::ipc::Client::RequestResult;
json valid() {
    return {{"api_version", fic::ipc::API_VERSION}, {"ok", true}, {"message", "proven"},
        {"severity", "ISOLATE"}, {"state_proven", true}, {"persistent_provenance", "PROVEN"},
        {"persistent_state_broken", false}, {"runtime", "active"}, {"response_mode", "ACTIVE"},
        {"response_mode_proven", true}, {"response_mode_diagnostic", "mode detail <b>"},
        {"detail", "diagnostic <script>"}, {"runtime_containment", {{"pam_gate_active", true},
        {"sessions_contained", true}, {"user_runtime_contained", true}, {"network_quarantined", true}}}};
}
void until(const std::function<bool()>& predicate) {
    QElapsedTimer timer; timer.start();
    while (!predicate() && timer.elapsed() < 4000) {
        QApplication::processEvents(); std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(predicate());
}
int main(int argc, char** argv) {
    QApplication app(argc, argv);
    json current = valid();
    IncidentService service([&](const json&) { return Result{true, current, {}}; });
    auto r = service.status(); assert(r.status && r.status->network && r.status->severity == "ISOLATE");
    for (auto field : {"api_version", "ok", "message", "severity", "state_proven", "persistent_provenance", "persistent_state_broken", "runtime", "response_mode", "response_mode_proven", "response_mode_diagnostic", "runtime_containment", "detail"}) {
        current = valid(); current[field] = nullptr;
        assert(service.status().failure == IncidentService::Failure::Protocol);
        current.erase(field); assert(!service.status().status);
    }
    for (auto field : {"pam_gate_active", "sessions_contained", "user_runtime_contained", "network_quarantined"}) {
        current = valid(); current["runtime_containment"][field] = 1; assert(!service.status().status);
    }
    current = valid(); current["severity"] = "UNLOCKED"; current["runtime"] = "inactive";
    for (auto& flag : current["runtime_containment"].items()) flag.value() = false;
    assert(service.status().status->normal());
    current["persistent_provenance"] = "BROKEN"; assert(!service.status().status->normal());
    current["persistent_provenance"] = "PROVEN";
    current["response_mode_proven"] = false; assert(!service.status().status->normal());
    current = valid(); current["state_proven"] = false; current["persistent_state_broken"] = true;
    current["persistent_provenance"] = "BROKEN"; current["runtime"] = "degraded";
    assert(service.status().status && !service.status().status->stateProven);
    current["response_mode_proven"] = false; assert(!service.status().status->modeProven);
    current["ok"] = false; current["message"] = "precise daemon refusal";
    r = service.status(); assert(r.failure == IncidentService::Failure::Daemon && r.message == "precise daemon refusal");
    IncidentService offline([](const json&) { return Result{false, {}, "connect failed"}; });
    assert(offline.status().failure == IncidentService::Failure::Transport);
    IncidentSnapshot state;
    assert(state.accept(1, {}, "first failure", false)); assert(!state.status && !state.stale);
    const auto timestamp = QDateTime::fromSecsSinceEpoch(1000, Qt::UTC);
    assert(state.accept(2, IncidentStatus::parse(valid()), {}, true, timestamp));
    assert(state.accept(3, {}, "connection lost", false));
    assert(state.stale && state.status->severity == "ISOLATE" && state.status->network && state.status->pam);
    assert(state.status->detail == "diagnostic <script>" && state.acquired == timestamp);
    assert(!state.accept(2, {}, "late error", false)); assert(state.error == "connection lost");
    assert(state.accept(4, IncidentStatus::parse(valid()), {}, true)); assert(!state.stale && state.error.isEmpty());
    json sent;
    IncidentService actions([&](const json& payload) { sent = payload; return Result{true, {{"api_version",1},{"ok",true},{"message","accepted"}}, {}}; });
    for (const auto& severity : {"SOFT","STANDARD","HARD","ISOLATE"}) {
        assert(actions.action("incident_raise", severity).failure == IncidentService::Failure::None);
        assert(sent.at("value") == severity && sent.at("command") == "incident_raise");
    }
    sent = nullptr; assert(actions.action("incident_raise", "UNLOCKED").failure == IncidentService::Failure::Protocol); assert(sent.is_null());
    assert(actions.action("incident_clear").failure == IncidentService::Failure::None); assert(sent.at("command") == "incident_clear" && !sent.contains("value"));
    assert(service.action("incident_clear").message == "precise daemon refusal");
    std::atomic<int> statusCalls{0}, actionCalls{0}, failure{0};
    std::atomic<bool> historyOffline{false};
    IncidentPage page(nullptr, [&](const json& payload) {
        assert(QThread::currentThread() != app.thread());
        if (payload.at("command") == "localization_bundle") return Result{false,{},"offline localization"};
        if (historyOffline && (payload.at("command") == "boot_id" || payload.at("command") == "log_records"))
            return Result{false,{},"history transport lost"};
        if (payload.at("command") == "boot_id") return Result{true, {{"ok",true},{"message","boot"},{"api_version",1},{"boot_id","test-boot"}}, {}};
        if (payload.at("command") == "log_records") {
            const json audit={{"event","incident_raise"},{"component","fic"},{"timestamp","time"},{"effective_severity","ISOLATE"},{"source","administrator"}};
            const json records=json::array({{{"category","audit"},{"source_file","/mock/audit.txt"},{"line",audit.dump()}},
                {{"category","audit"},{"source_file","/mock/audit.txt"},{"line","{bad"}}});
            return Result{true, {{"ok",true},{"message","logs"},{"api_version",1},{"boot_id","test-boot"},{"records",records},{"has_more",false},{"reload_required",false},{"next_cursor","2.0123456789abcdef0123456789abcdef"}}, {}};
        }
        if (payload.at("command") != "incident_status") {
            ++actionCalls; return Result{true, {{"api_version",1},{"ok",false},{"message","<b>denied</b>"}}, {}};
        }
        ++statusCalls;
        if (failure == 1) return Result{false, {}, "lost"};
        if (failure == 2) return Result{true, {{"ok",true}}, {}};
        if (failure == 3) { auto j = valid(); j["runtime"] = "degraded"; j["state_proven"] = false; return Result{true, j, {}}; }
        return Result{true, valid(), {}};
    });
    page.show(); until([&]{ return page.snapshot().status.has_value() && !page.isBusy(); });
    auto* warning = page.findChild<QLabel*>("incidentWarning");
    auto* details = page.findChild<QPlainTextEdit*>("incidentDetails");
    assert(warning && !warning->isVisible());
    auto* historyTable=page.findChild<QTableView*>("incidentHistoryTable");
    assert(historyTable->model()->rowCount() == 1); // Bad audit line never invalidates status.
    assert(page.findChild<QLabel*>("incidentHistoryWarning")->text().contains("PARTIAL"));
    assert(details->toPlainText().contains("diagnostic <script>"));
    failure = 1; auto sequence = page.snapshot().lastSequence; page.refresh();
    until([&]{ return page.snapshot().lastSequence > sequence && !page.isBusy(); });
    page.findChild<QTabWidget*>("incidentTabs")->setCurrentIndex(1);
    assert(page.snapshot().stale && warning->isVisible() && warning->text().contains("STALE"));
    assert(historyTable->model()->rowCount() == 1);
    assert(page.findChild<QLabel*>("incidentHistoryWarning")->text().contains("STALE"));
    page.findChild<QTabWidget*>("incidentTabs")->setCurrentIndex(0);
    assert(page.snapshot().status->severity == "ISOLATE" && page.snapshot().status->sessions && page.snapshot().status->userRuntime);
    assert(details->toPlainText().contains("mode detail <b>"));
    failure = 2; sequence = page.snapshot().lastSequence; page.refresh();
    until([&]{ return page.snapshot().lastSequence > sequence && !page.isBusy(); }); assert(page.snapshot().stale);
    failure = 3; sequence = page.snapshot().lastSequence; page.refresh();
    until([&]{ return page.snapshot().lastSequence > sequence && !page.isBusy(); }); assert(!page.snapshot().stale);
    for (auto* button : page.findChildren<QPushButton*>()) assert(button->isEnabled());
    // Both UI paths require a cancellable PlainText confirmation before IPC.
    for (auto* button : page.findChildren<QPushButton*>()) {
        if (button->text() != QLocalizationManager::getLang("[incident:raise]") &&
            button->text() != QLocalizationManager::getLang("[incident:clear]")) continue;
        QTimer::singleShot(0, [] {
            auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget());
            assert(box && box->textFormat() == Qt::PlainText);
            assert(box->text().contains("FIC") || box->text().contains("SOFT"));
            box->reject();
        });
        button->click(); assert(actionCalls == 0);
    }
    sequence = page.snapshot().lastSequence; page.executeConfirmedAction("incident_clear");
    until([&]{ return page.snapshot().lastSequence > sequence && !page.isBusy(); }); assert(actionCalls == 1 && statusCalls >= 5);
    assert(page.findChild<QLabel*>("incidentOperation")->text().contains("<b>denied</b>"));
    const auto beforeHistoryFailure=page.snapshot().acquired;
    historyOffline=true; page.refreshHistory(); until([&]{ return !page.isBusy(); });
    assert(page.snapshot().stale && page.snapshot().status->severity == "ISOLATE" && page.snapshot().acquired == beforeHistoryFailure);
    assert(warning->isVisible() && warning->text().contains("history transport lost") && historyTable->model()->rowCount() == 1);
    historyOffline=false;
    failure = 1; sequence = page.snapshot().lastSequence; page.executeConfirmedAction("incident_raise", "HARD");
    until([&]{ return page.snapshot().lastSequence > sequence && !page.isBusy(); }); assert(page.snapshot().stale);
    IncidentPage firstFailure(nullptr, [](const json&) { return Result{false, {}, "offline"}; });
    firstFailure.show(); until([&]{ return firstFailure.snapshot().lastSequence > 0; });
    assert(!firstFailure.snapshot().status && !firstFailure.snapshot().stale);
    assert(firstFailure.findChild<QLabel*>("incidentWarning")->isVisible());
    MainWindow window(nullptr, [](const json&) { return Result{false, {}, "module list unavailable"}; },
        [](const json&) { return Result{true, valid(), {}}; });
    window.show(); auto* tabs = window.findChild<QTabWidget*>("tab_modules");
    assert(tabs->count() == 1 && tabs->widget(0)->objectName() == "incidentPage" && tabs->isVisible());
    auto* original = tabs->widget(0); window.addModules(); window.addModules();
    assert(tabs->count() == 1 && tabs->widget(0) == original);
    MainWindow policyFailure(nullptr, [](const json& request) {
        if (request.at("command") == "module_list") return Result{true, {{"ok",true},{"modules", {{{"name","GLOBAL"},{"view","standard"},{"display_order",1}}}}}, {}};
        return Result{false, {}, "policy list unavailable"};
    }, [](const json&) { return Result{true, valid(), {}}; });
    policyFailure.show();
    assert(policyFailure.findChild<QTabWidget*>("tab_modules")->isVisible());
    assert(policyFailure.findChild<IncidentPage*>("incidentPage"));
    MainWindow malformedModules(nullptr, [](const json&) {
        return Result{true, {{"ok","invalid"},{"message","bad module envelope"}}, {}};
    }, [](const json&) { return Result{true, valid(), {}}; });
    malformedModules.show(); malformedModules.addModules();
    assert(malformedModules.findChild<QTabWidget*>("tab_modules")->count() == 1);
    // Changing selection and rebuilding ordinary pages retains the named page.
    const json bundle={{"ok",true},{"message","bundle"},{"api_version",1},{"language","en"},{"translations",json::object()}};
    assert(QLocalizationManager::installBundle(QByteArray::fromStdString(bundle.dump())));
    assert(QLocalizationManager::getLang("[incident:title]") != "[incident:title]");
    MainWindow normalModules(nullptr, [](const json& q) {
        if (q.at("command") == "module_list") return Result{true, {{"ok",true},{"modules",json::array({
            {{"name","GLOBAL"},{"view","standard"},{"display_order",1}},
            {{"name","SYSCTL"},{"view","standard"},{"display_order",2}}})}}, {}};
        return Result{true, {{"ok",true},{"message","policies loaded"},{"policies",json::array()}}, {}};
    }, [](const json&) { return Result{true, valid(), {}}; });
    auto* normalTabs=normalModules.findChild<QTabWidget*>("tab_modules");
    assert(normalTabs->count() == 3); normalTabs->setCurrentIndex(2);
    assert(normalTabs->currentWidget()->objectName() == "SYSCTL");
    normalModules.addModules(); assert(normalTabs->count() == 3 && normalTabs->currentWidget()->objectName() == "SYSCTL");
    normalTabs->setCurrentIndex(0); auto* permanent=normalTabs->currentWidget();
    normalModules.addModules(); assert(normalTabs->currentWidget() == permanent && normalTabs->count() == 3);
    std::atomic<bool> entered{false}, release{false}; std::atomic<int> slowCalls{0};
    auto* slow = new IncidentPage(nullptr, [&](const json&) {
        ++slowCalls; entered = true;
        while (!release) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return Result{true, valid(), {}};
    });
    until([&]{ return entered.load(); }); for (int i=0;i<100;++i) slow->refresh();
    assert(slowCalls == 1);
    std::thread unblock([&]{ std::this_thread::sleep_for(std::chrono::milliseconds(20)); release = true; });
    delete slow; unblock.join(); // In-flight worker cannot dereference destroyed page.
    return 0;
}
