#include "features/incidents/services/IncidentHistoryService.h"
#include "features/incidents/pages/IncidentHistoryView.h"
#include <fic/core/logging/SecurityAudit.h>
#include <QApplication>
#include <QTableView>
#include <QPlainTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QFile>
#include <QTextStream>
#include "shared/i18n/QLocalizationManager.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
using json = nlohmann::json;
using Result = fic::ipc::Client::RequestResult;
json event(const std::string& reason = "policy failure", const std::string& type = "incident_raise") {
    return fic::core::security_audit::makeEvent("fic", {
        {"event",type},{"previous_severity","SOFT"},{"effective_severity","HARD"},
        {"escalated",true},{"persistent_state_broken",false},{"runtime_state","active"},
        {"source","policy_apply"},{"reason",reason},{"detail","containment diagnostic <b>"},
        {"policy",{{"module","DC"},{"submodule","DeviceControl"},{"policy","permanent_device_missing"}}},
        {"device_id",42},{"failure_origin","Required"}}, "2026-10-12 10:00:00.001");
}
json record(const json& e) {
    return {{"category","audit"},{"source_file","/mock/audit/audit_1.txt"},
        {"line",e.dump()},{"line_truncated",false},{"byte_size",e.dump().size()}};
}
Result response(json j) {
    j["ok"] = true; j["message"] = "loaded"; j["api_version"] = fic::ipc::API_VERSION;
    return {true,std::move(j),{}};
}
QString cursor(int i) { return QString("2.%1").arg(i,32,16,QChar('0')); }
json page(const std::string& boot, const json& records, int position, bool more = false) {
    const auto list = records.is_object() ? json::array({records}) : records.is_null() ? json::array() : records;
    return {{"boot_id",boot},{"records",list},{"next_cursor",cursor(position).toStdString()},
        {"has_more",more},{"reload_required",false},{"categories",{"audit"}}};
}
int main(int argc, char** argv) {
    QApplication app(argc,argv);
    bool damaged = false;
    const auto full = IncidentAuditEvent::parse(record(event()),damaged);
    assert(full && !damaged && full->event == "incident_raise" && full->previous == "SOFT" && full->severity == "HARD");
    assert(full->raw.contains("failure_origin") && full->raw.contains("device_id") && full->raw.contains("persistent_state_broken"));
    for (const auto type : {"incident_raise","incident_clear","incident_persistence_failed","incident_action_failed",
                           "incident_mode_preflight_failed","incident_mode_registry_failed","ssh_bridge_degraded"})
        assert(IncidentAuditEvent::parse(record(event("reason",type)),damaged));
    assert(!IncidentAuditEvent::parse(record(event("normal","session_ready")),damaged) && !damaged);
    auto admin = fic::core::security_audit::makeIpcEvent("fic", {}, "incident_raise", {{"value","HARD"}}, true,"accepted", "time");
    assert(!IncidentAuditEvent::parse(record(admin),damaged) && !damaged);
    admin["event"] = "incident_raise";
    assert(!IncidentAuditEvent::parse(record(admin),damaged) && !damaged);
    auto ordinary = record(event()); ordinary["category"] = "daemon";
    assert(!IncidentAuditEvent::parse(ordinary,damaged));
    ordinary["category"] = "audit"; ordinary["line"] = "[2026-10-12] [INFO] ordinary Logger line";
    assert(!IncidentAuditEvent::parse(ordinary,damaged) && !damaged);
    auto minimal = record({{"event","incident_clear"},{"component","fic"},{"timestamp","time"}});
    auto parsed = IncidentAuditEvent::parse(minimal,damaged);
    assert(parsed && parsed->source.isEmpty() && parsed->reason.isEmpty() && parsed->severity.isEmpty() && parsed->diagnostic.isEmpty());
    minimal["line"] = "{bad json"; assert(!IncidentAuditEvent::parse(minimal,damaged) && damaged);
    minimal["line"] = std::string(17000,'x'); assert(!IncidentAuditEvent::parse(minimal,damaged) && damaged);
    minimal = record(event()); minimal["line_truncated"] = true;
    assert(!IncidentAuditEvent::parse(minimal,damaged) && damaged);
    minimal = record(event()); minimal["line_truncated"] = "yes";
    assert(!IncidentAuditEvent::parse(minimal,damaged) && damaged);
    auto invalid = event(); invalid["source"] = 7;
    assert(!IncidentAuditEvent::parse(record(invalid),damaged) && damaged);
    json nested = {1}; for (int i=0;i<24;++i) nested = json{{"child",nested}};
    invalid = event(); invalid["nested"] = nested;
    assert(!IncidentAuditEvent::parse(record(invalid),damaged) && damaged);
    auto fallback = record({{"event","incident_raise"},{"component","fic"},{"timestamp","time"},{"record_truncated",true}});
    parsed = IncidentAuditEvent::parse(fallback,damaged); assert(parsed && parsed->truncated && !damaged);
    auto truncatedFields = event(std::string(400,'x'));
    parsed = IncidentAuditEvent::parse(record(truncatedFields),damaged); assert(parsed && parsed->truncated);
    IncidentAuditModel model; IncidentAuditFilter filter; filter.setSourceModel(&model);
    int inserted=0, reset=0;
    QObject::connect(&model,&QAbstractItemModel::rowsInserted,[&]{++inserted;});
    QObject::connect(&model,&QAbstractItemModel::modelReset,[&]{++reset;});
    auto second = *IncidentAuditEvent::parse(record(event("second","incident_clear")),damaged);
    model.update({*full}); model.update({*full,second}); model.update({*full,second});
    assert(model.rowCount() == 2 && inserted == 2 && reset == 0 && model.columnCount() == 7);
    assert(model.data(model.index(0,1)).toString() == "incident_raise");
    assert(!model.data(model.index(0,0),Qt::ToolTipRole).isValid());
    filter.setFilters("incident_clear",{}, {},{}); assert(filter.rowCount() == 1);
    filter.setFilters({},"SOFT", "POLICY", "device_id"); assert(filter.rowCount() == 2);
    filter.setFilters({},"ISOLATE", {},{}); assert(filter.rowCount() == 0);
    filter.setFilters({},"HARD", "administrator",{}); assert(filter.rowCount() == 0);
    filter.setFilters({},"HARD", {},"second"); assert(filter.rowCount() == 1);
    model.update({second}); assert(reset == 1);

    int position=0, boots=0, requests=0;
    bool offline=false, reload=false, repeatReload=false, bootPageFail=false, badPage=false, stuck=false;
    std::string boot="boot-one";
    IncidentHistoryService service([&](const json& q) {
        if (offline) return Result{false,{},"precise connection failure"};
        if (q.at("command") == "boot_id") { ++boots; return response({{"boot_id",boot}}); }
        assert(q.at("command") == "log_records" && q.at("limit") == IncidentHistoryService::PageSize);
        assert(q.at("boot_id") == boot); ++requests;
        if (bootPageFail) return Result{true,{{"ok",false},{"message","exact log refusal"},{"api_version",1}}, {}};
        if (reload || repeatReload) {
            reload=false;
            return response({{"boot_id",boot},{"records",json::array()},{"has_more",false},{"reload_required",true}}); // Actual reader omits next_cursor here.
        }
        if (badPage) { auto j=page(boot,{},position); j["records"]=42; return response(j); }
        if (stuck) { auto j=page(boot,json::array(),position,true); j["next_cursor"]=q.at("cursor"); return response(j); }
        // Replay after reset includes precisely the same structured line.
        if (q.at("cursor") == "" && position >= 6) return response(page(boot,{record(event("page1")),record(event("replayed new"))},++position));
        const int next=position+1;
        assert(q.at("cursor") == (position == 0 ? "" : cursor(position).toStdString()));
        position=next; return response(page(boot,{record(event("page"+std::to_string(position)))},position,position < 6));
    });
    auto history=service.refresh(); assert(history.events.size() == 4 && history.hasMore && !history.stale);
    assert(history.cursor == cursor(4) && requests == IncidentHistoryService::MaxPages);
    history=service.refresh(); assert(history.events.size() == 6 && !history.hasMore && history.cursor == cursor(6));
    const auto lastTime=history.acquired; const auto lastCursor=history.cursor;
    offline=true; history=service.refresh(); assert(history.stale && history.transportFailed && history.events.size() == 6 && history.cursor == lastCursor && history.acquired == lastTime);
    assert(history.error == "precise connection failure" && history.bootId == "boot-one");
    offline=false; reload=true; history=service.refresh();
    assert(!history.stale && history.reloaded && history.events.size() == 7); // Identical page1 is not duplicated.
    repeatReload=true; const auto before=history;
    history=service.refresh(); assert(history.stale && history.cursor == before.cursor && history.events.size() == 7);
    repeatReload=false; badPage=true; history=service.refresh(); assert(history.stale && history.cursor == before.cursor);
    badPage=false; stuck=true; history=service.refresh(); assert(history.stale && history.events.size() == 7);
    stuck=false;
    boot="boot-two"; bootPageFail=true; history=service.refresh();
    assert(history.stale && history.bootId == "boot-one" && history.events.size() == 7 && history.error == "exact log refusal");
    bootPageFail=false; position=0; history=service.refresh();
    assert(history.bootId == "boot-two" && history.events.size() == 4 && history.hasMore && !history.stale);

    int count=0;
    IncidentHistoryService bounds([&](const json& q) {
        if (q.at("command") == "boot_id") return response({{"boot_id","bounded"}});
        json records=json::array();
        for (int i=0;i<IncidentHistoryService::PageSize;++i) {
            auto e=event("row"+std::to_string(++count)); e["padding"]=std::string(10000,'x');
            records.push_back(record(e));
        }
        return response(page("bounded",records,count,true));
    });
    history=bounds.refresh(); assert(history.trimmed && history.hasMore && count == 800);
    qsizetype bytes=0; for (const auto& e:history.events) bytes+=e.memoryBytes();
    assert(bytes <= IncidentHistoryService::MaxMemoryBytes && history.events.size() <= IncidentHistoryService::MaxEvents);
    history=bounds.refresh(); assert(history.trimmed && count == 1600);
    bytes=0; QSet<QString> ids; for (const auto& e:history.events) { bytes+=e.memoryBytes(); assert(!ids.contains(e.identity)); ids.insert(e.identity); }
    assert(bytes <= IncidentHistoryService::MaxMemoryBytes);
    int small=0;
    IncidentHistoryService rowBounds([&](const json& q) {
        if (q.at("command") == "boot_id") return response({{"boot_id","small"}});
        json records=json::array(); for (int i=0;i<200;++i) records.push_back(record(event("row"+std::to_string(++small))));
        return response(page("small",records,small,true));
    });
    rowBounds.refresh(); history=rowBounds.refresh(); assert(history.events.size() == 1000 && history.trimmed);
    bool failBatch=false;
    IncidentHistoryService transaction([&](const json& q) {
        if (q.at("command") == "boot_id") return response({{"boot_id","transaction"}});
        if (q.at("cursor") == "") return response(page("transaction",json::array({record(event("txn1"))}),1));
        if (q.at("cursor") == cursor(1).toStdString())
            return response(page("transaction",json::array({record(event("txn2"))}),2,failBatch));
        return Result{false,{},"page two lost"};
    });
    history=transaction.refresh(); assert(history.events.size() == 1);
    const auto published=history;
    failBatch=true; history=transaction.refresh();
    assert(history.stale && history.events.size() == 1 && history.cursor == published.cursor && history.acquired == published.acquired);
    failBatch=false; history=transaction.refresh(); assert(!history.stale && history.events.size() == 2);
    int calls=0;
    IncidentHistoryService initialBatch([&](const json& q) {
        if (q.at("command") == "boot_id") return response({{"boot_id","batch"}});
        if (++calls == 2) return Result{false,{},"page two lost"};
        return response(page("batch",json::array({record(event("first"))}),1,true));
    });
    history=initialBatch.refresh(); assert(history.stale && history.events.isEmpty() && history.cursor.isEmpty());
    IncidentHistoryService damagedLines([&](const json& q) {
        if (q.at("command") == "boot_id") return response({{"boot_id","damage"}});
        auto bad=record(event()); bad["line"]="{truncated";
        return response(page("damage",{bad,record(event())},1));
    });
    history=damagedLines.refresh(); assert(history.events.size() == 1 && history.damaged && !history.stale);
    IncidentHistoryView view; view.show(); view.updateSnapshot(history);
    auto* table=view.findChild<QTableView*>("incidentHistoryTable"); assert(table->model()->rowCount() == 1);
    table->selectRow(0); QApplication::processEvents();
    assert(view.findChild<QPlainTextEdit*>("incidentAuditDetails")->toPlainText().contains("containment diagnostic <b>"));
    history.stale=true; history.error="offline <script>"; view.updateSnapshot(history);
    assert(table->model()->rowCount() == 1);
    auto* warning=view.findChild<QLabel*>("incidentHistoryWarning");
    assert(warning->textFormat() == Qt::PlainText && warning->text().contains("STALE") && warning->text().contains("PARTIAL") && warning->isVisible());
    view.findChild<QLineEdit*>("incidentSearch")->setText("does-not-exist"); assert(table->model()->rowCount() == 0);
    view.findChild<QLineEdit*>("incidentSearch")->clear(); assert(table->model()->rowCount() == 1);
    // Exercise the shipped RU/EN bundles and atomic rejection of malformed data.
    for (const auto lang : {"ru", "en"}) {
        QFile file(QString(":/fic/lang/%1.lang").arg(lang)); assert(file.open(QIODevice::ReadOnly));
        QTextStream stream(&file);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        stream.setCodec("UTF-8");
#endif
        json translations = json::object();
        while (!stream.atEnd()) {
            auto line = stream.readLine(); auto separator = line.indexOf('=');
            if (line.startsWith("[incident:") && separator > 0)
                translations[line.left(separator).toStdString()] = line.mid(separator + 1).toStdString();
        }
        json bundle={{"ok",true},{"message","bundle"},{"api_version",1},{"language",lang},{"translations",translations}};
        assert(QLocalizationManager::installBundle(QByteArray::fromStdString(bundle.dump())));
        view.updateSnapshot(history);
        assert(view.findChild<QPushButton*>()->text() == QString::fromStdString(translations.at("[incident:history_refresh]").get<std::string>()));
        const auto title=QLocalizationManager::getLang("[incident:title]");
        bundle["translations"]["broken"] = 1;
        assert(!QLocalizationManager::installBundle(QByteArray::fromStdString(bundle.dump())));
        assert(QLocalizationManager::getLang("[incident:title]") == title);
    }
    // Every required page field is strictly checked before cache publication.
    for (const auto field : {"boot_id","records","has_more","reload_required","next_cursor"}) {
        bool corrupt=false;
        IncidentHistoryService malformedPage([&](const json& q) {
            if (q.at("command") == "boot_id") return response({{"boot_id","schema"}});
            auto j=page("schema",json::array({record(event())}),1);
            if (corrupt) j[field]=nullptr;
            return response(j);
        });
        auto good=malformedPage.refresh(); assert(good.events.size() == 1 && !good.stale);
        corrupt=true; auto bad=malformedPage.refresh();
        assert(bad.stale && bad.cursor == good.cursor && bad.acquired == good.acquired && bad.events.size() == 1);
    }
    return 0;
}
