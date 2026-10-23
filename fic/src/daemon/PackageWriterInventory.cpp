#include "daemon/PackageWriterProcesses.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>
#include <fic/core/integrity/ContentDigest.h>
#include <nlohmann/json.hpp>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
using json=nlohmann::json;
bool fail(std::string& error,const char* why){error=why;return false;}
bool validId(const std::string& id) {
    return id.size()==32&&id.find_first_not_of("0123456789abcdef")==std::string::npos;
}
bool privateParent(const std::filesystem::path& file,std::string& error) {
    if(!file.is_absolute()||file.lexically_normal()!=file||file.filename().empty())return fail(error,"invalid writer inventory path");
    int fd=fic::core::openRootControlledDirectory(file.parent_path(),error);
    if(fd<0)return false;
    struct stat info{};const bool trusted=::fstat(fd,&info)==0&&(info.st_mode&07777)==0700;
    ::close(fd);return trusted||fail(error,"writer inventory requires root-private parent");
}
bool validImages(const std::vector<LegacyWriterImage>& images) {
    if(images.size()>8)return false;
    std::set<std::string> digests;
    for(const auto& image:images) {
        if(!image.inode||!image.size||image.size>64*1024*1024||
            !fic::core::ContentDigest::isCanonicalSha256Hex(image.digest)||!digests.insert(image.digest).second)return false;
    }
    return true;
}
}
bool writeLegacyWriterInventory(const DaemonInstanceLock& guard,const std::filesystem::path& path,
    const std::string& id,const std::vector<LegacyWriterImage>& images,std::string& error) {
    if(!guard.heldByCurrentProcess()||!validId(id)||!validImages(images))return fail(error,"invalid writer inventory admission/provenance");
    if(!privateParent(path,error))return false;
    json value{{"version",1},{"id",id},{"count",images.size()}};
    for(std::size_t i=0;i<images.size();++i) {
        const auto prefix=std::to_string(i)+"_";const auto& image=images[i];
        value[prefix+"device"]=image.device;value[prefix+"inode"]=image.inode;
        value[prefix+"size"]=image.size;value[prefix+"digest"]=image.digest;
    }
    AtomicWriteOptions options;options.createIfMissing=true;options.exclusiveCreate=true;options.rejectSymlink=true;
    options.metadataPolicy=FileMetadataPolicy::EnforceProvided;options.fileOwner=0;options.fileGroup=0;options.fileMode=0600;
    AtomicWriteResult result;
    if(!AtomicFileWriter::writeWithResult(path.string(),value.dump()+"\n",options,&error,&result)||!result.durabilityConfirmed)return false;
    std::vector<LegacyWriterImage> proven;return readLegacyWriterInventory(path,id,proven,error);
}
bool readLegacyWriterInventory(const std::filesystem::path& path,const std::string& id,
    std::vector<LegacyWriterImage>& images,std::string& error) {
    images.clear();
    if(!validId(id)||!privateParent(path,error))return fail(error,"untrusted writer inventory identity/parent");
    fic::core::SecureStateFileExpectation options;
    options.owner=0;options.group=0;options.exactMode=0600;options.requireSingleLink=true;
    options.parentOwner=0;options.exactParentMode=0700;
    const auto file=fic::core::readSecureStateFile(path,options);
    if(file.status!=fic::core::SecureStateReadStatus::Proven)return fail(error,"writer inventory absent/unprovable");
    try {
        std::set<std::string> keys;bool duplicate=false;
        const auto value=json::parse(file.content,[&](int,json::parse_event_t event,json& token){
            if(event==json::parse_event_t::key&&!keys.insert(token.get<std::string>()).second)duplicate=true;
            return true;
        });
        if(duplicate||!value.is_object()||!value.at("version").is_number_unsigned()||value.at("version")!=1||
           value.at("id")!=id||!value.at("count").is_number_unsigned())throw std::runtime_error("schema");
        const auto count=value.at("count").get<std::uint64_t>();
        if(count>8||value.size()!=3+count*4)throw std::runtime_error("inventory bound");
        std::vector<LegacyWriterImage> parsed;
        for(std::uint64_t i=0;i<count;++i) {
            const auto prefix=std::to_string(i)+"_";
            for(const auto* field:{"device","inode","size"})if(!value.at(prefix+field).is_number_unsigned())throw std::runtime_error("number");
            parsed.push_back({value.at(prefix+"device").get<std::uint64_t>(),value.at(prefix+"inode").get<std::uint64_t>(),
                value.at(prefix+"size").get<std::uint64_t>(),value.at(prefix+"digest").get<std::string>()});
        }
        if(!validImages(parsed))throw std::runtime_error("image");
        images=std::move(parsed);error.clear();return true;
    }catch(...){return fail(error,"unknown/corrupt writer inventory");}
}
}
