#include "proxy.hpp"

#include <fastcgi2/except.h>
#include <fastcgi2/config.h>

#include <cstring>
#include <cstdio>
#include <iostream>

#include <boost/lexical_cast.hpp>
#include <boost/optional/optional.hpp>

Proxy::Proxy (fastcgi::ComponentContext *context)
    : fastcgi::Component(context)
{}

Proxy::~Proxy () {
}

void Proxy::onLoad () {
    const fastcgi::Config *config = context ()->getConfig ();
    std::string path(context()->getComponentXPath());

    elliptics::EllipticsProxy::config elconf;
    std::vector<std::string> names;

    logger_ = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));

    if (!logger_) {
        throw std::logic_error("can't find logger");
    }

    elconf.state_num = config->asInt(path + "/dnet/die-limit");
    elconf.base_port = config->asInt(path + "/dnet/base-port");
    // TODO:
    // write_port_ = config->asInt(path + "/dnet/write-port", 9000);
    elconf.directory_bit_num = config->asInt(path + "/dnet/directory-bit-num");
    elconf.eblob_style_path = config->asInt(path + "/dnet/eblob_style_path", 0);

    elconf.replication_count = config->asInt(path + "/dnet/replication-count", 0);
    elconf.chunk_size = config->asInt(path + "/dnet/chunk_size", 0);
    if (elconf.chunk_size < 0) elconf.chunk_size = 0;

    // TODO: cookie
    /*
    names.clear();
    config->subKeys(path + "/dnet/cookie/sign", names);
    use_cookie_ = !names.empty();

    if (use_cookie_) {
        cookie_name_ = config->asString(path + "/dnet/cookie/name", "");
        if (!cookie_name_.empty()) {
            cookie_key_ = config->asString(path + "/dnet/cookie/key");
            cookie_path_ = config->asString(path + "/dnet/cookie/path");
            cookie_domain_ = config->asString(path + "/dnet/cookie/domain");
            cookie_expires_ = config->asInt(path + "/dnet/cookie/expires");
        }

        names.clear();
        config->subKeys(path + "/dnet/cookie/sign", names);
        for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
            EllipticsProxy::cookie_sign cookie_;

            cookie_.path = config->asString(*it + "/path");
            cookie_.sign_key = config->asString(*it + "/sign_key");

            log()->debug("cookie %s path %s", it->c_str(), cookie_.path.c_str());
            cookie_signs_.push_back(cookie_);
        }
    }
*/


    elconf.log_path = config->asString(path + "/dnet/log/path");
    elconf.log_mask = config->asInt(path + "/dnet/log/mask");

    elconf.wait_timeout = config->asInt(path + "/dnet/wait-timeout", 0);
    elconf.check_timeout = config->asInt(path + "/dnet/reconnect-timeout", 0);
    elconf.flags = config->asInt(path + "/dnet/cfg-flags", 4);

    names.clear();
    config->subKeys(path + "/dnet/remote/addr", names);
    for (std::vector<std::string>::iterator it = names.begin(), end = names.end();
         end != it; ++it) {
        std::string remote = config->asString(it->c_str());
        Separator sep(":");
        Tokenizer tok(remote, sep);

        if (paramsNum(tok) != 2) {
            log()->error("invalid dnet remote %s", remote.c_str());
            continue;
        }

        std::string addr;
        int port, family;

        try {
            Tokenizer::iterator tit = tok.begin();
            addr = *tit;
            port = boost::lexical_cast<int>(*(++tit));
            family = boost::lexical_cast<int>(*(++tit));
            elconf.remotes.push_back(
                        elliptics::EllipticsProxy::remote(
                            addr, port, family));
            log ()->info("added dnet remote %s:%d:%d", addr.c_str(), port, family);
        }
        catch (...) {
            log()->error("invalid dnet remote %s", remote.c_str());
        }

    }

    // TODO: allow and deny
    /*
    names.clear();
    config->subKeys(path + "/dnet/allow/extention", names);
    for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
        allow_list_.insert(config->asString(it->c_str()));
    }

    names.clear();
    config->subKeys(path + "/dnet/deny/extention", names);
    for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
        deny_list_.insert(config->asString(it->c_str()));
    }
*/

    {
        std::string groups = config->asString(path + "/dnet/groups", "");

        Separator sep(":");
        Tokenizer tok(groups, sep);

        for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
            try {
                elconf.groups.push_back(boost::lexical_cast<int>(*it));
            }
            catch (...) {
                log()->error("invalid dnet group id %s", it->c_str());
            }
        }
    }

    elconf.success_copies_num = config->asInt(
                path + "/dnet/success-copies-num", elconf.groups.size());

    // TODO: typemap
    /*
    std::vector<std::string> typemap;
    config->subKeys(path + "/dnet/typemap/type", typemap);

    for (std::vector<std::string>::iterator it = typemap.begin(), end = typemap.end(); end != it; ++it) {
        std::string match = config->asString(it->c_str());

        std::string::size_type pos = match.find("->");
        std::string extention = match.substr(0, pos);
        std::string type = match.substr(pos + sizeof ("->") - 1, std::string::npos);

        typemap_[extention] = type;
    }

    expires_ = config->asInt(path + "/dnet/expires-time", 0);
*/

    elconf.metabase_write_addr = config->asString(path + "/dnet/metabase/write-addr", "");
    elconf.metabase_read_addr = config->asString(path + "/dnet/metabase/read-addr", "");

    elconf.cocaine_config = config->asString (path + "/dnet/cocaine_config", "");


    //std::string            ns;
    //int                    group_weights_refresh_period;

    // TODO: HAVE_METABASE
    /*
#ifdef HAVE_METABASE
    metabase_current_stamp_ = 0;
    metabase_usage_ = DNET_FCGI_META_NONE;
    names.clear();
    config->subKeys(path + "/metabase/addr", names);
    if (names.size() > 0) {
        try {
            metabase_context_.reset(new zmq::context_t(config->asInt(path + "/metabase/net_threads", 1)));
            metabase_socket_.reset(new zmq::socket_t(*metabase_context_, ZMQ_DEALER));

            // Disable linger so that the socket won't hang for eternity waiting for the peer
            int linger = 0;
            metabase_socket_->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));

            for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
                log()->debug("connecting to zmq host %s", config->asString(it->c_str()).c_str());
                metabase_socket_->connect(config->asString(it->c_str()).c_str());
            }

            // Default timeout is 100ms
            metabase_timeout_ = config->asInt(path + "/metabase/timeout", 100 * 1000);

            std::string cfg_metabase_usage = config->asString(path + "/metabase/usage", "normal");
            if (!cfg_metabase_usage.compare("normal")) {
                metabase_usage_ = DNET_FCGI_META_NORMAL;
            } else if (!cfg_metabase_usage.compare("optional")) {
                metabase_usage_ = DNET_FCGI_META_OPTIONAL;
            } else if (!cfg_metabase_usage.compare("mandatory")) {
                metabase_usage_ = DNET_FCGI_META_MANDATORY;
            } else {
                throw std::runtime_error(std::string("Incorrect metabase usage type: ") + cfg_metabase_usage);
            }
            log()->debug("cfg_metabase_usage %s, metabase_usage_ %d", cfg_metabase_usage.c_str(), metabase_usage_);

        }
        catch (const std::exception &e) {
            log()->error("can not connect to metabase: %s", e.what());
            metabase_socket_.release();
        }
        catch (...) {
            log()->error("can not connect to metabase");
            metabase_socket_.release();
        }
    }

#endif
*/

    // TODO: embed_processors
    /*
    names.clear();
    config->subKeys(path + "/embed_processors/processor", names);
    for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
        EmbedProcessorModuleBase *processor = context()->findComponent<EmbedProcessorModuleBase>(config->asString(*it + "/name"));
        if (!processor) {
            log()->error("Embed processor %s doesn't exists in config", config->asString(*it + "/name").c_str());
        } else {
                    embed_processors_.push_back(std::make_pair(config->asInt(*it + "/type"), processor));
        }
    }
    */

    // TODO: allow-origin
    /*
    names.clear();
    config->subKeys(path + "/dnet/allow-origin/domains/domain", names);
    for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
        allow_origin_domains_.insert(config->asString(it->c_str()));
    }

    names.clear();
    config->subKeys(path + "/dnet/allow-origin/handlers/handler", names);
    for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
        allow_origin_handlers_.insert(config->asString(it->c_str()));
    }
*/


	log ()->debug ("HANDLE create elliptics proxy");
    ellipticsProxy_.reset (new elliptics::EllipticsProxy (elconf));
	log ()->debug ("HANDLE elliptics proxy is created");

    //
    registerHandler ("upload", &Proxy::uploadHandler);
    registerHandler ("get", &Proxy::getHandler);

	log ()->debug ("HANDLE handles are registred");
}

void Proxy::onUnload () {
}

void Proxy::handleRequest (fastcgi::Request *request, fastcgi::HandlerContext *context) {
    (void)context;
	//log ()->debug ("HANDLE process any request. Script: %s\n", request->getScriptName ().c_str ());
	//return;
    try {
        std::string handler;
        if (request->getQueryString().length() != 0) {
#if 0
            if (request->hasArg("stat") || request->hasArg("ping")) {
                handler = "stat";
            }
            else if (request->hasArg("stat_log")) {
                handler = "stat-log";
            }
            else if (request->hasArg("direct")) {
                handler = "get";
            }
            else if (request->hasArg("range")) {
                handler = "range";
            }
            else if (request->hasArg("range-delete")) {
                handler = "range-delete";
            }
            else if (request->hasArg("unlink")) {
                handler = "delete";
            }
            else if (request->hasArg("bulk-read")) {
                handler = "bulk-read";
            }
            else if (request->hasArg("bulk-write")) {
                handler = "bulk-write";
            }
            else if (request->hasArg("exec-script")) {
                handler = "exec-script";
            }
            else {
                if (request->hasArg("name")) {
                    handler = request->getServerPort() == write_port_ ? "upload" : "download-info";
                }
                else {
#endif
                    handler = request->getScriptName().substr(1, std::string::npos);
#if 0
                }
            }
#endif
        }
        else {
            handler = request->getScriptName().substr(1, std::string::npos);
        }
        std::string::size_type pos = handler.find('/');
        handler = handler.substr(0, pos);
        RequestHandlers::iterator it = handlers_.find(handler);
        if (handlers_.end() == it) {
            throw fastcgi::HttpException(404);
        }
#if 0
        if (allow_origin_handlers_.end() != allow_origin_handlers_.find(handler)) {
            allowOrigin(request);
        }
#endif

        (this->*it->second)(request);
    }
    catch (const fastcgi::HttpException &e) {
        throw;
    }
    catch (...) {
        throw fastcgi::HttpException(501);
    }
}

fastcgi::Logger *Proxy::log() const {
    return logger_;
}

size_t Proxy::paramsNum(Proxy::Tokenizer &tok) {
    size_t result = 0;
    for (Tokenizer::iterator it = ++tok.begin(), end = tok.end(); end != it; ++it) {
        ++result;
    }
    return result;
}

void Proxy::dnet_parse_numeric_id(const std::string &value, struct dnet_id &id) {
    unsigned char ch[5];
    unsigned int i, len = value.size();
    const char *ptr = value.data();

    memset(id.id, 0, DNET_ID_SIZE);

    if (len/2 > DNET_ID_SIZE)
        len = DNET_ID_SIZE * 2;

    ch[0] = '0';
    ch[1] = 'x';
    ch[4] = '\0';
    for (i=0; i<len / 2; i++) {
        ch[2] = ptr[2*i + 0];
        ch[3] = ptr[2*i + 1];

        id.id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
    }

    if (len & 1) {
        ch[2] = ptr[2*i + 0];
        ch[3] = '0';

        id.id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
    }
}

void Proxy::registerHandler (const char *name, Proxy::RequestHandler handler) {
    bool was_inserted = handlers_.insert (std::make_pair (name, handler)).second;
    if (!was_inserted) {
        log ()->error ("repeated registration of %s handler", name);
    }
}

void Proxy::uploadHandler(fastcgi::Request *request)
{
    //request->setHeader ("Simple-Header", "Reply from proxy");

    /*const std::streamsize buf_size = 1024;
    char buf [buf_size] = {0};
    const std::streamsize written = snprintf (
                buf, buf_size, "%s", request->getQueryString ().c_str ());*/
    //request->setHeader ("QueryString", request->getQueryString ());
    //request->setHeader ("ScriptName", request->getScriptName ());
    //request->setHeader ("_countArgs",
    //                    boost::lexical_cast <std::string> (request->countArgs ()));
    //request->setHeader ("Has_a", boost::lexical_cast <std::string> (request->hasArg ("a")));

    /*if (request->hasArg ("get")) {

        request->write (buf, written);
    }*/

    /*
-- Key &key,
std::string &data,
-- uint64_t offset,
-- uint64_t size,
-- uint64_t cflags,
-- uint64_t ioflags,
-- std::vector<int> &groups,
-- unsigned int replication_count,
- std::vector<boost::shared_ptr<embed> > embeds
*/

    //boost::optional <elliptics::Key> key;

//	request->setHeader ("Header", "Proxy");
//	return;
	log ()->debug ("HANDLER upload start");

    elliptics::Key key;
    uint64_t size;
    std::string data;

    uint64_t offset = request->hasArg ("offset") ? boost::lexical_cast <uint64_t> (request->getArg ("offset")) : 0;
    unsigned int cflags = request->hasArg ("cflags") ? boost::lexical_cast <unsigned int> (request->getArg ("cflags")) : 0;
    unsigned int ioflags = request->hasArg ("ioflags") ? boost::lexical_cast <unsigned int> (request->getArg ("ioflags")) : 0;

    std::vector<int> groups;

    int replication_count = request->hasArg ("replication-count") ? boost::lexical_cast <int> (request->getArg ("replication-count")) : 0;
    // TODO: support embed
    //bool embed = request->hasArg ("embed") || request->hasArg ("embed_timestamp");

    if (request->hasArg ("groups")) {
        Separator sep (":");
        Tokenizer tok (request->getArg ("groups"), sep);

        try {
            for (Tokenizer::iterator it = tok.begin (), end = tok.end (); end != it; ++it) {
                groups.push_back (boost::lexical_cast<int>(*it));
            }
        }
        catch (...) {
            throw fastcgi::HttpException(503);
        }
    }

    if (replication_count != 0 && replication_count < groups.size()) {
        groups.erase(groups.begin() + replication_count, groups.end());
    }

    if (request->hasArg ("id")) {
        struct dnet_id id;
        dnet_parse_numeric_id (request->getArg ("id"), id);
        elliptics::ID ID (id);
        key = elliptics::Key (ID);
    } else {
        std::string filename = request->hasArg ("name") ? request->getArg ("name") :
            request->getScriptName().substr(sizeof ("/upload/") - 1, std::string::npos);
        int column = request->hasArg ("column") ? boost::lexical_cast <int> (request->getArg ("column")) : 0;
        key = elliptics::Key (filename, column);

        if (request->hasArg ("prepare")) {
            size = boost::lexical_cast<uint64_t>(request->getArg("prepare"));
            ioflags = DNET_IO_FLAGS_PREPARE;
        } else if (request->hasArg ("commit")) {
            size = 0;
            ioflags = DNET_IO_FLAGS_COMMIT;
        } else if (request->hasArg ("plain_write")) {
            size = 0;
            ioflags = DNET_IO_FLAGS_PLAIN_WRITE;
        } else {
			size = 0;
		}
    }

	log ()->debug ("HANDLER upload calling lib");

    // TODO: temporary code for testing
    data = request->getArg ("data");

    try {
        ellipticsProxy_->write (key, data, offset = offset, size = size, cflags = cflags,
                                ioflags = ioflags, groups = groups,
                                replication_count = replication_count);
		log ()->debug ("HANDLER upload success");

        request->setStatus (200);
    } catch (const std::exception &e) {
        log()->error("Error occurred: %s", e.what());
        request->setStatus (503);
    } catch (...) {
        log()->error("Error occured unknown");
        request->setStatus (503);
    }
}

void Proxy::getHandler(fastcgi::Request *request) {
    elliptics::Key key;

    if (request->hasArg ("id")) {
        struct dnet_id id;
        dnet_parse_numeric_id (request->getArg ("id"), id);
        elliptics::ID ID (id);
        key = elliptics::Key (ID);
    } else {
        std::string filename = request->hasArg ("name") ? request->getArg ("name") :
            request->getScriptName().substr(sizeof ("/upload/") - 1, std::string::npos);
        int column = request->hasArg ("column") ? boost::lexical_cast <int> (request->getArg ("column")) : 0;
        key = elliptics::Key (filename, column);

        /*if (request->hasArg ("prepare")) {
            size = boost::lexical_cast<uint64_t>(request->getArg("prepare"));
            ioflags = DNET_IO_FLAGS_PREPARE;
        } else if (request->hasArg ("commit")) {
            size = 0;
            ioflags = DNET_IO_FLAGS_COMMIT;
        } else if (request->hasArg ("plain_write")) {
            size = 0;
            ioflags = DNET_IO_FLAGS_PLAIN_WRITE;
        }*/
    }

    elliptics::ReadResult result = ellipticsProxy_->read (key);
    request->setStatus (200);
    request->setContentType ("text/plain");
    request->setHeader ("Content-Length",
                        boost::lexical_cast <std::string> (result.data.length ()));
	request->setHeader ("Data", result.data);
    request->write (result.data.c_str (), result.data.length ());
}
